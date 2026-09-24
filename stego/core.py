"""Encode and verify carriers, and provide file wrappers.

The protocol functions here work on a ``CarrierSource``. They decide which
carrier units change and in what order the protocol steps run; the carrier
backend only supplies units. ``encode_carrier`` and ``decode_carrier`` keep the
original NumPy-array API by wrapping the array in an ``ArrayCarrier``.
"""

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike, fspath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
import numpy as np

from .bootstrap import (
    BootstrapFields,
    bootstrap_span,
    encode_bootstrap_aad,
    parse_bootstrap,
    serialize_bootstrap,
)
from .bits import (
    _require_bytes,
    _validate_carrier_units,
    _validate_lsb_count,
    _validate_media_code,
    _validate_non_negative_integer,
    bit_sequence_to_bytes,
    bytes_to_bit_sequence,
    read_lsb_bits,
    write_lsb_bits,
)
from .carrier import ArrayCarrier, CarrierSource, overlap_range
from .constants import (
    AEAD_NONCE_SIZE,
    AUDIO_MEDIA_CODE,
    BOOTSTRAP_LSB_COUNT,
    BOOTSTRAP_START_UNIT,
    GCM_TAG_SIZE,
    IMAGE_MEDIA_CODE,
    MEDIA_ID_SIZE,
    MEDIA_PREFIXES,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    RSA_SIGNATURE_SIZE,
    SESSION_KEY_SIZE,
)
from .crypto import (
    aead_open,
    aead_seal,
    display_rsa_public_key_fingerprint,
    open_with_private_key,
    seal_to_public_key,
    sign_bytes,
    validate_rsa_private_key,
    validate_rsa_public_key,
    verify_signature,
)
from .layout import (
    EmbeddingLayout,
    MaskedMediaHasher,
    build_embedding_layout,
    encode_signing_input,
    max_user_payload_length,
    minimum_carrier_units,
    preserved_bit_count,
)
from .media import (
    UnSupportedFileType,
    WavCarrier,
    carrier_to_rgb_array,
    encode_png_media_context,
    encode_wav_media_context,
    load_png_from_path,
    rgb_array_to_carrier,
    save_rgb_png_to_path,
)
from .packet import (
    PayloadRecord,
    parse_payload,
    serialized_record_length,
    serialize_payload,
)


def _validate_carrier_source(source: CarrierSource) -> CarrierSource:
    """Check that source is a carrier backend."""
    if not isinstance(source, CarrierSource):
        raise TypeError("source must be a CarrierSource")
    return source


def _new_masked_hasher(media_code: int, layout: EmbeddingLayout) -> MaskedMediaHasher:
    """Make a masked media hasher for the layout's geometry."""
    return MaskedMediaHasher(
        media_code,
        layout.lsb_count,
        layout.total_units,
        layout.start_unit,
        layout.footprint,
        layout.bootstrap_span,
    )


def _hash_carrier_source(source: CarrierSource, media_code: int, layout: EmbeddingLayout) -> bytes:
    """Compute the masked media hash in one bounded pass over the carrier."""
    hasher = _new_masked_hasher(media_code, layout)
    for chunk in source.iter_chunks():
        hasher.update(chunk)
    return hasher.digest()


def _plan_layout(total_units: int, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, media_id: str, user_payload: bytes, metadata: bytes) -> EmbeddingLayout:
    """Check capacity and return the packet geometry before any carrier data is read.

    The record length does not depend on the media hash value, because the hash
    has a fixed size, so the whole geometry is known before the first pass.
    """
    span = bootstrap_span(receiver_public_key)
    minimum_record_length = serialized_record_length(MEDIA_ID_SIZE, 0, 0)
    minimum_units = minimum_carrier_units(span, lsb_count, minimum_record_length)
    if total_units < minimum_units:
        raise ValueError(
            "carrier is too small for the protocol: "
            f"total_units={total_units}, start_unit={start_unit}, "
            f"lsb_count={lsb_count}, minimum_units={minimum_units}"
        )
    if start_unit < span:
        raise ValueError(
            f"start_unit {start_unit} is below the reserved bootstrap region; "
            f"lowest legal start_unit is {span}"
        )
    record_overhead = serialized_record_length(
        len(media_id.encode("utf-8")), 0, len(metadata)
    )
    maximum_user_payload = max_user_payload_length(
        total_units, start_unit, span, lsb_count, record_overhead
    )
    if len(user_payload) > maximum_user_payload:
        raise ValueError(
            f"user payload exceeds capacity: user_payload_length={len(user_payload)}, "
            f"max_user_payload_length={maximum_user_payload}, total_units={total_units}, "
            f"start_unit={start_unit}, lsb_count={lsb_count}"
        )
    record_length = serialized_record_length(
        len(media_id.encode("utf-8")), len(user_payload), len(metadata)
    )
    return build_embedding_layout(
        total_units, start_unit, lsb_count, record_length + GCM_TAG_SIZE, span
    )


class CarrierEncoding:
    """Hold one prepared encoding and embed it into carrier chunks during the second pass.

    ``prepare_carrier_encoding`` makes this object after the first pass. A
    backend then passes every original chunk, in order, to ``embed_chunk`` and
    writes the returned units. ``finish`` must be called afterwards: it checks
    that the second pass saw every unit and that the original carrier did not
    change between the passes.
    """

    def __init__(self, media_code: int, layout: EmbeddingLayout, payload: PayloadRecord, media_hash: bytes, packet: bytes, envelope: bytes) -> None:
        """Keep the packet and bootstrap bits for embedding."""
        self.layout = layout
        self.payload = payload
        self._media_hash = media_hash
        packet_bits = bytes_to_bit_sequence(packet)
        self._packet_bits = np.zeros(layout.footprint * layout.lsb_count, dtype=np.uint8)
        self._packet_bits[:packet_bits.size] = packet_bits
        self._envelope_bits = bytes_to_bit_sequence(envelope)
        self._rehash = _new_masked_hasher(media_code, layout)
        self._next_unit = 0

    def embed_chunk(self, chunk_start: int, units: np.ndarray) -> np.ndarray:
        """Return a copy of an original chunk with its bootstrap and packet bits embedded."""
        units = _validate_carrier_units(units)
        chunk_start = _validate_non_negative_integer(chunk_start, "chunk_start")
        if chunk_start != self._next_unit:
            raise ValueError("carrier chunks must be embedded once each, in order")
        # Hash the original units before any change so finish() can detect a
        # carrier that changed after the first pass.
        self._rehash.update(units)
        chunk_end = chunk_start + int(units.size)
        result = units.copy()
        layout = self.layout
        local = overlap_range(chunk_start, chunk_end, BOOTSTRAP_START_UNIT, BOOTSTRAP_START_UNIT + layout.bootstrap_span)
        if local is not None:
            first_unit = chunk_start + local[0] - BOOTSTRAP_START_UNIT
            bits = self._envelope_bits[first_unit * BOOTSTRAP_LSB_COUNT:(first_unit + local[1] - local[0]) * BOOTSTRAP_LSB_COUNT]
            result[local[0]:local[1]] = write_lsb_bits(result[local[0]:local[1]], bits, BOOTSTRAP_LSB_COUNT)
        local = overlap_range(chunk_start, chunk_end, layout.start_unit, layout.start_unit + layout.footprint)
        if local is not None:
            first_unit = chunk_start + local[0] - layout.start_unit
            bits = self._packet_bits[first_unit * layout.lsb_count:(first_unit + local[1] - local[0]) * layout.lsb_count]
            result[local[0]:local[1]] = write_lsb_bits(result[local[0]:local[1]], bits, layout.lsb_count)
        self._next_unit = chunk_end
        return result

    def finish(self) -> None:
        """Check that the second pass covered the carrier and read the same original data."""
        if self._rehash.digest() != self._media_hash:
            raise ValueError(
                "carrier changed between encoding passes; the output is not valid"
            )


def prepare_carrier_encoding(source: CarrierSource, media_code: int, media_context: bytes, signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> CarrierEncoding:
    """Plan the layout, hash the carrier in a first pass, then encrypt, sign, and seal.

    The returned ``CarrierEncoding`` embeds the result during a second pass.
    """
    source = _validate_carrier_source(source)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    signing_private_key = validate_rsa_private_key(signing_private_key)
    receiver_public_key = validate_rsa_public_key(receiver_public_key)
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    user_payload = _require_bytes(user_payload, "user_payload")
    metadata = _require_bytes(metadata, "metadata")
    try:
        metadata.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("metadata must contain valid UTF-8 bytes") from error

    total_units = _validate_non_negative_integer(source.total_units, "total_units")
    media_id = f"{MEDIA_PREFIXES[media_code]}-{secrets.token_hex(16)}"
    layout = _plan_layout(
        total_units, receiver_public_key, start_unit, lsb_count, media_id, user_payload, metadata
    )
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = secrets.token_bytes(NONCE_SIZE)
    media_hash = _hash_carrier_source(source, media_code, layout)
    payload = PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
    record_bytes = serialize_payload(payload)
    session_key = secrets.token_bytes(SESSION_KEY_SIZE)
    aead_nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    fields = BootstrapFields(
        PROTOCOL_VERSION,
        lsb_count,
        start_unit,
        layout.ciphertext_length,
        session_key,
        aead_nonce,
    )
    ciphertext = aead_seal(
        session_key,
        aead_nonce,
        encode_bootstrap_aad(fields),
        record_bytes,
    )
    if len(ciphertext) != layout.ciphertext_length:
        raise ValueError("AES-GCM ciphertext has an unexpected length")
    signature = sign_bytes(
        encode_signing_input(media_code, media_context, layout, ciphertext),
        signing_private_key,
    )
    envelope = seal_to_public_key(serialize_bootstrap(fields), receiver_public_key)
    if len(envelope) * 8 != layout.bootstrap_span:
        raise ValueError("bootstrap envelope has an unexpected span")
    return CarrierEncoding(media_code, layout, payload, media_hash, ciphertext + signature, envelope)


def encode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[np.ndarray, EmbeddingLayout, PayloadRecord]:
    """Encrypt, sign, and embed a record with a receiver bootstrap."""
    source = ArrayCarrier(_validate_carrier_units(carrier_units))
    encoding = prepare_carrier_encoding(
        source, media_code, media_context, signing_private_key, receiver_public_key,
        start_unit, lsb_count, user_payload, metadata,
    )
    encoded = source.rewrite(encoding.embed_chunk)
    encoding.finish()
    return encoded, encoding.layout, encoding.payload


@dataclass(frozen=True)
class VerificationResult:
    """Keep a carrier's verification verdict and the details that support it."""
    valid: bool
    verdict: str
    detail: str
    payload: PayloadRecord | None
    key_fingerprint: str | None
    start_unit: int | None
    lsb_count: int | None
    preserved_bits: int | None
    preserved_ratio: float | None


def _failure_result(verdict: str, detail: str) -> VerificationResult:
    """Make a failed verification result without a payload."""
    return VerificationResult(False, verdict, detail, None, None, None, None, None, None)


def decode_carrier_source(source: CarrierSource, media_code: int, media_context: bytes, sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Recover and verify an encrypted packet from a carrier backend.

    The carrier is read three times: the bootstrap range, the packet range, and
    one full bounded pass for the masked media hash. Carrier read failures give
    ``Cannot Verify``.
    """
    source = _validate_carrier_source(source)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    sender_public_key = validate_rsa_public_key(sender_public_key)
    receiver_private_key = validate_rsa_private_key(receiver_private_key)
    total_units = _validate_non_negative_integer(source.total_units, "total_units")
    span = bootstrap_span(receiver_private_key)
    try:
        # A carrier shorter than the span yields fewer units, and read_lsb_bits
        # then reports the capacity failure.
        bootstrap_units = source.read_units(
            BOOTSTRAP_START_UNIT, min(span, total_units - BOOTSTRAP_START_UNIT)
        )
        envelope_bits = read_lsb_bits(bootstrap_units, span, BOOTSTRAP_LSB_COUNT)
        envelope = bit_sequence_to_bytes(envelope_bits)
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
    try:
        bootstrap_plaintext = open_with_private_key(envelope, receiver_private_key)
    except ValueError:
        return _failure_result(
            "Payload Missing",
            "nothing was readable with the supplied receiver private key",
        )
    try:
        fields = parse_bootstrap(bootstrap_plaintext)
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
    if fields.ciphertext_length < GCM_TAG_SIZE:
        return _failure_result("Cannot Verify", "ciphertext_length must include a 16-byte GCM tag")
    if fields.start_unit < span:
        return _failure_result(
            "Wrong Start Location",
            f"start_unit {fields.start_unit} is below bootstrap_span {span}",
        )
    # Bootstrap fields are structurally validated and the span is known, so this
    # narrow layout failure can only mean that the packet footprint is out of range.
    try:
        layout = build_embedding_layout(
            total_units,
            fields.start_unit,
            fields.lsb_count,
            fields.ciphertext_length,
            span,
        )
    except ValueError as error:
        return _failure_result("Wrong Start Location", str(error))
    packet_bits_length = (layout.ciphertext_length + RSA_SIGNATURE_SIZE) * 8
    try:
        packet_units = source.read_units(layout.start_unit, layout.footprint)
        all_bits = read_lsb_bits(
            packet_units,
            layout.footprint * layout.lsb_count,
            layout.lsb_count,
        )
        if np.any(all_bits[packet_bits_length:] != 0):
            return _failure_result("Cannot Verify", "alignment padding must be zero")
        packet = bit_sequence_to_bytes(all_bits[:packet_bits_length])
        ciphertext = packet[:layout.ciphertext_length]
        signature = packet[layout.ciphertext_length:]
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
    signing_input = encode_signing_input(
        media_code, media_context, layout, ciphertext
    )
    if not verify_signature(signing_input, signature, sender_public_key):
        return _failure_result("Signature Invalid", "RSA-PSS signature verification failed")
    try:
        record_bytes = aead_open(
            fields.session_key,
            fields.aead_nonce,
            encode_bootstrap_aad(fields),
            ciphertext,
        )
    except InvalidTag:
        return _failure_result(
            "Cannot Decrypt",
            "signature verified but the AES-GCM tag rejected the body",
        )
    try:
        payload = parse_payload(record_bytes)
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
    try:
        calculated_hash = _hash_carrier_source(source, media_code, layout)
    except ValueError as error:
        return _failure_result(
            "Cannot Verify", f"carrier could not be read for the masked media hash: {error}"
        )
    if calculated_hash != payload.media_hash:
        return _failure_result("Tampered", "masked media hash mismatch")
    preserved_bits = preserved_bit_count(
        layout.total_units,
        layout.footprint,
        layout.lsb_count,
        layout.bootstrap_span,
    )
    total_bits = layout.total_units * 8
    ratio = preserved_bits / total_bits if total_bits else 0.0
    return VerificationResult(
        True,
        "Authentic",
        "signature and masked media hash are valid under the supplied public key",
        payload,
        display_rsa_public_key_fingerprint(sender_public_key),
        layout.start_unit,
        layout.lsb_count,
        preserved_bits,
        ratio,
    )


def decode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Recover and verify an encrypted packet using the receiver's private key."""
    source = ArrayCarrier(_validate_carrier_units(carrier_units))
    return decode_carrier_source(source, media_code, media_context, sender_public_key, receiver_private_key)


def _paths_resolve_same(first_path: str | bytes | PathLike[str], second_path: str | bytes | PathLike[str]) -> bool:
    """Check whether two filesystem paths point to the same place."""
    for path in (first_path, second_path):
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
    return os.path.normcase(os.path.realpath(os.fsdecode(fspath(first_path)))) == os.path.normcase(os.path.realpath(os.fsdecode(fspath(second_path))))


def encode_png(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an RGB PNG file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    image = load_png_from_path(input_path)
    carrier = rgb_array_to_carrier(image)
    context = encode_png_media_context(image.shape, carrier.size)
    encoded, layout, payload = encode_carrier(carrier, IMAGE_MEDIA_CODE, context, signing_private_key, receiver_public_key, start_unit, lsb_count, user_payload, metadata)
    save_rgb_png_to_path(carrier_to_rgb_array(encoded, image.shape), output_path)
    return layout, payload


def verify_png(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Verify an RGB PNG using sender and receiver keys."""
    try:
        image = load_png_from_path(input_path)
        carrier = rgb_array_to_carrier(image)
        context = encode_png_media_context(image.shape, carrier.size)
    except (OSError, ValueError, UnSupportedFileType) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier(carrier, IMAGE_MEDIA_CODE, context, sender_public_key, receiver_private_key)


def _remove_incomplete_output(output_path: str | bytes | PathLike[str]) -> None:
    """Delete an output file left by a failed encode, keeping the original error if this fails."""
    try:
        os.remove(output_path)
    except OSError:
        pass


def encode_wav(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an uncompressed PCM WAV file and save it.

    The WAV is read in bounded chunks: one pass for the masked media hash and a
    second pass that writes the output. If the second pass fails, or the input
    changed between the passes, the output file is removed and the error is raised.
    """
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    source = WavCarrier(input_path)
    context = encode_wav_media_context(source.info, source.total_units)
    encoding = prepare_carrier_encoding(source, AUDIO_MEDIA_CODE, context, signing_private_key, receiver_public_key, start_unit, lsb_count, user_payload, metadata)
    try:
        source.rewrite_to_path(output_path, encoding.embed_chunk)
        encoding.finish()
    except BaseException:
        _remove_incomplete_output(output_path)
        raise
    return encoding.layout, encoding.payload


def verify_wav(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Verify an uncompressed PCM WAV using sender and receiver keys.

    The WAV is read in bounded chunks. A missing, truncated, or unreadable WAV
    gives ``Cannot Verify``.
    """
    try:
        source = WavCarrier(input_path)
        context = encode_wav_media_context(source.info, source.total_units)
    except (OSError, ValueError) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier_source(source, AUDIO_MEDIA_CODE, context, sender_public_key, receiver_private_key)
