"""Encode and verify carriers, and provide file wrappers."""

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
    require_supported_flags,
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
    build_embedding_layout,
    calculate_masked_media_hash,
    encode_signing_input,
    max_user_payload_length,
    minimum_carrier_units,
    preserved_bit_count,
)
from .media import (
    UnSupportedFileType,
    carrier_to_rgb_array,
    encode_png_media_context,
    encode_wav_media_context,
    load_pcm_wav_from_path,
    load_png_from_path,
    rgb_array_to_carrier,
    save_pcm_wav_to_path,
    save_rgb_png_to_path,
    wav_data_with_carrier,
    wav_frame_bytes_to_carrier,
)
from .packet import (
    PayloadRecord,
    parse_payload,
    serialized_record_length,
    serialize_payload,
)


def _embed_packet(carrier_units: np.ndarray, layout: EmbeddingLayout, packet: bytes) -> np.ndarray:
    """Put a packet into the layout's carrier units and return a new carrier array."""
    packet = _require_bytes(packet, "packet")
    packet_bits = bytes_to_bit_sequence(packet)
    bits = np.zeros(layout.footprint * layout.lsb_count, dtype=np.uint8)
    bits[:packet_bits.size] = packet_bits
    result = carrier_units.copy()
    start = layout.start_unit
    end = start + layout.footprint
    result[start:end] = write_lsb_bits(result[start:end], bits, layout.lsb_count)
    return result


def encode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[np.ndarray, EmbeddingLayout, PayloadRecord]:
    """Encrypt, sign, and embed a record with a receiver bootstrap."""
    carrier_units = _validate_carrier_units(carrier_units)
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

    total_units = carrier_units.size
    span = bootstrap_span(receiver_public_key)
    minimum_record_length = serialized_record_length(MEDIA_ID_SIZE, 0, 0)
    minimum_units = minimum_carrier_units(span, lsb_count, minimum_record_length)
    if total_units < minimum_units:
        raise ValueError(
            "carrier is too small for the protocol: "
            f"total_units={total_units}, start_unit={start_unit}, "
            f"lsb_count={lsb_count}, minimum_units={minimum_units}"
        )
    carrier_units = carrier_units.copy()
    if start_unit < span:
        raise ValueError(
            f"start_unit {start_unit} is below the reserved bootstrap region; "
            f"lowest legal start_unit is {span}"
        )

    media_id = f"{MEDIA_PREFIXES[media_code]}-{secrets.token_hex(16)}"
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = secrets.token_bytes(NONCE_SIZE)
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
    ciphertext_length = record_length + GCM_TAG_SIZE
    layout = build_embedding_layout(
        total_units, start_unit, lsb_count, ciphertext_length, span
    )
    media_hash = calculate_masked_media_hash(
        carrier_units, media_code, lsb_count, start_unit, layout.footprint, span
    )
    payload = PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
    record_bytes = serialize_payload(payload)
    session_key = secrets.token_bytes(SESSION_KEY_SIZE)
    aead_nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    fields = BootstrapFields(
        PROTOCOL_VERSION,
        0,
        lsb_count,
        start_unit,
        ciphertext_length,
        session_key,
        aead_nonce,
    )
    ciphertext = aead_seal(
        session_key,
        aead_nonce,
        encode_bootstrap_aad(fields),
        record_bytes,
    )
    if len(ciphertext) != ciphertext_length:
        raise ValueError("AES-GCM ciphertext has an unexpected length")
    signature = sign_bytes(
        encode_signing_input(media_code, media_context, layout, fields.flags, ciphertext),
        signing_private_key,
    )
    envelope = seal_to_public_key(serialize_bootstrap(fields), receiver_public_key)
    if len(envelope) * 8 != span:
        raise ValueError("bootstrap envelope has an unexpected span")
    encoded = _embed_packet(carrier_units, layout, ciphertext + signature)
    bootstrap_slice = slice(BOOTSTRAP_START_UNIT, BOOTSTRAP_START_UNIT + span)
    encoded[bootstrap_slice] = write_lsb_bits(
        encoded[bootstrap_slice],
        bytes_to_bit_sequence(envelope),
        BOOTSTRAP_LSB_COUNT,
    )
    return encoded, layout, payload


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


def decode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Recover and verify an encrypted packet using the receiver's private key."""
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    sender_public_key = validate_rsa_public_key(sender_public_key)
    receiver_private_key = validate_rsa_private_key(receiver_private_key)
    span = bootstrap_span(receiver_private_key)
    try:
        envelope_bits = read_lsb_bits(
            carrier_units[BOOTSTRAP_START_UNIT:BOOTSTRAP_START_UNIT + span],
            span,
            BOOTSTRAP_LSB_COUNT,
        )
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
            carrier_units.size,
            fields.start_unit,
            fields.lsb_count,
            fields.ciphertext_length,
            span,
        )
    except ValueError as error:
        return _failure_result("Wrong Start Location", str(error))
    packet_bits_length = (layout.ciphertext_length + RSA_SIGNATURE_SIZE) * 8
    try:
        all_bits = read_lsb_bits(
            carrier_units[layout.start_unit:layout.start_unit + layout.footprint],
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
        media_code, media_context, layout, fields.flags, ciphertext
    )
    if not verify_signature(signing_input, signature, sender_public_key):
        return _failure_result("Signature Invalid", "RSA-PSS signature verification failed")
    try:
        require_supported_flags(fields.flags)
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
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
    calculated_hash = calculate_masked_media_hash(
        carrier_units,
        media_code,
        layout.lsb_count,
        layout.start_unit,
        layout.footprint,
        layout.bootstrap_span,
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


def encode_wav(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an uncompressed PCM WAV file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    wav_data = load_pcm_wav_from_path(input_path)
    carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes, wav_data.sample_width)
    context = encode_wav_media_context(wav_data, carrier.size)
    encoded, layout, payload = encode_carrier(carrier, AUDIO_MEDIA_CODE, context, signing_private_key, receiver_public_key, start_unit, lsb_count, user_payload, metadata)
    save_pcm_wav_to_path(wav_data_with_carrier(wav_data, encoded), output_path)
    return layout, payload


def verify_wav(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Verify an uncompressed PCM WAV using sender and receiver keys."""
    try:
        wav_data = load_pcm_wav_from_path(input_path)
        carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes, wav_data.sample_width)
        context = encode_wav_media_context(wav_data, carrier.size)
    except (OSError, ValueError) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier(carrier, AUDIO_MEDIA_CODE, context, sender_public_key, receiver_private_key)
