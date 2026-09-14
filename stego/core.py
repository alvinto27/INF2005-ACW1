"""Encode and verify carriers, and provide file wrappers."""

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike, fspath

from cryptography.hazmat.primitives.asymmetric import rsa
import numpy as np

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
    AUDIO_MEDIA_CODE,
    IMAGE_MEDIA_CODE,
    MEDIA_PREFIXES,
    RSA_SIGNATURE_SIZE,
    NONCE_SIZE,
)
from .crypto import (
    display_rsa_public_key_fingerprint,
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


def encode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, private_key: rsa.RSAPrivateKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[np.ndarray, EmbeddingLayout, PayloadRecord]:
    """Create, sign, and embed a packet, then return the new units, layout, and payload."""
    carrier_units = _validate_carrier_units(carrier_units).copy()
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    private_key = validate_rsa_private_key(private_key)
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    user_payload = _require_bytes(user_payload, "user_payload")
    metadata = _require_bytes(metadata, "metadata")
    try:
        metadata.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("metadata must contain valid UTF-8 bytes") from error

    media_id = f"{MEDIA_PREFIXES[media_code]}-{secrets.token_hex(16)}"
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = secrets.token_bytes(NONCE_SIZE)
    payload_length = serialized_record_length(len(media_id.encode("utf-8")), len(user_payload), len(metadata))
    layout = build_embedding_layout(carrier_units.size, start_unit, lsb_count, payload_length, 0)
    media_hash = calculate_masked_media_hash(carrier_units, media_code, lsb_count, start_unit, layout.footprint, 0)
    payload = PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
    payload_bytes = serialize_payload(payload)
    signing_input = encode_signing_input(media_code, media_context, layout, payload_bytes)
    signature = sign_bytes(signing_input, private_key)
    packet = payload_bytes + signature
    return _embed_packet(carrier_units, layout, packet), layout, payload


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


def decode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, payload_length: int) -> VerificationResult:
    """Check a packet; payload_length is the complete serialized record length, not user bytes."""
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    public_key = validate_rsa_public_key(public_key)
    try:
        start_unit = _validate_non_negative_integer(start_unit, "start_unit")
        lsb_count = _validate_lsb_count(lsb_count)
        payload_length = _validate_non_negative_integer(payload_length, "payload_length")
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
    # Geometry fields are validated and bootstrap_span is zero, so this narrow
    # layout failure can only mean that the packet does not fit the carrier.
    try:
        layout = build_embedding_layout(carrier_units.size, start_unit, lsb_count, payload_length, 0)
    except ValueError as error:
        return _failure_result("Wrong Start Location", str(error))
    packet_bits_length = (layout.payload_length + RSA_SIGNATURE_SIZE) * 8
    try:
        all_bits = read_lsb_bits(
            carrier_units[layout.start_unit:layout.start_unit + layout.footprint],
            layout.footprint * layout.lsb_count,
            layout.lsb_count,
        )
        if np.any(all_bits[packet_bits_length:] != 0):
            return _failure_result("Cannot Verify", "alignment padding must be zero")
        packet = bit_sequence_to_bytes(all_bits[:packet_bits_length])
        payload_bytes = packet[:payload_length]
        signature = packet[payload_length:]
        payload = parse_payload(payload_bytes)
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error))
    signing_input = encode_signing_input(media_code, media_context, layout, payload_bytes)
    if not verify_signature(signing_input, signature, public_key):
        return _failure_result("Signature Invalid", "RSA-PSS signature verification failed")
    calculated_hash = calculate_masked_media_hash(carrier_units, media_code, layout.lsb_count, layout.start_unit, layout.footprint, 0)
    if calculated_hash != payload.media_hash:
        return _failure_result("Tampered", "masked media hash mismatch")
    preserved_bits = preserved_bit_count(layout.total_units, layout.footprint, layout.lsb_count, 0)
    total_bits = layout.total_units * 8
    ratio = preserved_bits / total_bits if total_bits else 0.0
    return VerificationResult(
        True,
        "Authentic",
        "signature and masked media hash are valid under the supplied public key",
        payload,
        display_rsa_public_key_fingerprint(public_key),
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


def encode_png(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], private_key: rsa.RSAPrivateKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an RGB PNG file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    image = load_png_from_path(input_path)
    carrier = rgb_array_to_carrier(image)
    context = encode_png_media_context(image.shape, carrier.size)
    encoded, layout, payload = encode_carrier(carrier, IMAGE_MEDIA_CODE, context, private_key, start_unit, lsb_count, user_payload, metadata)
    save_rgb_png_to_path(carrier_to_rgb_array(encoded, image.shape), output_path)
    return layout, payload


def verify_png(input_path: str | bytes | PathLike[str], public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, payload_length: int) -> VerificationResult:
    """Check an RGB PNG; payload_length is the complete serialized record length, not user bytes."""
    try:
        image = load_png_from_path(input_path)
        carrier = rgb_array_to_carrier(image)
        context = encode_png_media_context(image.shape, carrier.size)
    except (OSError, ValueError, UnSupportedFileType) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier(carrier, IMAGE_MEDIA_CODE, context, public_key, start_unit, lsb_count, payload_length)


def encode_wav(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], private_key: rsa.RSAPrivateKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an uncompressed PCM WAV file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    wav_data = load_pcm_wav_from_path(input_path)
    carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes, wav_data.sample_width)
    context = encode_wav_media_context(wav_data, carrier.size)
    encoded, layout, payload = encode_carrier(carrier, AUDIO_MEDIA_CODE, context, private_key, start_unit, lsb_count, user_payload, metadata)
    save_pcm_wav_to_path(wav_data_with_carrier(wav_data, encoded), output_path)
    return layout, payload


def verify_wav(input_path: str | bytes | PathLike[str], public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, payload_length: int) -> VerificationResult:
    """Check an uncompressed PCM WAV; payload_length is the complete serialized record length, not user bytes."""
    try:
        wav_data = load_pcm_wav_from_path(input_path)
        carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes, wav_data.sample_width)
        context = encode_wav_media_context(wav_data, carrier.size)
    except (OSError, ValueError) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier(carrier, AUDIO_MEDIA_CODE, context, public_key, start_unit, lsb_count, payload_length)
