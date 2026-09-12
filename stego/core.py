"""Encode and verify carriers, and provide file wrappers."""

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike, fspath

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
    PACKET_HEADER_SIZE,
    RSA_SIGNATURE_SIZE,
    NONCE_SIZE,
)
from .keys import (
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
    ceil_unit_count,
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
    PacketHeader,
    StartMagicCandidate,
    PayloadRecord,
    parse_packet_header,
    parse_payload,
    scan_start_magic,
    serialize_packet_header,
    serialize_payload,
)


def _embed_packet(carrier_units, layout, packet):
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


def encode_carrier(carrier_units, media_code, media_context, private_key, start_unit, lsb_count, user_payload, metadata):
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
    payload_length = 1 + len(media_id.encode("utf-8")) + 8 + 16 + 32 + 4 + len(user_payload) + 4 + len(metadata)
    layout = build_embedding_layout(carrier_units.size, start_unit, lsb_count, payload_length)
    media_hash = calculate_masked_media_hash(carrier_units, media_code, lsb_count, start_unit, layout.footprint)
    payload = PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
    payload_bytes = serialize_payload(payload)
    signing_input = encode_signing_input(media_code, media_context, layout, payload_bytes)
    signature = sign_bytes(signing_input, private_key)
    packet = serialize_packet_header(lsb_count, media_code, len(payload_bytes)) + payload_bytes + signature
    return _embed_packet(carrier_units, layout, packet), layout, payload


class VerificationError(ValueError):
    """A verification failure that carries the verdict to report back."""
    def __init__(self, verdict, message):
        """Set the verdict and message for a verification failure."""
        super().__init__(message)
        self.verdict = verdict


@dataclass(frozen=True)
class ResolvedCandidate:
    """Keep a discovered candidate with its header and embedding layout."""
    candidate: StartMagicCandidate
    header: PacketHeader
    layout: EmbeddingLayout


def resolve_candidate(carrier_units, candidate, expected_media_code):
    """Check the start unit and LSB count the receiver found instead of trusting supplied geometry."""
    carrier_units = _validate_carrier_units(carrier_units)
    if not isinstance(candidate, StartMagicCandidate):
        raise TypeError("candidate must be a StartMagicCandidate")
    expected_media_code = _validate_media_code(expected_media_code)
    header_units = ceil_unit_count(PACKET_HEADER_SIZE * 8, candidate.lsb_count)
    if candidate.start_unit + header_units > carrier_units.size:
        raise VerificationError("Wrong Start Location", "candidate header is out of range")
    header_bits = read_lsb_bits(carrier_units[candidate.start_unit:candidate.start_unit + header_units], PACKET_HEADER_SIZE * 8, candidate.lsb_count)
    header = parse_packet_header(bit_sequence_to_bytes(header_bits))
    if header.lsb_count != candidate.lsb_count:
        raise ValueError("header LSB count does not match scanned LSB count")
    if header.media_code != expected_media_code:
        raise ValueError("header media code does not match adapter media code")
    try:
        layout = build_embedding_layout(carrier_units.size, candidate.start_unit, candidate.lsb_count, header.payload_length)
    except ValueError as error:
        if "does not fit" in str(error):
            raise VerificationError("Wrong Start Location", "declared embedding footprint is out of range") from error
        raise
    return ResolvedCandidate(candidate, header, layout)


def verify_resolved_candidate(carrier_units, media_code, media_context, public_key, resolved):
    """Check a packet's signature and masked media hash, then return its payload."""
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    public_key = validate_rsa_public_key(public_key)
    if not isinstance(resolved, ResolvedCandidate):
        raise TypeError("resolved must be a ResolvedCandidate")
    layout = resolved.layout
    packet_bits_length = (PACKET_HEADER_SIZE + layout.payload_length + RSA_SIGNATURE_SIZE) * 8
    all_bits = read_lsb_bits(carrier_units[layout.start_unit:layout.start_unit + layout.footprint], layout.footprint * layout.lsb_count, layout.lsb_count)
    if np.any(all_bits[packet_bits_length:] != 0):
        raise ValueError("alignment padding must be zero")
    packet = bit_sequence_to_bytes(all_bits[:packet_bits_length])
    payload_start = PACKET_HEADER_SIZE
    payload_end = payload_start + resolved.header.payload_length
    payload_bytes = packet[payload_start:payload_end]
    payload = parse_payload(payload_bytes)
    signature = packet[payload_end:]
    signing_input = encode_signing_input(media_code, media_context, layout, payload_bytes)
    if not verify_signature(signing_input, signature, public_key):
        raise VerificationError("Signature Invalid", "RSA-PSS signature verification failed")
    calculated_hash = calculate_masked_media_hash(carrier_units, media_code, layout.lsb_count, layout.start_unit, layout.footprint)
    if calculated_hash != payload.media_hash:
        raise VerificationError("Tampered", "masked media hash mismatch")
    return payload


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


def _failure_result(verdict, detail):
    """Make a failed verification result without a payload."""
    return VerificationResult(False, verdict, detail, None, None, None, None, None, None)


def decode_carrier(carrier_units, media_code, media_context, public_key):
    """Discover and check a packet in carrier units, then return its verification result."""
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    public_key = validate_rsa_public_key(public_key)
    try:
        candidates = scan_start_magic(carrier_units)
    except ValueError as error:
        return _failure_result("Cannot Verify", f"scanner failure: {error}")
    if not candidates:
        return _failure_result("Payload Missing", "no start-magic candidate was found")

    valid = []
    failures = []
    for candidate in candidates:
        try:
            resolved = resolve_candidate(carrier_units, candidate, media_code)
            payload = verify_resolved_candidate(carrier_units, media_code, media_context, public_key, resolved)
            valid.append((payload, resolved.layout))
        except VerificationError as error:
            failures.append((error.verdict, candidate, str(error)))
        except ValueError as error:
            failures.append(("Cannot Verify", candidate, str(error)))
    if len(valid) > 1:
        return _failure_result("Cannot Verify", "ambiguous valid candidates were found")
    if len(valid) == 1:
        payload, layout = valid[0]
        preserved_bits = preserved_bit_count(layout.total_units, layout.footprint, layout.lsb_count)
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
    # Prefer the failure from the candidate that reached the deepest verification stage.
    priority = ("Tampered", "Signature Invalid", "Wrong Start Location", "Cannot Verify")
    verdict = next(item for item in priority if any(failure[0] == item for failure in failures))
    details = "; ".join(f"candidate {candidate.start_unit}/{candidate.lsb_count}: {detail}" for kind, candidate, detail in failures if kind == verdict)
    return _failure_result(verdict, details[:1000])


def _paths_resolve_same(first_path, second_path):
    """Check whether two filesystem paths point to the same place."""
    for path in (first_path, second_path):
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
    return os.path.normcase(os.path.realpath(os.fsdecode(fspath(first_path)))) == os.path.normcase(os.path.realpath(os.fsdecode(fspath(second_path))))


def encode_png(input_path, output_path, private_key, start_unit, lsb_count, user_payload, metadata):
    """Encode a signed packet into an RGB PNG file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    image = load_png_from_path(input_path)
    carrier = rgb_array_to_carrier(image)
    context = encode_png_media_context(image.shape, carrier.size)
    encoded, layout, payload = encode_carrier(carrier, IMAGE_MEDIA_CODE, context, private_key, start_unit, lsb_count, user_payload, metadata)
    save_rgb_png_to_path(carrier_to_rgb_array(encoded, image.shape), output_path)
    return layout, payload


def verify_png(input_path, public_key):
    """Load an RGB PNG file and check its signed packet."""
    try:
        image = load_png_from_path(input_path)
        carrier = rgb_array_to_carrier(image)
        context = encode_png_media_context(image.shape, carrier.size)
    except (OSError, ValueError, UnSupportedFileType) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier(carrier, IMAGE_MEDIA_CODE, context, public_key)


def encode_wav(input_path, output_path, private_key, start_unit, lsb_count, user_payload, metadata):
    """Encode a signed packet into an uncompressed PCM WAV file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    wav_data = load_pcm_wav_from_path(input_path)
    carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
    context = encode_wav_media_context(wav_data, carrier.size)
    encoded, layout, payload = encode_carrier(carrier, AUDIO_MEDIA_CODE, context, private_key, start_unit, lsb_count, user_payload, metadata)
    save_pcm_wav_to_path(wav_data_with_carrier(wav_data, encoded), output_path)
    return layout, payload


def verify_wav(input_path, public_key):
    """Load an uncompressed PCM WAV file and check its signed packet."""
    try:
        wav_data = load_pcm_wav_from_path(input_path)
        carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
        context = encode_wav_media_context(wav_data, carrier.size)
    except (OSError, ValueError) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_carrier(carrier, AUDIO_MEDIA_CODE, context, public_key)
