"""Build embedding layouts, masked media hashes, and signing input for signed packets."""

import hashlib
import struct
from dataclasses import dataclass

import numpy as np

from .bits import (
    _require_bytes,
    _validate_carrier_units,
    _validate_lsb_count,
    _validate_media_code,
    _validate_non_negative_integer,
    validate_payload_bytes,
    validate_payload_length,
)
from .constants import (
    MEDIA_HASH_CONTEXT_PREFIX_FORMAT,
    MEDIA_HASH_DOMAIN,
    PACKET_HEADER_SIZE,
    PROTOCOL_FLAGS,
    PROTOCOL_VERSION,
    RSA_SIGNATURE_SIZE,
    SIGNING_CONTEXT_PREFIX_FORMAT,
    SIGNING_DOMAIN,
)


def ceil_unit_count(bit_length: int, lsb_count: int) -> int:
    """How many carrier units it takes to hold this many bits, at lsb_count bits per unit."""
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    return (bit_length + lsb_count - 1) // lsb_count


@dataclass(frozen=True)
class EmbeddingLayout:
    """Keep the carrier-unit footprint and packet geometry used for embedding."""
    total_units: int
    start_unit: int
    footprint: int
    lsb_count: int
    payload_length: int
    pad_bits: int


def max_payload_length(total_units: int, start_unit: int, lsb_count: int) -> int:
    """Calculate the maximum packet payload length that fits after start_unit."""
    total_units = _validate_non_negative_integer(total_units, "total_units")
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    available_bytes = ((total_units - start_unit) * lsb_count) // 8
    return max(0, available_bytes - PACKET_HEADER_SIZE - RSA_SIGNATURE_SIZE)


def carrier_field_width(total_units: int) -> int:
    """Calculate the byte width for carrier-bounded fields."""
    total_units = _validate_non_negative_integer(total_units, "total_units")
    return max(1, (total_units.bit_length() + 7) // 8)


def build_embedding_layout(total_units: int, start_unit: int, lsb_count: int, payload_length: int) -> EmbeddingLayout:
    """Calculate and check how many carrier units a packet needs."""
    total_units = _validate_non_negative_integer(total_units, "total_units")
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    payload_length = validate_payload_length(payload_length)
    packet_bits = (PACKET_HEADER_SIZE + payload_length + RSA_SIGNATURE_SIZE) * 8
    footprint = ceil_unit_count(packet_bits, lsb_count)
    pad_bits = footprint * lsb_count - packet_bits
    if start_unit + footprint > total_units:
        maximum = max_payload_length(total_units, start_unit, lsb_count)
        # Keep "does not fit": core.resolve_candidate maps it to Wrong Start Location.
        raise ValueError(
            "embedding footprint does not fit after start_unit: "
            f"total_units={total_units}, start_unit={start_unit}, "
            f"lsb_count={lsb_count}, max_payload_length={maximum}"
        )
    return EmbeddingLayout(total_units, start_unit, footprint, lsb_count, payload_length, pad_bits)


def preserved_bit_count(total_units: int, footprint: int, lsb_count: int) -> int:
    """Count the carrier bits left unchanged after embedding a packet footprint."""
    total_units = _validate_non_negative_integer(total_units, "total_units")
    footprint = _validate_non_negative_integer(footprint, "footprint")
    lsb_count = _validate_lsb_count(lsb_count)
    if footprint > total_units:
        raise ValueError("footprint exceeds total_units")
    return 8 * (total_units - footprint) + (8 - lsb_count) * footprint


def calculate_masked_media_hash(carrier_units: np.ndarray, media_code: int, lsb_count: int, start_unit: int, footprint: int) -> bytes:
    """Hash the carrier with the packet's low bits cleared, so the sender and receiver get the
    same answer even though the packet overwrote those bits."""
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    lsb_count = _validate_lsb_count(lsb_count)
    total_units = _validate_non_negative_integer(carrier_units.size, "total_units")
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    footprint = _validate_non_negative_integer(footprint, "footprint")
    if start_unit + footprint > total_units:
        raise ValueError("masked media footprint is out of range")
    masked = carrier_units.copy()
    mask = (~((1 << lsb_count) - 1)) & 0xFF
    masked[start_unit:start_unit + footprint] &= np.uint8(mask)
    width = carrier_field_width(total_units)
    preimage = (
        MEDIA_HASH_DOMAIN
        + struct.pack(MEDIA_HASH_CONTEXT_PREFIX_FORMAT, media_code, lsb_count)
        + total_units.to_bytes(width, "big")
        + start_unit.to_bytes(width, "big")
        + footprint.to_bytes(width, "big")
        + masked.tobytes()
    )
    return hashlib.sha256(preimage).digest()


def encode_signing_input(media_code: int, media_context: bytes, layout: EmbeddingLayout, payload_bytes: bytes) -> bytes:
    """Build signed bytes covering the packet geometry and payload, so moving the packet makes verification fail."""
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    if not isinstance(layout, EmbeddingLayout):
        raise TypeError("layout must be an EmbeddingLayout")
    payload_bytes = validate_payload_bytes(payload_bytes)
    if len(payload_bytes) != layout.payload_length:
        raise ValueError("payload length does not match layout")
    width = carrier_field_width(layout.total_units)
    return (
        SIGNING_DOMAIN
        + struct.pack(
            SIGNING_CONTEXT_PREFIX_FORMAT,
            # Use PROTOCOL_VERSION, never a packet version: reading it looks tidy but removes downgrade protection.
            PROTOCOL_VERSION,
            PROTOCOL_FLAGS,
            media_code,
            layout.lsb_count,
        )
        + layout.total_units.to_bytes(width, "big")
        + layout.start_unit.to_bytes(width, "big")
        + layout.footprint.to_bytes(width, "big")
        + layout.payload_length.to_bytes(width, "big")
        + media_context
        + payload_bytes
    )
