"""Embedding layout, masked media hash, and signing input."""

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
    MEDIA_HASH_CONTEXT_FORMAT,
    MEDIA_HASH_DOMAIN,
    PACKET_HEADER_SIZE,
    PROTOCOL_VERSION,
    RSA_SIGNATURE_SIZE,
    SIGNING_CONTEXT_FORMAT,
    SIGNING_DOMAIN,
)


def ceil_unit_count(bit_length, lsb_count):
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    return (bit_length + lsb_count - 1) // lsb_count


@dataclass(frozen=True)
class EmbeddingLayout:
    total_units: int
    start_unit: int
    footprint: int
    lsb_count: int
    payload_length: int
    pad_bits: int


def build_embedding_layout(total_units, start_unit, lsb_count, payload_length):
    total_units = _validate_non_negative_integer(total_units, "total_units")
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    payload_length = validate_payload_length(payload_length)
    packet_bits = (PACKET_HEADER_SIZE + payload_length + RSA_SIGNATURE_SIZE) * 8
    footprint = ceil_unit_count(packet_bits, lsb_count)
    pad_bits = footprint * lsb_count - packet_bits
    if start_unit + footprint > total_units:
        raise ValueError("embedding footprint does not fit after start_unit")
    return EmbeddingLayout(total_units, start_unit, footprint, lsb_count, payload_length, pad_bits)


def preserved_bit_count(total_units, footprint, lsb_count):
    total_units = _validate_non_negative_integer(total_units, "total_units")
    footprint = _validate_non_negative_integer(footprint, "footprint")
    lsb_count = _validate_lsb_count(lsb_count)
    if footprint > total_units:
        raise ValueError("footprint exceeds total_units")
    return 8 * (total_units - footprint) + (8 - lsb_count) * footprint


def calculate_masked_media_hash(carrier_units, media_code, lsb_count, start_unit, footprint):
    """Hash all intentionally preserved carrier bits without expanding them to bits."""
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
    preimage = (
        MEDIA_HASH_DOMAIN
        + struct.pack(MEDIA_HASH_CONTEXT_FORMAT, media_code, lsb_count, total_units, start_unit, footprint)
        + masked.tobytes()
    )
    return hashlib.sha256(preimage).digest()


def encode_signing_input(media_code, media_context, layout, payload_bytes):
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    if not isinstance(layout, EmbeddingLayout):
        raise TypeError("layout must be an EmbeddingLayout")
    payload_bytes = validate_payload_bytes(payload_bytes)
    if len(payload_bytes) != layout.payload_length:
        raise ValueError("payload length does not match layout")
    return (
        SIGNING_DOMAIN
        + struct.pack(
            SIGNING_CONTEXT_FORMAT,
            PROTOCOL_VERSION,
            media_code,
            layout.lsb_count,
            layout.total_units,
            layout.start_unit,
            layout.footprint,
            layout.payload_length,
        )
        + media_context
        + payload_bytes
    )
