"""Packet header, payload records, and start-magic discovery."""

import struct
from dataclasses import dataclass

import numpy as np

from .bits import (
    _require_bytes,
    _validate_carrier_units,
    _validate_lsb_count,
    _validate_media_code,
    _validate_positive_integer,
    _validate_non_negative_integer,
    bytes_to_bit_sequence,
    validate_payload_bytes,
    validate_payload_length,
)
from .constants import (
    MAX_MAGIC_CANDIDATES,
    MAX_MEDIA_ID_BYTES,
    PACKET_HEADER_FORMAT,
    PACKET_HEADER_SIZE,
    PROTOCOL_VERSION,
    SHA256_DIGEST_SIZE,
    START_MAGIC,
    SUPPORTED_LSB_COUNTS,
    NONCE_SIZE,
)
from .layout import ceil_unit_count


@dataclass(frozen=True)
class PacketHeader:
    version: int
    lsb_count: int
    media_code: int
    payload_length: int


def serialize_packet_header(lsb_count, media_code, payload_length):
    return struct.pack(
        PACKET_HEADER_FORMAT,
        START_MAGIC,
        PROTOCOL_VERSION,
        _validate_lsb_count(lsb_count),
        _validate_media_code(media_code),
        validate_payload_length(payload_length),
    )


def parse_packet_header(header_bytes):
    header_bytes = _require_bytes(header_bytes, "header_bytes")
    if len(header_bytes) != PACKET_HEADER_SIZE:
        raise ValueError("header must contain exactly 23 bytes")
    magic, version, lsb_count, media_code, payload_length = struct.unpack(PACKET_HEADER_FORMAT, header_bytes)
    if magic != START_MAGIC:
        raise ValueError("header has the wrong start magic")
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    return PacketHeader(version, _validate_lsb_count(lsb_count), _validate_media_code(media_code), validate_payload_length(payload_length))


@dataclass(frozen=True)
class PayloadRecord:
    media_id: str
    timestamp: int
    nonce: bytes
    media_hash: bytes
    user_payload: bytes
    metadata: bytes

    def __post_init__(self):
        if not isinstance(self.media_id, str):
            raise TypeError("media_id must be text")
        media_id_bytes = self.media_id.encode("utf-8")
        if not media_id_bytes or len(media_id_bytes) > MAX_MEDIA_ID_BYTES:
            raise ValueError("media_id UTF-8 length must be between 1 and 255 bytes")
        timestamp = _validate_non_negative_integer(self.timestamp, "timestamp")
        nonce = _require_bytes(self.nonce, "nonce")
        media_hash = _require_bytes(self.media_hash, "media_hash")
        user_payload = _require_bytes(self.user_payload, "user_payload")
        metadata = _require_bytes(self.metadata, "metadata")
        if len(nonce) != NONCE_SIZE:
            raise ValueError("nonce must contain exactly 16 bytes")
        if len(media_hash) != SHA256_DIGEST_SIZE:
            raise ValueError("media_hash must contain exactly 32 bytes")
        try:
            metadata.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("metadata must contain valid UTF-8 bytes") from error
        object.__setattr__(self, "timestamp", timestamp)


def serialize_payload(record):
    if not isinstance(record, PayloadRecord):
        raise TypeError("record must be a PayloadRecord")
    media_id = record.media_id.encode("utf-8")
    payload = (
        bytes((len(media_id),))
        + media_id
        + struct.pack(">Q", record.timestamp)
        + record.nonce
        + record.media_hash
        + struct.pack(">I", len(record.user_payload))
        + record.user_payload
        + struct.pack(">I", len(record.metadata))
        + record.metadata
    )
    return validate_payload_bytes(payload)


def _take_payload_field(payload_bytes, offset, length, name):
    end = offset + length
    if end > len(payload_bytes):
        raise ValueError(f"payload is truncated in {name}")
    return payload_bytes[offset:end], end


def parse_payload(payload_bytes):
    payload_bytes = validate_payload_bytes(payload_bytes)
    if not payload_bytes:
        raise ValueError("payload is truncated before media_id length")
    media_id_length = payload_bytes[0]
    offset = 1
    media_id_bytes, offset = _take_payload_field(payload_bytes, offset, media_id_length, "media_id")
    fixed, offset = _take_payload_field(payload_bytes, offset, 8 + NONCE_SIZE + SHA256_DIGEST_SIZE, "fixed fields")
    timestamp = struct.unpack(">Q", fixed[:8])[0]
    nonce = fixed[8:24]
    media_hash = fixed[24:56]
    user_length_bytes, offset = _take_payload_field(payload_bytes, offset, 4, "user length")
    user_length = struct.unpack(">I", user_length_bytes)[0]
    user_payload, offset = _take_payload_field(payload_bytes, offset, user_length, "user payload")
    metadata_length_bytes, offset = _take_payload_field(payload_bytes, offset, 4, "metadata length")
    metadata_length = struct.unpack(">I", metadata_length_bytes)[0]
    metadata, offset = _take_payload_field(payload_bytes, offset, metadata_length, "metadata")
    if offset != len(payload_bytes):
        raise ValueError("payload contains trailing bytes")
    try:
        media_id = media_id_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("media_id must contain valid UTF-8") from error
    return PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)


@dataclass(frozen=True)
class StartMagicCandidate:
    start_unit: int
    lsb_count: int


def _magic_unit_masks_and_values(lsb_count):
    lsb_count = _validate_lsb_count(lsb_count)
    magic_bits = bytes_to_bit_sequence(START_MAGIC)
    unit_count = ceil_unit_count(magic_bits.size, lsb_count)
    masks = np.zeros(unit_count, dtype=np.uint8)
    values = np.zeros(unit_count, dtype=np.uint8)
    for bit_index, bit in enumerate(magic_bits):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        masks[unit_index] |= np.uint8(1 << position)
        values[unit_index] |= np.uint8(int(bit) << position)
    return masks, values


def _find_magic_start_mask(carrier_units, lsb_count):
    carrier_units = _validate_carrier_units(carrier_units)
    masks, values = _magic_unit_masks_and_values(lsb_count)
    if carrier_units.size < masks.size:
        return np.empty(0, dtype=bool), 0
    candidate_count = carrier_units.size - masks.size + 1
    matches = np.ones(candidate_count, dtype=bool)
    for offset in range(masks.size):
        matches &= (carrier_units[offset:offset + candidate_count] & masks[offset]) == values[offset]
    return matches, int(np.count_nonzero(matches))


def scan_start_magic(carrier_units, max_candidates=MAX_MAGIC_CANDIDATES):
    carrier_units = _validate_carrier_units(carrier_units)
    max_candidates = _validate_positive_integer(max_candidates, "max_candidates")
    candidates = []
    for lsb_count in SUPPORTED_LSB_COUNTS:
        matches, count = _find_magic_start_mask(carrier_units, lsb_count)
        if count > max_candidates - len(candidates):
            raise ValueError("magic candidate limit exceeded")
        candidates.extend(StartMagicCandidate(int(start), lsb_count) for start in np.flatnonzero(matches))
    return tuple(sorted(candidates, key=lambda item: (item.start_unit, item.lsb_count)))
