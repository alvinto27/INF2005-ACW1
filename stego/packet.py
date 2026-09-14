"""Serialise and parse payload records."""

import struct
from dataclasses import dataclass

from .bits import (
    _require_bytes,
    _validate_non_negative_integer,
    validate_payload_bytes,
)
from .constants import (
    MAX_MEDIA_ID_BYTES,
    NONCE_SIZE,
    SHA256_DIGEST_SIZE,
)
from .layout import carrier_field_width


def serialized_record_length(media_id_length: int, user_payload_length: int, metadata_length: int, total_units: int) -> int:
    """Calculate the serialised record length from its field lengths and carrier width."""
    media_id_length = _validate_non_negative_integer(media_id_length, "media_id_length")
    user_payload_length = _validate_non_negative_integer(user_payload_length, "user_payload_length")
    metadata_length = _validate_non_negative_integer(metadata_length, "metadata_length")
    width = carrier_field_width(total_units)
    return 1 + media_id_length + 8 + 16 + 32 + width + user_payload_length + width + metadata_length


@dataclass(frozen=True)
class PayloadRecord:
    """Keep the signed media record and the user's payload."""
    media_id: str
    timestamp: int
    nonce: bytes
    media_hash: bytes
    user_payload: bytes
    metadata: bytes

    def __post_init__(self) -> None:
        """Check and normalise all payload record fields."""
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


def serialize_payload(record: PayloadRecord, total_units: int) -> bytes:
    """Turn a payload record into checked packet payload bytes."""
    if not isinstance(record, PayloadRecord):
        raise TypeError("record must be a PayloadRecord")
    width = carrier_field_width(total_units)
    media_id = record.media_id.encode("utf-8")
    payload = (
        bytes((len(media_id),))
        + media_id
        + struct.pack(">Q", record.timestamp)
        + record.nonce
        + record.media_hash
        + len(record.user_payload).to_bytes(width, "big")
        + record.user_payload
        + len(record.metadata).to_bytes(width, "big")
        + record.metadata
    )
    return validate_payload_bytes(payload)


def _take_payload_field(payload_bytes: bytes, offset: int, length: int, name: str) -> tuple[bytes, int]:
    """Take one checked field from payload bytes and return where the next field starts."""
    end = offset + length
    if end > len(payload_bytes):
        raise ValueError(f"payload is truncated in {name}")
    return payload_bytes[offset:end], end


def parse_payload(payload_bytes: bytes, total_units: int) -> PayloadRecord:
    """Read checked payload bytes into a payload record."""
    payload_bytes = validate_payload_bytes(payload_bytes)
    width = carrier_field_width(total_units)
    if not payload_bytes:
        raise ValueError("payload is truncated before media_id length")
    media_id_length = payload_bytes[0]
    offset = 1
    media_id_bytes, offset = _take_payload_field(payload_bytes, offset, media_id_length, "media_id")
    fixed, offset = _take_payload_field(payload_bytes, offset, 8 + NONCE_SIZE + SHA256_DIGEST_SIZE, "fixed fields")
    timestamp = struct.unpack(">Q", fixed[:8])[0]
    nonce = fixed[8:24]
    media_hash = fixed[24:56]
    user_length_bytes, offset = _take_payload_field(payload_bytes, offset, width, "user length")
    user_length = int.from_bytes(user_length_bytes, "big")
    user_payload, offset = _take_payload_field(payload_bytes, offset, user_length, "user payload")
    metadata_length_bytes, offset = _take_payload_field(payload_bytes, offset, width, "metadata length")
    metadata_length = int.from_bytes(metadata_length_bytes, "big")
    metadata, offset = _take_payload_field(payload_bytes, offset, metadata_length, "metadata")
    if offset != len(payload_bytes):
        raise ValueError("payload contains trailing bytes")
    try:
        media_id = media_id_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("media_id must contain valid UTF-8") from error
    return PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
