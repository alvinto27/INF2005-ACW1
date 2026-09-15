"""Serialise and parse payload records."""

from dataclasses import dataclass

from .bits import (
    _require_bytes,
    _validate_non_negative_integer,
    encode_protocol_field,
    validate_payload_bytes,
)
from .constants import (
    MAX_MEDIA_ID_BYTES,
    NONCE_SIZE,
    PROTOCOL_FIELD_WIDTH,
    SHA256_DIGEST_SIZE,
)


def serialized_record_length(media_id_length: int, user_payload_length: int, metadata_length: int) -> int:
    """Calculate the fixed-width serialised record length from its field lengths."""
    media_id_length = _validate_non_negative_integer(media_id_length, "media_id_length")
    user_payload_length = _validate_non_negative_integer(user_payload_length, "user_payload_length")
    metadata_length = _validate_non_negative_integer(metadata_length, "metadata_length")
    return (
        1
        + media_id_length
        + PROTOCOL_FIELD_WIDTH
        + 16
        + 32
        + PROTOCOL_FIELD_WIDTH
        + user_payload_length
        + PROTOCOL_FIELD_WIDTH
        + metadata_length
    )


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


def serialize_payload(record: PayloadRecord) -> bytes:
    """Turn a payload record into checked packet payload bytes."""
    if not isinstance(record, PayloadRecord):
        raise TypeError("record must be a PayloadRecord")
    media_id = record.media_id.encode("utf-8")
    payload = (
        bytes((len(media_id),))
        + media_id
        + encode_protocol_field(record.timestamp, "timestamp")
        + record.nonce
        + record.media_hash
        + encode_protocol_field(len(record.user_payload), "user_payload_length")
        + record.user_payload
        + encode_protocol_field(len(record.metadata), "metadata_length")
        + record.metadata
    )
    return validate_payload_bytes(payload)


def _take_payload_field(payload_bytes: bytes, offset: int, length: int, name: str) -> tuple[bytes, int]:
    """Take one checked field from payload bytes and return where the next field starts."""
    end = offset + length
    if end > len(payload_bytes):
        raise ValueError(f"payload is truncated in {name}")
    return payload_bytes[offset:end], end


def parse_payload(payload_bytes: bytes) -> PayloadRecord:
    """Read checked payload bytes into a payload record."""
    payload_bytes = validate_payload_bytes(payload_bytes)
    if not payload_bytes:
        raise ValueError("payload is truncated before media_id length")
    media_id_length = payload_bytes[0]
    offset = 1
    media_id_bytes, offset = _take_payload_field(payload_bytes, offset, media_id_length, "media_id")
    fixed, offset = _take_payload_field(
        payload_bytes,
        offset,
        PROTOCOL_FIELD_WIDTH + NONCE_SIZE + SHA256_DIGEST_SIZE,
        "fixed fields",
    )
    timestamp = int.from_bytes(fixed[:PROTOCOL_FIELD_WIDTH], "big")
    nonce = fixed[PROTOCOL_FIELD_WIDTH:PROTOCOL_FIELD_WIDTH + NONCE_SIZE]
    media_hash = fixed[PROTOCOL_FIELD_WIDTH + NONCE_SIZE:]
    user_length_bytes, offset = _take_payload_field(
        payload_bytes, offset, PROTOCOL_FIELD_WIDTH, "user length"
    )
    user_length = int.from_bytes(user_length_bytes, "big")
    user_payload, offset = _take_payload_field(payload_bytes, offset, user_length, "user payload")
    metadata_length_bytes, offset = _take_payload_field(
        payload_bytes, offset, PROTOCOL_FIELD_WIDTH, "metadata length"
    )
    metadata_length = int.from_bytes(metadata_length_bytes, "big")
    metadata, offset = _take_payload_field(payload_bytes, offset, metadata_length, "metadata")
    if offset != len(payload_bytes):
        raise ValueError("payload contains trailing bytes")
    try:
        media_id = media_id_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("media_id must contain valid UTF-8") from error
    return PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
