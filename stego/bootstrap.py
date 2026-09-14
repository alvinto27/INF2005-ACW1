"""Build and parse the receiver bootstrap envelope and its authenticated data."""

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

from .bits import _require_bytes, _validate_lsb_count, _validate_non_negative_integer
from .constants import (
    AEAD_NONCE_SIZE,
    BOOTSTRAP_PREFIX_FORMAT,
    PROTOCOL_FLAGS,
    PROTOCOL_VERSION,
    SESSION_KEY_SIZE,
)
from .layout import carrier_field_width


@dataclass(frozen=True)
class BootstrapFields:
    """Hold the fields carried by the receiver bootstrap envelope."""
    version: int
    flags: int
    lsb_count: int
    start_unit: int
    ciphertext_length: int
    session_key: bytes
    aead_nonce: bytes


def bootstrap_span(public_key: rsa.RSAPublicKey) -> int:
    """Return the serialised envelope size in carrier units at one LSB."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")
    # RSA-OAEP ciphertext length equals modulus length, so RSA envelope and key sizes coincide; span is envelope-defined.
    envelope_bytes = (public_key.key_size + 7) // 8
    return envelope_bytes * 8


def _validate_bootstrap_fields(fields: BootstrapFields) -> BootstrapFields:
    """Check bootstrap field values and return normalised fields."""
    if not isinstance(fields, BootstrapFields):
        raise TypeError("fields must be BootstrapFields")
    version = _validate_non_negative_integer(fields.version, "version")
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported bootstrap version")
    flags = _validate_non_negative_integer(fields.flags, "flags")
    if flags != PROTOCOL_FLAGS:
        raise ValueError("bootstrap flags must be zero")
    lsb_count = _validate_lsb_count(fields.lsb_count)
    start_unit = _validate_non_negative_integer(fields.start_unit, "start_unit")
    ciphertext_length = _validate_non_negative_integer(fields.ciphertext_length, "ciphertext_length")
    session_key = _require_bytes(fields.session_key, "session_key")
    if len(session_key) != SESSION_KEY_SIZE:
        raise ValueError("session_key must contain exactly 32 bytes")
    aead_nonce = _require_bytes(fields.aead_nonce, "aead_nonce")
    if len(aead_nonce) != AEAD_NONCE_SIZE:
        raise ValueError("aead_nonce must contain exactly 12 bytes")
    return BootstrapFields(
        version,
        flags,
        lsb_count,
        start_unit,
        ciphertext_length,
        session_key,
        aead_nonce,
    )


def serialize_bootstrap(fields: BootstrapFields, total_units: int) -> bytes:
    """Serialise bootstrap fields using the carrier-derived field width."""
    fields = _validate_bootstrap_fields(fields)
    width = carrier_field_width(total_units)
    return (
        struct.pack(BOOTSTRAP_PREFIX_FORMAT, fields.version, fields.flags, fields.lsb_count)
        + fields.start_unit.to_bytes(width, "big")
        + fields.ciphertext_length.to_bytes(width, "big")
        + fields.session_key
        + fields.aead_nonce
    )


def parse_bootstrap(plaintext: bytes, total_units: int) -> BootstrapFields:
    """Parse and validate a bootstrap envelope for the carrier geometry."""
    plaintext = _require_bytes(plaintext, "plaintext")
    width = carrier_field_width(total_units)
    prefix_length = struct.calcsize(BOOTSTRAP_PREFIX_FORMAT)
    expected_length = prefix_length + 2 * width + SESSION_KEY_SIZE + AEAD_NONCE_SIZE
    if len(plaintext) != expected_length:
        raise ValueError("bootstrap length does not match carrier field width")
    version, flags, lsb_count = struct.unpack(BOOTSTRAP_PREFIX_FORMAT, plaintext[:prefix_length])
    offset = prefix_length
    start_unit = int.from_bytes(plaintext[offset:offset + width], "big")
    offset += width
    ciphertext_length = int.from_bytes(plaintext[offset:offset + width], "big")
    offset += width
    session_key = plaintext[offset:offset + SESSION_KEY_SIZE]
    offset += SESSION_KEY_SIZE
    aead_nonce = plaintext[offset:offset + AEAD_NONCE_SIZE]
    return _validate_bootstrap_fields(
        BootstrapFields(
            version,
            flags,
            lsb_count,
            start_unit,
            ciphertext_length,
            session_key,
            aead_nonce,
        )
    )


def encode_bootstrap_aad(fields: BootstrapFields, total_units: int) -> bytes:
    """Encode the bootstrap fields authenticated as additional data."""
    fields = _validate_bootstrap_fields(fields)
    width = carrier_field_width(total_units)
    return (
        struct.pack(BOOTSTRAP_PREFIX_FORMAT, fields.version, fields.flags, fields.lsb_count)
        + fields.start_unit.to_bytes(width, "big")
        + fields.ciphertext_length.to_bytes(width, "big")
    )
