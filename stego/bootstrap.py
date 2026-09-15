"""Build and parse the receiver bootstrap envelope and its authenticated data."""

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

from .bits import (
    _require_bytes,
    _validate_lsb_count,
    _validate_non_negative_integer,
    encode_protocol_field,
)
from .constants import (
    AEAD_NONCE_SIZE,
    BOOTSTRAP_PREFIX_FORMAT,
    PROTOCOL_FIELD_WIDTH,
    PROTOCOL_VERSION,
    SESSION_KEY_SIZE,
)


@dataclass(frozen=True)
class BootstrapFields:
    """Hold the fields carried by the receiver bootstrap envelope."""
    version: int
    lsb_count: int
    start_unit: int
    ciphertext_length: int
    session_key: bytes
    aead_nonce: bytes


def bootstrap_span(key: rsa.RSAPublicKey | rsa.RSAPrivateKey) -> int:
    """Return the serialised envelope size in carrier units at one LSB."""
    if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        raise TypeError("key must be an RSA public or private key")
    # RSA-OAEP ciphertext length equals modulus length, so RSA envelope and key sizes coincide; span is envelope-defined.
    envelope_bytes = (key.key_size + 7) // 8
    return envelope_bytes * 8


def _validate_bootstrap_fields(fields: BootstrapFields) -> BootstrapFields:
    """Check bootstrap field values and return normalised fields."""
    if not isinstance(fields, BootstrapFields):
        raise TypeError("fields must be BootstrapFields")
    version = _validate_non_negative_integer(fields.version, "version")
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported bootstrap version")
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
        lsb_count,
        start_unit,
        ciphertext_length,
        session_key,
        aead_nonce,
    )


def serialize_bootstrap(fields: BootstrapFields) -> bytes:
    """Serialise bootstrap fields using fixed-width protocol integers."""
    fields = _validate_bootstrap_fields(fields)
    return (
        struct.pack(BOOTSTRAP_PREFIX_FORMAT, fields.version, fields.lsb_count)
        + encode_protocol_field(fields.start_unit, "start_unit")
        + encode_protocol_field(fields.ciphertext_length, "ciphertext_length")
        + fields.session_key
        + fields.aead_nonce
    )


def parse_bootstrap(plaintext: bytes) -> BootstrapFields:
    """Parse and validate a fixed-width bootstrap envelope."""
    plaintext = _require_bytes(plaintext, "plaintext")
    prefix_length = struct.calcsize(BOOTSTRAP_PREFIX_FORMAT)
    expected_length = (
        prefix_length
        + 2 * PROTOCOL_FIELD_WIDTH
        + SESSION_KEY_SIZE
        + AEAD_NONCE_SIZE
    )
    if len(plaintext) != expected_length:
        raise ValueError("bootstrap length does not match fixed protocol format")
    version, lsb_count = struct.unpack(BOOTSTRAP_PREFIX_FORMAT, plaintext[:prefix_length])
    offset = prefix_length
    start_unit = int.from_bytes(
        plaintext[offset:offset + PROTOCOL_FIELD_WIDTH], "big"
    )
    offset += PROTOCOL_FIELD_WIDTH
    ciphertext_length = int.from_bytes(
        plaintext[offset:offset + PROTOCOL_FIELD_WIDTH], "big"
    )
    offset += PROTOCOL_FIELD_WIDTH
    session_key = plaintext[offset:offset + SESSION_KEY_SIZE]
    offset += SESSION_KEY_SIZE
    aead_nonce = plaintext[offset:offset + AEAD_NONCE_SIZE]
    return _validate_bootstrap_fields(
        BootstrapFields(
            version,
            lsb_count,
            start_unit,
            ciphertext_length,
            session_key,
            aead_nonce,
        )
    )


def encode_bootstrap_aad(fields: BootstrapFields) -> bytes:
    """Encode bootstrap fields authenticated as additional data."""
    fields = _validate_bootstrap_fields(fields)
    return (
        struct.pack(BOOTSTRAP_PREFIX_FORMAT, fields.version, fields.lsb_count)
        + encode_protocol_field(fields.start_unit, "start_unit")
        + encode_protocol_field(fields.ciphertext_length, "ciphertext_length")
    )
