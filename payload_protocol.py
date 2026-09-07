"""Sign and verify byte-only metadata packets; no steganography or file I/O.

Wire format: uint32 big-endian JSON byte length | JSON bytes | RSA signature.
RSA-2048 signatures occupy 256 bytes; other RSA sizes use their key's byte size.
Trailing bytes are ignored so a packet can be extracted from a larger buffer.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair(
    key_size: int = 2048,
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA private/public key pair with public exponent 65537."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def export_key_pem(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> bytes:
    """Export RSA keys as PEM (unencrypted PKCS8 private keys or SPKI public keys)."""
    if isinstance(key, rsa.RSAPrivateKey):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    if isinstance(key, rsa.RSAPublicKey):
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    raise TypeError("Expected an RSA private or public key")


def load_key_pem(pem_bytes: bytes) -> rsa.RSAPrivateKey | rsa.RSAPublicKey:
    """Load an unencrypted RSA private key or an RSA public key from PEM bytes."""
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=None)
    except ValueError:
        key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise TypeError("Expected an RSA private or public key")
    return key


def create_payload(
    media_id: str, cover_bytes: bytes, custom_metadata: dict | None = None
) -> bytes:
    """Create canonical JSON with a UTC timestamp and a random 16-byte nonce.

    Metadata is omitted when None. Non-JSON values (including NaN) are rejected.
    Fresh calls intentionally differ because their timestamp and nonce are fresh.
    """
    if not isinstance(media_id, str):
        raise TypeError("media_id must be a string")
    if custom_metadata is not None and not isinstance(custom_metadata, dict):
        raise TypeError("custom_metadata must be a dictionary or None")
    payload = {
        "media_id": media_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cover_hash": hashlib.sha256(cover_bytes).hexdigest(),
        "nonce": secrets.token_hex(16),
    }
    if custom_metadata is not None:
        payload["metadata"] = custom_metadata
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def pack_verification_packet(
    payload_bytes: bytes, private_key: rsa.RSAPrivateKey
) -> bytes:
    """Frame and sign the exact supplied bytes with RSA PKCS#1 v1.5 / SHA-256."""
    header = struct.pack(">I", len(payload_bytes))
    signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    return header + payload_bytes + signature


def unpack_and_verify_packet(
    raw_packet: bytes,
    public_key: rsa.RSAPublicKey,
    current_cover_bytes: bytes | None = None,
) -> tuple[bool, str, dict | None]:
    """Verify framing and signature, then optionally check the cover hash.

    Incomplete buffers, invalid signatures, and invalid JSON return failure
    verdicts. Cover comparison requires the same bytes originally hashed, such
    as the original cover before embedding. Without a cover, only the signed
    metadata is authenticated. Replay detection is the caller's responsibility.
    """
    signature_len = (public_key.key_size + 7) // 8
    if len(raw_packet) < 4 + signature_len:
        return False, "Payload Missing or Incomplete", None

    payload_len = struct.unpack(">I", raw_packet[:4])[0]
    payload_end = 4 + payload_len
    if len(raw_packet) < payload_end + signature_len:
        return False, "Payload Missing or Corrupted", None

    payload_bytes = raw_packet[4:payload_end]
    signature = raw_packet[payload_end:payload_end + signature_len]
    try:
        public_key.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False, "Signature Invalid", None

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False, "Payload Missing or Corrupted", None
    if not isinstance(payload, dict):
        return False, "Payload Missing or Corrupted", None

    if current_cover_bytes is not None:
        if not isinstance(payload.get("cover_hash"), str):
            return False, "Payload Missing or Corrupted", None
        if hashlib.sha256(current_cover_bytes).hexdigest() != payload["cover_hash"]:
            return False, "Tampered", payload

    return True, "Authentic", payload
