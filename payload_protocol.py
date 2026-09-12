"""
INF2005 ACW1
FR3 - Payload Generation
FR4 - Digital Signature

This module:
- detects whether supplied cover bytes are PNG image or WAV audio
- creates a compact verification payload
- digitally signs the payload using RSA-PSS with SHA-256
- verifies the signature using the corresponding RSA public key
- packs/unpacks payload + signature for later steganography integration

No steganography is performed in this file.
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


RSA_KEY_SIZE = 2048

MEDIA_PREFIXES = {
    "image": "IMG",
    "audio": "AUD",
}


# ============================================================
# FR3 - MEDIA TYPE DETECTION
# ============================================================

def detect_media_type(cover_bytes: bytes) -> str:
    """
    Detect whether the supplied bytes represent a PNG image
    or a WAV audio file.

    Returns:
        "image" for PNG
        "audio" for WAV

    Raises:
        ValueError for unsupported media formats.
    """

    if not isinstance(cover_bytes, bytes):
        raise TypeError("cover_bytes must be bytes")

    # PNG files start with this 8-byte signature.
    png_signature = b"\x89PNG\r\n\x1a\n"

    if cover_bytes.startswith(png_signature):
        return "image"

    # Standard WAV files use a RIFF container:
    # bytes 0-3  = RIFF
    # bytes 8-11 = WAVE
    if (
        len(cover_bytes) >= 12
        and cover_bytes[0:4] == b"RIFF"
        and cover_bytes[8:12] == b"WAVE"
    ):
        return "audio"

    raise ValueError(
        "Unsupported media format. Expected PNG image or WAV audio."
    )


# ============================================================
# FR3 - PAYLOAD GENERATION
# ============================================================

def create_payload(
    cover_bytes: bytes,
    team_id: str,
    sender: str,
    custom_metadata: dict[str, object] | None = None,
) -> bytes:
    """
    Create a compact verification payload.

    FR3 required fields:
    - media_id
    - timestamp
    - media_hash
    - nonce
    - team-defined metadata

    Additional field:
    - media_type, automatically detected as "image" or "audio"

    The returned payload is UTF-8 encoded compact JSON bytes.
    """

    if not isinstance(cover_bytes, bytes):
        raise TypeError("cover_bytes must be bytes")

    if not isinstance(team_id, str):
        raise TypeError("team_id must be a string")

    if not isinstance(sender, str):
        raise TypeError("sender must be a string")

    if custom_metadata is not None and not isinstance(custom_metadata, dict):
        raise TypeError("custom_metadata must be a dictionary")

    team_id = team_id.strip()
    sender = sender.strip()

    if not team_id:
        raise ValueError("team_id cannot be empty")

    if not sender:
        raise ValueError("sender cannot be empty")

    media_type = detect_media_type(cover_bytes)
    media_hash = hashlib.sha256(cover_bytes).hexdigest()
    return create_payload_from_hash(
        media_type,
        media_hash,
        team_id,
        sender,
        custom_metadata,
    )


def create_payload_from_hash(
    media_type: str,
    media_hash: str,
    team_id: str,
    sender: str,
    custom_metadata: dict[str, object] | None = None,
) -> bytes:
    """Build canonical payload bytes from an already-computed SHA-256 hash.

    Args:
        media_type: ``"image"`` or ``"audio"`` from validated cover media.
        media_hash: Lowercase hexadecimal SHA-256 digest of the original cover.
        team_id: Team-defined identifier stored in signed metadata.
        sender: Sender name stored in signed metadata.
        custom_metadata: Optional JSON-compatible metadata fields.

    Returns:
        Compact, canonical UTF-8 JSON bytes ready for signing.
    """
    if media_type not in MEDIA_PREFIXES:
        raise ValueError("media_type must be 'image' or 'audio'")
    if not isinstance(media_hash, str):
        raise TypeError("media_hash must be a string")
    if len(media_hash) != 64:
        raise ValueError("media_hash must be a SHA-256 hexadecimal digest")
    try:
        bytes.fromhex(media_hash)
    except ValueError as error:
        raise ValueError("media_hash must be a SHA-256 hexadecimal digest") from error
    if not isinstance(team_id, str):
        raise TypeError("team_id must be a string")
    if not isinstance(sender, str):
        raise TypeError("sender must be a string")
    if custom_metadata is not None and not isinstance(custom_metadata, dict):
        raise TypeError("custom_metadata must be a dictionary")

    team_id = team_id.strip()
    sender = sender.strip()
    if not team_id:
        raise ValueError("team_id cannot be empty")
    if not sender:
        raise ValueError("sender cannot be empty")

    # Auto-generate a media ID.
    # Example: IMG-a3f92c10 or AUD-51bc1234
    prefix = MEDIA_PREFIXES[media_type]
    media_id = f"{prefix}-{secrets.token_hex(4)}"

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    # 16 random bytes = 128-bit nonce.
    nonce = secrets.token_hex(16)

    # Required team metadata is always present.  Additional team-defined
    # fields are copied into the signed metadata object without allowing them
    # to replace the protocol-owned identity fields.
    metadata = {
        "team_id": team_id,
        "sender": sender,
    }
    if custom_metadata:
        reserved = set(metadata).intersection(custom_metadata)
        if reserved:
            names = ", ".join(sorted(reserved))
            raise ValueError(f"custom_metadata cannot replace reserved fields: {names}")
        metadata.update(custom_metadata)

    payload = {
        "media_id": media_id,
        "media_type": media_type,
        "timestamp": timestamp,
        "media_hash": media_hash,
        "nonce": nonce,
        "metadata": metadata,
    }

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def decode_payload(payload_bytes: bytes) -> dict:

    if not isinstance(payload_bytes, bytes):
        raise TypeError("payload_bytes must be bytes")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))

    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Payload is not valid JSON") from error

    if not isinstance(payload, dict):
        raise ValueError("Payload must contain a JSON object")

    return payload


# ============================================================
# FR4 - RSA KEY GENERATION
# ============================================================

def generate_rsa_keypair(
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA-2048 private/public key pair.

    Private key -> signing
    Public key  -> verification
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    return private_key, private_key.public_key()


def _get_pss_padding() -> padding.PSS:
    """
    Return the RSA-PSS padding configuration used by both
    signing and verification.
    """

    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


# ============================================================
# FR4 - SIGN AND VERIFY
# ============================================================

def sign_payload(
    payload_bytes: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    """
    Digitally sign the exact FR3 payload bytes.

    Algorithm:
    - RSA-2048
    - RSA-PSS padding
    - SHA-256
    """

    if not isinstance(payload_bytes, bytes):
        raise TypeError("payload_bytes must be bytes")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError(
            "private_key must be an RSA private key"
        )

    return private_key.sign(
        payload_bytes,
        _get_pss_padding(),
        hashes.SHA256(),
    )


def verify_signature(
    payload_bytes: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey,
) -> bool:
    """
    Verify the digital signature using the corresponding
    RSA public key.

    Returns:
        True  -> signature valid
        False -> signature invalid
    """

    if not isinstance(payload_bytes, bytes):
        raise TypeError("payload_bytes must be bytes")

    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError(
            "public_key must be an RSA public key"
        )

    try:
        public_key.verify(
            signature,
            payload_bytes,
            _get_pss_padding(),
            hashes.SHA256(),
        )

        return True

    except InvalidSignature:
        return False


# ============================================================
# INTEGRATION - PACKET BUILDING
# ============================================================

def build_verification_packet(
    payload_bytes: bytes,
    signature: bytes,
) -> bytes:
    """
    Combine payload and signature into one byte packet.

    Format:
        4-byte big-endian payload length
        + payload bytes
        + RSA signature

    For RSA-2048, the signature is 256 bytes.
    """

    if not isinstance(payload_bytes, bytes):
        raise TypeError("payload_bytes must be bytes")

    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")

    header = struct.pack(
        ">I",
        len(payload_bytes),
    )

    return header + payload_bytes + signature


def unpack_verification_packet(
    raw_packet: bytes,
    public_key: rsa.RSAPublicKey,
) -> tuple[bytes, bytes]:
    """
    Extract payload bytes and signature bytes from a packet.

    Extra trailing bytes are ignored because steganography
    extraction may return a larger buffer.
    """

    if not isinstance(raw_packet, bytes):
        raise TypeError("raw_packet must be bytes")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError(
            "public_key must be an RSA public key"
        )

    signature_length = (
        public_key.key_size + 7
    ) // 8

    minimum_size = 4 + signature_length

    if len(raw_packet) < minimum_size:
        raise ValueError(
            "Payload missing or incomplete"
        )

    payload_length = struct.unpack(
        ">I",
        raw_packet[:4],
    )[0]

    payload_start = 4
    payload_end = (
        payload_start + payload_length
    )

    signature_end = (
        payload_end + signature_length
    )

    if len(raw_packet) < signature_end:
        raise ValueError(
            "Payload missing or corrupted"
        )

    payload_bytes = raw_packet[
        payload_start:payload_end
    ]

    signature = raw_packet[
        payload_end:signature_end
    ]

    return payload_bytes, signature


def verify_verification_packet(
    raw_packet: bytes,
    public_key: rsa.RSAPublicKey,
) -> tuple[bool, str, dict | None]:
    """
    Verify a complete payload/signature packet.

    Performs:
    1. packet extraction
    2. FR4 signature verification
    3. payload JSON decoding

    This function intentionally does NOT perform FR9
    media-hash verification.
    """

    try:
        payload_bytes, signature = (
            unpack_verification_packet(
                raw_packet,
                public_key,
            )
        )

    except ValueError as error:
        return False, str(error), None

    if not verify_signature(
        payload_bytes,
        signature,
        public_key,
    ):
        return (
            False,
            "Signature Invalid",
            None,
        )

    try:
        payload = decode_payload(
            payload_bytes
        )

    except ValueError:
        return (
            False,
            "Payload Missing or Corrupted",
            None,
        )

    return (
        True,
        "Signature Valid",
        payload,
    )


# ============================================================
# FR4 - KEY EXPORT / IMPORT
# ============================================================

def export_private_key_pem(
    private_key: rsa.RSAPrivateKey,
    password: str,
) -> bytes:
    """
    Export an RSA private key as password-encrypted PEM bytes.
    """

    if not isinstance(
        private_key,
        rsa.RSAPrivateKey,
    ):
        raise TypeError(
            "Expected an RSA private key"
        )

    if not isinstance(password, str):
        raise TypeError(
            "password must be a string"
        )

    if not password:
        raise ValueError(
            "password cannot be empty"
        )

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,

        format=serialization.PrivateFormat.PKCS8,

        encryption_algorithm=(
            serialization.BestAvailableEncryption(
                password.encode("utf-8")
            )
        ),
    )


def export_public_key_pem(
    public_key: rsa.RSAPublicKey,
) -> bytes:
    """
    Export an RSA public key as PEM bytes.
    """

    if not isinstance(
        public_key,
        rsa.RSAPublicKey,
    ):
        raise TypeError(
            "Expected an RSA public key"
        )

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,

        format=(
            serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )


def load_private_key_pem(
    pem_bytes: bytes,
    password: str,
) -> rsa.RSAPrivateKey:
    """
    Load a password-encrypted RSA private key from PEM bytes.
    """

    if not isinstance(pem_bytes, bytes):
        raise TypeError(
            "pem_bytes must be bytes"
        )

    if not isinstance(password, str):
        raise TypeError(
            "password must be a string"
        )

    key = serialization.load_pem_private_key(
        pem_bytes,
        password=password.encode("utf-8"),
    )

    if not isinstance(
        key,
        rsa.RSAPrivateKey,
    ):
        raise TypeError(
            "Expected an RSA private key"
        )

    return key


def load_public_key_pem(
    pem_bytes: bytes,
) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from PEM bytes.
    """

    if not isinstance(pem_bytes, bytes):
        raise TypeError(
            "pem_bytes must be bytes"
        )

    key = serialization.load_pem_public_key(
        pem_bytes
    )

    if not isinstance(
        key,
        rsa.RSAPublicKey,
    ):
        raise TypeError(
            "Expected an RSA public key"
        )

    return key
