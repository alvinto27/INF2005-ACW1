"""Provide RSA-PSS, RSA-OAEP, and AES-GCM primitives plus key fingerprints and PEM files."""

import base64
import hashlib
from os import PathLike

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .bits import _require_bytes
from .constants import (
    FINGERPRINT_DISPLAY_PREFIX,
    RSA_KEY_SIZE,
    RSA_PSS_SALT_LENGTH,
    RSA_PUBLIC_EXPONENT,
    RSA_SIGNATURE_SIZE,
)


def validate_rsa_public_key(public_key: rsa.RSAPublicKey) -> rsa.RSAPublicKey:
    """Check that the key is an RSA-2048 public key with the expected exponent."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")
    if public_key.key_size != RSA_KEY_SIZE:
        raise ValueError("public_key must be RSA-2048")
    if public_key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("public_key exponent must be 65537")
    return public_key


def validate_rsa_private_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPrivateKey:
    """Check that the key is an RSA-2048 private key with the expected exponent."""
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")
    if private_key.key_size != RSA_KEY_SIZE:
        raise ValueError("private_key must be RSA-2048")
    if private_key.private_numbers().public_numbers.e != RSA_PUBLIC_EXPONENT:
        raise ValueError("private_key exponent must be 65537")
    return private_key


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA-2048 private key and its matching public key."""
    private_key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def serialize_rsa_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Turn an RSA public key into DER bytes for storage or hashing."""
    public_key = validate_rsa_public_key(public_key)
    encoded = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return encoded


def fingerprint_rsa_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Return the SHA-256 fingerprint of an RSA public key's DER bytes."""
    return hashlib.sha256(serialize_rsa_public_key(public_key)).digest()


def display_rsa_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Return a readable SHA-256 fingerprint for an RSA public key."""
    encoded = base64.b64encode(fingerprint_rsa_public_key(public_key)).decode("ascii").rstrip("=")
    return FINGERPRINT_DISPLAY_PREFIX + encoded


def rsa_oaep_padding() -> padding.OAEP:
    """Make RSA-OAEP padding with SHA-256 for encryption and MGF1."""
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_pss_padding() -> padding.PSS:
    """Make the RSA-PSS padding used by this protocol."""
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=RSA_PSS_SALT_LENGTH)


def seal_to_public_key(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt plaintext with RSA-OAEP to an RSA public key."""
    plaintext = _require_bytes(plaintext, "plaintext")
    return validate_rsa_public_key(public_key).encrypt(plaintext, rsa_oaep_padding())


def open_with_private_key(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt RSA-OAEP ciphertext with an RSA private key."""
    ciphertext = _require_bytes(ciphertext, "ciphertext")
    return validate_rsa_private_key(private_key).decrypt(ciphertext, rsa_oaep_padding())


def _validate_aead_key(key: bytes) -> bytes:
    """Check that an AES-GCM key has exactly 32 bytes."""
    key = _require_bytes(key, "key")
    if len(key) != 32:
        raise ValueError("key must contain exactly 32 bytes")
    return key


def _validate_aead_nonce(nonce: bytes) -> bytes:
    """Check that an AES-GCM nonce has exactly 12 bytes."""
    nonce = _require_bytes(nonce, "nonce")
    if len(nonce) != 12:
        raise ValueError("nonce must contain exactly 12 bytes")
    return nonce


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-GCM and return ciphertext with its tag."""
    key = _validate_aead_key(key)
    nonce = _validate_aead_nonce(nonce)
    aad = _require_bytes(aad, "aad")
    plaintext = _require_bytes(plaintext, "plaintext")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate AES-GCM ciphertext."""
    key = _validate_aead_key(key)
    nonce = _validate_aead_nonce(nonce)
    aad = _require_bytes(aad, "aad")
    ciphertext = _require_bytes(ciphertext, "ciphertext")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def _sign_digest(digest: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign a SHA-256 digest with the protocol RSA-PSS parameters."""
    digest = _require_bytes(digest, "digest")
    if len(digest) != hashes.SHA256.digest_size:
        raise ValueError("digest must contain exactly 32 bytes")
    signature = validate_rsa_private_key(private_key).sign(
        digest, rsa_pss_padding(), utils.Prehashed(hashes.SHA256())
    )
    if len(signature) != RSA_SIGNATURE_SIZE:
        raise ValueError("RSA signature has an unexpected length")
    return signature


def _verify_digest(
    digest: bytes, signature: bytes, public_key: rsa.RSAPublicKey
) -> bool:
    """Check a precomputed SHA-256 digest with the protocol RSA-PSS parameters."""
    digest = _require_bytes(digest, "digest")
    signature = _require_bytes(signature, "signature")
    public_key = validate_rsa_public_key(public_key)
    if len(digest) != hashes.SHA256.digest_size or len(signature) != RSA_SIGNATURE_SIZE:
        return False
    try:
        public_key.verify(
            signature,
            digest,
            rsa_pss_padding(),
            utils.Prehashed(hashes.SHA256()),
        )
    except InvalidSignature:
        return False
    return True


def sign_bytes(signing_input: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign bytes with RSA-PSS and return the fixed-size signature bytes."""
    signing_input = _require_bytes(signing_input, "signing_input")
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(signing_input)
    return _sign_digest(hasher.finalize(), private_key)


def verify_signature(signing_input: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Check an RSA-PSS signature and return whether it is valid."""
    signing_input = _require_bytes(signing_input, "signing_input")
    signature = _require_bytes(signature, "signature")
    public_key = validate_rsa_public_key(public_key)
    if len(signature) != RSA_SIGNATURE_SIZE:
        return False
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(signing_input)
    return _verify_digest(hasher.finalize(), signature, public_key)


def save_rsa_private_key_pem(private_key: rsa.RSAPrivateKey, path: str | bytes | PathLike[str], password: bytes | None = None) -> None:
    """Save an RSA private key as an optionally encrypted PEM file."""
    private_key = validate_rsa_private_key(private_key)
    algorithm = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    with open(path, "wb") as key_file:
        key_file.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm))


def load_rsa_private_key_pem(path: str | bytes | PathLike[str], password: bytes | None = None) -> rsa.RSAPrivateKey:
    """Load and check an RSA private key from a PEM file."""
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=password)
    return validate_rsa_private_key(private_key)


def save_rsa_public_key_pem(public_key: rsa.RSAPublicKey, path: str | bytes | PathLike[str]) -> None:
    """Save an RSA public key as a PEM file."""
    public_key = validate_rsa_public_key(public_key)
    with open(path, "wb") as key_file:
        key_file.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_rsa_public_key_pem(path: str | bytes | PathLike[str]) -> rsa.RSAPublicKey:
    """Load and check an RSA public key from a PEM file."""
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return validate_rsa_public_key(public_key)
