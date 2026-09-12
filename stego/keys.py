"""RSA-PSS operations, fingerprints, and PEM helpers."""

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .bits import _require_bytes
from .constants import (
    FINGERPRINT_DISPLAY_PREFIX,
    RSA_KEY_SIZE,
    RSA_PSS_SALT_LENGTH,
    RSA_PUBLIC_EXPONENT,
    RSA_SIGNATURE_SIZE,
)


def validate_rsa_public_key(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")
    if public_key.key_size != RSA_KEY_SIZE:
        raise ValueError("public_key must be RSA-2048")
    if public_key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("public_key exponent must be 65537")
    return public_key


def validate_rsa_private_key(private_key):
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")
    if private_key.key_size != RSA_KEY_SIZE:
        raise ValueError("private_key must be RSA-2048")
    if private_key.private_numbers().public_numbers.e != RSA_PUBLIC_EXPONENT:
        raise ValueError("private_key exponent must be 65537")
    return private_key


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def serialize_rsa_public_key(public_key):
    public_key = validate_rsa_public_key(public_key)
    encoded = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return encoded


def fingerprint_rsa_public_key(public_key):
    return hashlib.sha256(serialize_rsa_public_key(public_key)).digest()


def display_rsa_public_key_fingerprint(public_key):
    encoded = base64.b64encode(fingerprint_rsa_public_key(public_key)).decode("ascii").rstrip("=")
    return FINGERPRINT_DISPLAY_PREFIX + encoded


def rsa_pss_padding():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=RSA_PSS_SALT_LENGTH)


def sign_bytes(signing_input, private_key):
    signing_input = _require_bytes(signing_input, "signing_input")
    signature = validate_rsa_private_key(private_key).sign(signing_input, rsa_pss_padding(), hashes.SHA256())
    if len(signature) != RSA_SIGNATURE_SIZE:
        raise ValueError("RSA signature has an unexpected length")
    return signature


def verify_signature(signing_input, signature, public_key):
    signing_input = _require_bytes(signing_input, "signing_input")
    signature = _require_bytes(signature, "signature")
    public_key = validate_rsa_public_key(public_key)
    if len(signature) != RSA_SIGNATURE_SIZE:
        return False
    try:
        public_key.verify(signature, signing_input, rsa_pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def save_rsa_private_key_pem(private_key, path, password=None):
    private_key = validate_rsa_private_key(private_key)
    algorithm = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    with open(path, "wb") as key_file:
        key_file.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm))


def load_rsa_private_key_pem(path, password=None):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=password)
    return validate_rsa_private_key(private_key)


def save_rsa_public_key_pem(public_key, path):
    public_key = validate_rsa_public_key(public_key)
    with open(path, "wb") as key_file:
        key_file.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_rsa_public_key_pem(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return validate_rsa_public_key(public_key)
