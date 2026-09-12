"""Cryptographic operations used by encoding and verification pipelines."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from payload_protocol import (
    build_verification_packet,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    sign_payload,
    verify_verification_packet,
)

from stego_web.models import VerificationResult, Verdict


@dataclass(frozen=True)
class SignedPacket:
    """Signed payload packet and its corresponding public key."""

    packet: bytes
    payload: dict
    public_key_pem: bytes


@dataclass(frozen=True)
class GeneratedKeyPair:
    """Password-protected key material created during explicit key setup."""

    private_key_pem: bytes
    public_key_pem: bytes


class CryptoManager:
    """Hash covers, load existing keys, sign payloads, and verify packets."""

    @staticmethod
    def hash_cover(cover_bytes: bytes) -> str:
        """Return the SHA-256 hex digest of the exact original cover bytes."""
        if not isinstance(cover_bytes, bytes):
            raise TypeError("cover_bytes must be bytes")
        return hashlib.sha256(cover_bytes).hexdigest()

    @staticmethod
    def load_signing_key(private_key_pem: bytes, password: str):
        """Load a user-supplied, password-encrypted RSA private key.

        Args:
            private_key_pem: PKCS#8 PEM bytes uploaded for this signing action.
            password: Password used when the private key was exported.

        Returns:
            A validated RSA private-key object.
        """
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("key password must contain at least 8 characters")
        return load_private_key_pem(private_key_pem, password)

    @staticmethod
    def sign_packet(payload_bytes: bytes, payload: dict, private_key) -> SignedPacket:
        """Sign exact payload bytes and package the payload plus signature."""
        signature = sign_payload(payload_bytes, private_key)
        return SignedPacket(
            packet=build_verification_packet(payload_bytes, signature),
            payload=payload,
            public_key_pem=export_public_key_pem(private_key.public_key()),
        )

    @staticmethod
    def generate_key_pair(password: str) -> GeneratedKeyPair:
        """Generate initial local demo keys outside the encoding pipeline."""
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("key password must contain at least 8 characters")
        private_key, public_key = generate_rsa_keypair()
        return GeneratedKeyPair(
            private_key_pem=export_private_key_pem(private_key, password),
            public_key_pem=export_public_key_pem(public_key),
        )

    def verify_signed_packet(
        self,
        packet: bytes,
        public_key_pem: bytes,
        original_cover: bytes | None = None,
    ) -> VerificationResult:
        """Verify packet signature and, when supplied, the original-cover hash."""
        try:
            public_key = load_public_key_pem(public_key_pem)
        except (TypeError, ValueError) as error:
            return VerificationResult(
                Verdict.CANNOT_VERIFY,
                f"The public key could not be loaded: {error}",
            )

        valid, message, payload = verify_verification_packet(packet, public_key)
        if not valid:
            verdict = Verdict.SIGNATURE_INVALID if message == "Signature Invalid" else Verdict.PAYLOAD_MISSING
            return VerificationResult(verdict, message)

        if original_cover is None:
            return VerificationResult(
                Verdict.CANNOT_VERIFY,
                "The signature is valid, but the original cover is required for media-hash verification.",
                payload,
                signature_valid=True,
            )

        actual_hash = self.hash_cover(original_cover)
        expected_hash = payload.get("media_hash") if payload else None
        if not isinstance(expected_hash, str) or not hmac.compare_digest(actual_hash, expected_hash):
            return VerificationResult(
                Verdict.TAMPERED,
                "The signature is valid, but the supplied original cover hash does not match.",
                payload,
                signature_valid=True,
                media_hash_valid=False,
            )

        return VerificationResult(
            Verdict.AUTHENTIC,
            "The signature and original-cover hash are valid.",
            payload,
            signature_valid=True,
            media_hash_valid=True,
        )


class CryptographyService(CryptoManager):
    """Compatibility alias retained for existing imports."""
