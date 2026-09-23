"""Cryptographic operations used by encoding and verification pipelines."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime

from payload_protocol import (
    build_verification_packet,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    sign_payload,
    unpack_verification_packet,
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

        details = {"signature_size": (public_key.key_size + 7) // 8}
        try:
            payload_bytes, _ = unpack_verification_packet(packet, public_key)
            details["payload_size"] = len(payload_bytes)
            if len(packet) != 4 + len(payload_bytes) + details["signature_size"]:
                raise ValueError("Unexpected trailing bytes in the framed packet")
        except (ValueError, struct.error):
            return VerificationResult(
                Verdict.CANNOT_VERIFY, "Invalid payload/signature lengths.", details=details
            )
        valid, message, payload = verify_verification_packet(packet, public_key)
        if not valid:
            invalid_signature = message == "Signature Invalid"
            verdict = Verdict.SIGNATURE_INVALID if invalid_signature else Verdict.CANNOT_VERIFY
            return VerificationResult(verdict, message, signature_valid=not invalid_signature,
                                      details=details)

        try:
            self.validate_payload(payload)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return VerificationResult(
                Verdict.CANNOT_VERIFY, "Signed payload has invalid or missing required fields.",
                signature_valid=True, details=details,
            )
        details["stored_hash"] = payload["media_hash"]

        if original_cover is None:
            return VerificationResult(
                Verdict.CANNOT_VERIFY,
                "The signature is valid, but the original cover is required for media-hash verification.",
                payload,
                signature_valid=True,
                details=details,
            )

        actual_hash = self.hash_cover(original_cover)
        details["computed_hash"] = actual_hash
        expected_hash = payload.get("media_hash") if payload else None
        if not isinstance(expected_hash, str) or not hmac.compare_digest(actual_hash, expected_hash):
            return VerificationResult(
                Verdict.TAMPERED,
                "The signature is valid, but the supplied original cover hash does not match.",
                payload,
                signature_valid=True,
                media_hash_valid=False,
                details=details,
            )

        return VerificationResult(
            Verdict.AUTHENTIC,
            "The signature and original-cover hash are valid.",
            payload,
            signature_valid=True,
            media_hash_valid=True,
            details=details,
        )

    @staticmethod
    def validate_payload(payload: dict) -> None:
        """Validate the existing encoder schema after authenticating its exact bytes."""
        if not isinstance(payload, dict):
            raise ValueError("Payload must be an object")
        media_type = payload.get("media_type")
        if media_type not in ("image", "audio"):
            raise ValueError("Unsupported media type")
        prefix = "IMG" if media_type == "image" else "AUD"
        for name, pattern in (("media_id", prefix + r"-[0-9a-f]{8}"),
                              ("media_hash", r"[0-9a-f]{64}"), ("nonce", r"[0-9a-f]{32}")):
            value = payload.get(name)
            if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
                raise ValueError(f"Invalid {name}")
        timestamp = payload.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("Invalid timestamp")
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("Invalid metadata")
        for name in ("team_id", "sender"):
            if not isinstance(metadata.get(name), str) or not metadata[name].strip():
                raise ValueError(f"Invalid {name}")
        json.dumps(payload, allow_nan=False)


class CryptographyService(CryptoManager):
    """Compatibility alias retained for existing imports."""
