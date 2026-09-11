"""OOP adapter around the repository's existing signed-payload protocol."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from payload_protocol import (
    build_verification_packet,
    create_payload,
    decode_payload,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    load_public_key_pem,
    sign_payload,
    verify_verification_packet,
)

from stego_web.models import VerificationResult, Verdict


@dataclass(frozen=True)
class SignedPacket:
    packet: bytes
    payload: dict
    private_key_pem: bytes
    public_key_pem: bytes


class CryptographyService:
    """Create signed packets and turn protocol results into strict verdicts."""

    def create_signed_packet(
        self,
        cover_bytes: bytes,
        team_id: str,
        sender: str,
        key_password: str,
    ) -> SignedPacket:
        if len(key_password) < 8:
            raise ValueError("key password must contain at least 8 characters")

        private_key, public_key = generate_rsa_keypair()
        payload_bytes = create_payload(cover_bytes, team_id, sender)
        signature = sign_payload(payload_bytes, private_key)

        return SignedPacket(
            packet=build_verification_packet(payload_bytes, signature),
            payload=decode_payload(payload_bytes),
            private_key_pem=export_private_key_pem(private_key, key_password),
            public_key_pem=export_public_key_pem(public_key),
        )

    def verify_signed_packet(
        self,
        packet: bytes,
        public_key_pem: bytes,
        original_cover: bytes | None = None,
    ) -> VerificationResult:
        try:
            public_key = load_public_key_pem(public_key_pem)
        except (TypeError, ValueError) as error:
            return VerificationResult(
                Verdict.CANNOT_VERIFY,
                f"The public key could not be loaded: {error}",
            )

        valid, message, payload = verify_verification_packet(packet, public_key)
        if not valid:
            verdict = (
                Verdict.SIGNATURE_INVALID
                if message == "Signature Invalid"
                else Verdict.PAYLOAD_MISSING
            )
            return VerificationResult(verdict, message)

        if original_cover is None:
            return VerificationResult(
                Verdict.CANNOT_VERIFY,
                "The signature is valid, but the original cover is required for media-hash verification.",
                payload,
                signature_valid=True,
            )

        actual_hash = hashlib.sha256(original_cover).hexdigest()
        expected_hash = payload.get("media_hash") if payload else None
        if not isinstance(expected_hash, str) or not hmac_safe_equal(actual_hash, expected_hash):
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


def hmac_safe_equal(left: str, right: str) -> bool:
    """Compare fixed-format hashes without data-dependent early exit."""
    import hmac

    return hmac.compare_digest(left, right)
