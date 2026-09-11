"""OOP facade over the repository's signed payload protocol."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization

from payload_protocol import (
    build_verification_packet,
    create_payload,
    generate_rsa_keypair,
    sign_payload,
    verify_verification_packet,
)


class CryptographyService:
    """Create and verify packets; replace key storage before production use."""

    def __init__(self):
        self.private_key, self.public_key = generate_rsa_keypair()

    def create_packet(self, cover_bytes: bytes, team_id: str, sender: str) -> tuple[bytes, bytes]:
        payload = create_payload(cover_bytes, team_id, sender)
        return payload, build_verification_packet(payload, sign_payload(payload, self.private_key))

    def verify_packet(self, packet: bytes) -> tuple[bool, str, dict | None]:
        return verify_verification_packet(packet, self.public_key)

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
