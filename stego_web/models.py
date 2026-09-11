"""Small immutable values shared by the web and service layers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Verdict(StrEnum):
    """Strict verification outcomes required by the assignment."""

    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"


@dataclass(frozen=True)
class EmbeddedMedia:
    media_bytes: bytes
    start_location: int
    capacity_bytes: int


@dataclass(frozen=True)
class ExtractedPacket:
    packet: bytes
    start_location: int


@dataclass(frozen=True)
class VerificationResult:
    verdict: Verdict
    message: str
    payload: dict | None = None
    signature_valid: bool = False
    media_hash_valid: bool | None = None

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "message": self.message,
            "payload": self.payload,
            "signature_valid": self.signature_valid,
            "media_hash_valid": self.media_hash_valid,
        }
