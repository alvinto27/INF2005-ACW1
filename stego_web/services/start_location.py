"""Strategies for deterministic, secret-dependent embedding locations."""

from __future__ import annotations

import hashlib
import hmac
from abc import ABC, abstractmethod


class StartLocationStrategy(ABC):
    """Interface that keeps location selection independent of media engines."""

    @abstractmethod
    def derive(
        self,
        secret: str,
        media_type: str,
        slot_count: int,
        lsb_bits: int,
    ) -> int:
        """Return the first carrier slot for embedding or extraction."""


class HmacStartLocation(StartLocationStrategy):
    """Derive a reproducible non-zero location from a shared passphrase."""

    _SALT = b"INF2005-ACW1/start-location/v1"
    _ROUNDS = 120_000

    def derive(
        self,
        secret: str,
        media_type: str,
        slot_count: int,
        lsb_bits: int,
    ) -> int:
        if not isinstance(secret, str) or len(secret) < 8:
            raise ValueError("start secret must contain at least 8 characters")
        if slot_count < 2:
            raise ValueError("carrier does not contain enough embedding slots")
        if lsb_bits not in range(1, 9):
            raise ValueError("lsb_bits must be between 1 and 8")

        key = hashlib.pbkdf2_hmac(
            "sha256",
            secret.encode("utf-8"),
            self._SALT,
            self._ROUNDS,
        )
        # LSB depth is validated but deliberately excluded from the location
        # context, allowing the seven-step controller to derive the location
        # before the embedding-depth choice is applied.
        context = f"{media_type}|{slot_count}".encode("ascii")
        digest = hmac.new(key, context, hashlib.sha256).digest()
        return 1 + int.from_bytes(digest[:8], "big") % (slot_count - 1)
