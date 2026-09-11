"""Deterministic, non-default start-location derivation.

The location is not sent as an unauthenticated control value.  Both sides
derive it from the verification public key and stable carrier properties.
The packet's signature still protects the payload after extraction.
"""

from __future__ import annotations

import hashlib
import struct


class StartLocationDeriver:
    """Derive an LSB-unit offset that can be reproduced during decoding."""

    def __init__(self, key_material: bytes):
        if not isinstance(key_material, bytes) or not key_material:
            raise TypeError("key_material must be non-empty bytes")
        self._key_material = key_material

    def derive(self, carrier_units: int, bits_per_unit: int) -> int:
        """Return a non-zero unit index, or raise if the carrier is tiny."""
        if not isinstance(carrier_units, int) or carrier_units < 2:
            raise ValueError("carrier must contain at least two units")
        if not isinstance(bits_per_unit, int) or not 1 <= bits_per_unit <= 8:
            raise ValueError("bits_per_unit must be between 1 and 8")

        digest = hashlib.sha256(
            self._key_material
            + struct.pack(">QQ", carrier_units, bits_per_unit)
        ).digest()
        # Starting at zero makes accidental fixed-location implementations
        # indistinguishable.  Reserve one unit so the result is always > 0.
        return 1 + (int.from_bytes(digest[:8], "big") % (carrier_units - 1))
