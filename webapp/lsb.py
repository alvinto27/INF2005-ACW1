"""Generic 1–8 bit-per-byte LSB embedding primitives."""

from __future__ import annotations

import numpy as np


def _validate_bits(bits_per_unit: int) -> None:
    if not isinstance(bits_per_unit, int) or not 1 <= bits_per_unit <= 8:
        raise ValueError("bits_per_unit must be an integer from 1 to 8")


def _payload_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def embed_bytes(values: np.ndarray, payload: bytes, start_unit: int, bits_per_unit: int) -> np.ndarray:
    """Embed bytes into a copy of a flat uint8 carrier array."""
    _validate_bits(bits_per_unit)
    if not isinstance(values, np.ndarray) or values.dtype != np.uint8 or values.ndim != 1:
        raise TypeError("values must be a flat uint8 numpy array")
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not isinstance(start_unit, int) or start_unit < 0:
        raise ValueError("start_unit must be a non-negative integer")

    bits = _payload_bits(payload)
    capacity = (values.size - start_unit) * bits_per_unit
    if bits.size > capacity:
        raise ValueError("payload is too large for the carrier capacity")

    result = values.copy()
    mask = (1 << bits_per_unit) - 1
    for unit_index in range(start_unit, values.size):
        offset = (unit_index - start_unit) * bits_per_unit
        if offset >= bits.size:
            break
        chunk = bits[offset:offset + bits_per_unit]
        chunk_value = int("".join(str(int(bit)) for bit in chunk).ljust(bits_per_unit, "0"), 2)
        result[unit_index] = np.uint8((int(result[unit_index]) & ~mask) | chunk_value)
    return result


def extract_bytes(values: np.ndarray, start_unit: int, byte_count: int, bits_per_unit: int) -> bytes:
    """Extract an exact number of bytes from a flat uint8 carrier array."""
    _validate_bits(bits_per_unit)
    if not isinstance(values, np.ndarray) or values.dtype != np.uint8 or values.ndim != 1:
        raise TypeError("values must be a flat uint8 numpy array")
    if not isinstance(byte_count, int) or byte_count < 0:
        raise ValueError("byte_count must be non-negative")
    if not isinstance(start_unit, int) or start_unit < 0:
        raise ValueError("start_unit must be a non-negative integer")

    bit_count = byte_count * 8
    capacity = (values.size - start_unit) * bits_per_unit
    if bit_count > capacity:
        raise ValueError("requested data exceeds carrier capacity")
    mask = (1 << bits_per_unit) - 1
    bits: list[int] = []
    for value in values[start_unit:]:
        bits.extend((int(value) & mask) >> bit for bit in range(bits_per_unit - 1, -1, -1))
        if len(bits) >= bit_count:
            break
    return np.packbits(np.array(bits[:bit_count], dtype=np.uint8)).tobytes()
