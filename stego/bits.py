"""Check values and read or write LSB bits in carrier units."""

import numpy as np

from .constants import MAX_PAYLOAD_LENGTH, SUPPORTED_LSB_COUNTS, SUPPORTED_MEDIA_CODES


def _validate_non_negative_integer(value, name):
    """Check that value is a whole number that is zero or more, and return it as an int."""
    if not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} must be an integer")
    value = int(value)
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _validate_positive_integer(value, name):
    """Check that value is a whole number above zero, and return it as an int."""
    value = _validate_non_negative_integer(value, name)
    if value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _validate_lsb_count(lsb_count):
    """Check the LSB count is a whole number from 1 to 8, and hand it back as an int."""
    if not isinstance(lsb_count, (int, np.integer)):
        raise TypeError("lsb_count must be an integer")
    lsb_count = int(lsb_count)
    if lsb_count not in SUPPORTED_LSB_COUNTS:
        raise ValueError("lsb_count must be between 1 and 8")
    return lsb_count


def _validate_media_code(media_code):
    """Check the media code is supported, and return it as an int."""
    if not isinstance(media_code, (int, np.integer)):
        raise TypeError("media_code must be an integer")
    media_code = int(media_code)
    if media_code not in SUPPORTED_MEDIA_CODES:
        raise ValueError("unsupported media code")
    return media_code


def _require_bytes(value, name):
    """Check that value is bytes, and return it unchanged."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def _validate_carrier_units(carrier_units):
    """Check that carrier_units is a one-dimensional NumPy array of 8-bit carrier units."""
    if not isinstance(carrier_units, np.ndarray):
        raise TypeError("carrier_units must be a numpy array")
    if carrier_units.dtype != np.uint8:
        raise TypeError("carrier_units must have dtype uint8")
    if carrier_units.ndim != 1:
        raise ValueError("carrier_units must be one-dimensional")
    return carrier_units


def _validate_bit_sequence(bit_sequence, byte_aligned=False):
    """Check that bit_sequence is a one-dimensional array of zero and one values, with optional byte alignment."""
    if not isinstance(bit_sequence, np.ndarray):
        raise TypeError("bit_sequence must be a numpy array")
    if bit_sequence.dtype != np.uint8:
        raise TypeError("bit_sequence must have dtype uint8")
    if bit_sequence.ndim != 1:
        raise ValueError("bit_sequence must be one-dimensional")
    if not np.all((bit_sequence == 0) | (bit_sequence == 1)):
        raise ValueError("bit_sequence may contain only zero and one")
    if byte_aligned and bit_sequence.size % 8:
        raise ValueError("bit_sequence length must be byte-aligned")
    return bit_sequence


def bytes_to_bit_sequence(data):
    """Turn bytes into a NumPy sequence of bits, in big-endian order."""
    data = _require_bytes(data, "data")
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big").astype(np.uint8, copy=True)


def bit_sequence_to_bytes(bit_sequence):
    """Turn a byte-aligned sequence of bits back into bytes."""
    _validate_bit_sequence(bit_sequence, byte_aligned=True)
    return np.packbits(bit_sequence, bitorder="big").tobytes()


def write_lsb_bits(carrier_units, bit_sequence, lsb_count):
    """Put the bits into the low bits of the carrier units without changing anything else."""
    carrier_units = _validate_carrier_units(carrier_units)
    bit_sequence = _validate_bit_sequence(bit_sequence)
    lsb_count = _validate_lsb_count(lsb_count)
    if bit_sequence.size > carrier_units.size * lsb_count:
        raise ValueError("bit_sequence exceeds carrier capacity")
    result = carrier_units.copy()
    for bit_index, bit in enumerate(bit_sequence):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        mask = 1 << position
        result[unit_index] = np.uint8((int(result[unit_index]) & ~mask) | (int(bit) << position))
    return result


def read_lsb_bits(carrier_units, bit_length, lsb_count):
    """Read the requested number of low-order bits from the carrier units."""
    carrier_units = _validate_carrier_units(carrier_units)
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    if bit_length > carrier_units.size * lsb_count:
        raise ValueError("requested bit length exceeds carrier capacity")
    result = np.empty(bit_length, dtype=np.uint8)
    for bit_index in range(bit_length):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        result[bit_index] = (int(carrier_units[unit_index]) >> position) & 1
    return result


def validate_payload_length(payload_length):
    """Check the payload length is within the 16 MiB limit, and return it as an int."""
    payload_length = _validate_non_negative_integer(payload_length, "payload_length")
    if payload_length > MAX_PAYLOAD_LENGTH:
        raise ValueError("payload exceeds the 16 MiB payload limit")
    return payload_length


def validate_payload_bytes(payload_bytes):
    """Check the payload bytes are within the 16 MiB limit, and return a bytes copy."""
    payload_bytes = _require_bytes(payload_bytes, "payload_bytes")
    validate_payload_length(len(payload_bytes))
    return bytes(payload_bytes)
