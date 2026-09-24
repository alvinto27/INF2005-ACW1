"""Check values and read or write LSB bits in carrier units."""

import numpy as np

from .constants import PROTOCOL_FIELD_WIDTH, SUPPORTED_LSB_COUNTS, SUPPORTED_MEDIA_CODES


def _validate_non_negative_integer(value: int, name: str) -> int:
    """Check that value is a whole number that is zero or more, and return it as an int."""
    if not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} must be an integer")
    value = int(value)
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _validate_protocol_field_value(value: int, name: str) -> int:
    """Check that value fits in a non-negative unsigned protocol field."""
    value = _validate_non_negative_integer(value, name)
    if value >= 1 << (8 * PROTOCOL_FIELD_WIDTH):
        raise ValueError(f"{name} must fit in {PROTOCOL_FIELD_WIDTH} bytes")
    return value


def encode_protocol_field(value: int, name: str) -> bytes:
    """Encode a non-negative protocol integer as a big-endian unsigned u64."""
    value = _validate_protocol_field_value(value, name)
    return value.to_bytes(PROTOCOL_FIELD_WIDTH, "big")


def _validate_positive_integer(value: int, name: str) -> int:
    """Check that value is a whole number above zero, and return it as an int."""
    value = _validate_non_negative_integer(value, name)
    if value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _validate_lsb_count(lsb_count: int) -> int:
    """Check the LSB count is a whole number from 1 to 8, and hand it back as an int."""
    if not isinstance(lsb_count, (int, np.integer)):
        raise TypeError("lsb_count must be an integer")
    lsb_count = int(lsb_count)
    if lsb_count not in SUPPORTED_LSB_COUNTS:
        raise ValueError("lsb_count must be between 1 and 8")
    return lsb_count


def _validate_media_code(media_code: int) -> int:
    """Check the media code is supported, and return it as an int."""
    if not isinstance(media_code, (int, np.integer)):
        raise TypeError("media_code must be an integer")
    media_code = int(media_code)
    if media_code not in SUPPORTED_MEDIA_CODES:
        raise ValueError("unsupported media code")
    return media_code


def _require_bytes(value: bytes, name: str) -> bytes:
    """Check that value is bytes, and return it unchanged."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def _validate_carrier_units(carrier_units: np.ndarray) -> np.ndarray:
    """Check that carrier_units is a one-dimensional NumPy array of 8-bit carrier units."""
    if not isinstance(carrier_units, np.ndarray):
        raise TypeError("carrier_units must be a numpy array")
    if carrier_units.dtype != np.uint8:
        raise TypeError("carrier_units must have dtype uint8")
    if carrier_units.ndim != 1:
        raise ValueError("carrier_units must be one-dimensional")
    return carrier_units


def _validate_bit_sequence(bit_sequence: np.ndarray, byte_aligned: bool = False) -> np.ndarray:
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


def bytes_to_bit_sequence(data: bytes) -> np.ndarray:
    """Turn bytes into a NumPy sequence of bits, in big-endian order."""
    data = _require_bytes(data, "data")
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big").astype(np.uint8, copy=True)


def bit_sequence_to_bytes(bit_sequence: np.ndarray) -> bytes:
    """Turn a byte-aligned sequence of bits back into bytes."""
    _validate_bit_sequence(bit_sequence, byte_aligned=True)
    return np.packbits(bit_sequence, bitorder="big").tobytes()


def write_lsb_bits(carrier_units: np.ndarray, bit_sequence: np.ndarray, lsb_count: int) -> np.ndarray:
    """Put the bits into the low bits of the carrier units without changing anything else."""
    carrier_units = _validate_carrier_units(carrier_units)
    bit_sequence = _validate_bit_sequence(bit_sequence)
    lsb_count = _validate_lsb_count(lsb_count)
    if bit_sequence.size > carrier_units.size * lsb_count:
        raise ValueError("bit_sequence exceeds carrier capacity")
    result = carrier_units.copy()
    bit_count = int(bit_sequence.size)
    unit_count = (bit_count + lsb_count - 1) // lsb_count
    if unit_count == 0:
        return result

    padded_bits = np.zeros(unit_count * lsb_count, dtype=np.uint8)
    padded_bits[:bit_count] = bit_sequence
    shifts = np.arange(lsb_count - 1, -1, -1, dtype=np.uint8)
    grouped_bits = padded_bits.reshape(unit_count, lsb_count)
    encoded_fields = np.bitwise_or.reduce(grouped_bits << shifts, axis=1)

    full_units = bit_count // lsb_count
    field_mask = (1 << lsb_count) - 1
    if full_units:
        result[:full_units] = (
            carrier_units[:full_units] & np.uint8((~field_mask) & 0xFF)
        ) | encoded_fields[:full_units]
    partial_bits = bit_count % lsb_count
    if partial_bits:
        partial_mask = ((1 << partial_bits) - 1) << (lsb_count - partial_bits)
        result[full_units] = np.uint8(
            (int(carrier_units[full_units]) & (~partial_mask & 0xFF))
            | int(encoded_fields[full_units])
        )
    return result


def read_lsb_bits(carrier_units: np.ndarray, bit_length: int, lsb_count: int) -> np.ndarray:
    """Read the requested number of low-order bits from the carrier units."""
    carrier_units = _validate_carrier_units(carrier_units)
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    if bit_length > carrier_units.size * lsb_count:
        raise ValueError("requested bit length exceeds carrier capacity")
    if bit_length == 0:
        return np.empty(0, dtype=np.uint8)
    unit_count = (bit_length + lsb_count - 1) // lsb_count
    shifts = np.arange(lsb_count - 1, -1, -1, dtype=np.uint8)
    low_fields = carrier_units[:unit_count, None] & np.uint8((1 << lsb_count) - 1)
    bits = ((low_fields >> shifts) & np.uint8(1)).reshape(-1)
    return bits[:bit_length].copy()


def validate_payload_length(payload_length: int) -> int:
    """Check that the payload length is non-negative, and return it as an int."""
    return _validate_non_negative_integer(payload_length, "payload_length")


def validate_payload_bytes(payload_bytes: bytes) -> bytes:
    """Check that payload_bytes is bytes, and return a bytes copy."""
    payload_bytes = _require_bytes(payload_bytes, "payload_bytes")
    return bytes(payload_bytes)
