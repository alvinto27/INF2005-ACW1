"""Give the protocol bounded, seekable access to logical carrier units.

A carrier backend owns storage. It knows how many 8-bit carrier units a medium
holds, reads a bounded range of them, and yields them in fixed order as chunks.
It holds no payload, cryptography, or protocol policy. The protocol core in
``core.py`` decides which units change; a backend only supplies and rewrites them.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator

import numpy as np

from .bits import (
    _validate_bit_sequence,
    _validate_carrier_units,
    _validate_lsb_count,
    _validate_non_negative_integer,
    _validate_positive_integer,
    write_lsb_bits,
)

# Target size of one working chunk of physical carrier data, in bytes.
#
# Reason for 1 MiB:
# - Memory: one pass holds a small, fixed number of chunk-sized buffers (the raw
#   read, the extracted units, one masked or embedded copy, and the output
#   buffer), so the carrier working set stays at a few MiB for any carrier size.
# - Throughput: SHA-256 and NumPy work dominate each chunk. Smaller chunks pay
#   more fixed per-chunk Python cost; larger chunks fall out of CPU cache. On a
#   96 MiB WAV the hash pass was fastest at 1 MiB, with a traced peak of about
#   2.6 MiB. See AGENT_docs/CARRIER-AND-PAYLOAD-FLOW.md for the measurement.
# - WAV alignment: a PCM frame is at most 65,535 channels x 4 bytes, which is
#   below 1 MiB, so every chunk holds at least one complete frame.
DEFAULT_CHUNK_BYTES = 1024 * 1024

class CarrierAccessError(ValueError):
    """A carrier backend could not supply the requested carrier units."""


class _PackedByteRangeReader(ABC):
    """Supply packed bytes by bounded ranges to an LSB transform."""

    @property
    @abstractmethod
    def size(self) -> int:
        """Return the number of available bytes."""

    @abstractmethod
    def read_range(self, offset: int, length: int) -> bytes:
        """Return a bounded byte range."""


def _packed_lsb_range_transform(
    region_start: int,
    data: bytes | _PackedByteRangeReader,
    bit_length: int,
    lsb_count: int,
) -> Callable[[int, np.ndarray], np.ndarray]:
    """Return a chunk transform backed by packed bytes.

    The first ``min(bit_length, len(data) * 8)`` bits come from ``data`` in
    big-endian order. Missing trailing bits are zero. This lets a packet writer
    include alignment padding without allocating a bit array for the packet.
    """
    region_start = _validate_non_negative_integer(region_start, "region_start")
    if isinstance(data, bytes):
        data_size = len(data)
        read_range = lambda offset, length: data[offset:offset + length]
    elif isinstance(data, _PackedByteRangeReader):
        data_size = data.size
        read_range = data.read_range
    else:
        raise TypeError("data must be bytes or a packed byte range reader")
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    region_end = region_start + (bit_length + lsb_count - 1) // lsb_count
    data_bit_length = data_size * 8

    def transform(chunk_start: int, units: np.ndarray) -> np.ndarray:
        """Unpack only the packed data bits that overlap this chunk."""
        units = _validate_carrier_units(units)
        chunk_start = _validate_non_negative_integer(chunk_start, "chunk_start")
        local = overlap_range(
            chunk_start, chunk_start + units.size, region_start, region_end
        )
        if local is None:
            return units

        first_unit = chunk_start + local[0] - region_start
        bit_start = first_unit * lsb_count
        bit_end = min(
            bit_length,
            bit_start + (local[1] - local[0]) * lsb_count,
        )
        write_length = bit_end - bit_start
        result = units.copy()
        if lsb_count == 8 and write_length % 8 == 0:
            field_start = local[0]
            field_count = write_length // 8
            first_data_byte = bit_start // 8
            available_bytes = max(
                0, min(field_count, data_size - first_data_byte)
            )
            if available_bytes > 0:
                packed_bytes = read_range(first_data_byte, available_bytes)
                result[field_start:field_start + available_bytes] = np.frombuffer(
                    packed_bytes, dtype=np.uint8
                )
            if available_bytes < field_count:
                result[field_start + available_bytes:field_start + field_count] = 0
            return result

        bits = np.zeros(write_length, dtype=np.uint8)
        available = min(write_length, data_bit_length - bit_start)
        if available > 0:
            first_byte = bit_start // 8
            last_byte = (bit_start + available + 7) // 8
            packed = np.frombuffer(
                read_range(first_byte, last_byte - first_byte), dtype=np.uint8
            )
            unpacked = np.unpackbits(packed, bitorder="big")
            bit_offset = bit_start % 8
            bits[:available] = unpacked[bit_offset:bit_offset + available]

        result[local[0]:local[1]] = write_lsb_bits(
            result[local[0]:local[1]], bits, lsb_count
        )
        return result

    return transform


def lsb_range_transform(region_start: int, bit_sequence: np.ndarray, lsb_count: int) -> Callable[[int, np.ndarray], np.ndarray]:
    """Return a chunk transform that writes bits at a global carrier-unit range.

    ``bit_sequence`` starts at ``region_start`` and is written into the low
    ``lsb_count`` bits of each unit. Chunks may begin or end inside that range;
    their boundaries do not change the resulting carrier units.
    """
    region_start = _validate_non_negative_integer(region_start, "region_start")
    bit_sequence = _validate_bit_sequence(bit_sequence).copy()
    lsb_count = _validate_lsb_count(lsb_count)
    packed_bits = np.packbits(bit_sequence, bitorder="big").tobytes()
    return _packed_lsb_range_transform(
        region_start, packed_bits, int(bit_sequence.size), lsb_count
    )


def overlap_range(chunk_start: int, chunk_end: int, region_start: int, region_end: int) -> tuple[int, int] | None:
    """Return the local [start, end) slice of a chunk that lies inside a global region.

    Both ranges are half-open global unit ranges. The result is relative to
    ``chunk_start``, or ``None`` when the ranges do not overlap.
    """
    overlap_start = max(chunk_start, region_start)
    overlap_end = min(chunk_end, region_end)
    if overlap_start >= overlap_end:
        return None
    return overlap_start - chunk_start, overlap_end - chunk_start


def _validate_unit_range(start_unit: int, count: int, total_units: int) -> tuple[int, int]:
    """Check that [start_unit, start_unit + count) lies inside the carrier."""
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    count = _validate_non_negative_integer(count, "count")
    if start_unit + count > total_units:
        raise CarrierAccessError(
            f"carrier range is out of bounds: start_unit={start_unit}, "
            f"count={count}, total_units={total_units}"
        )
    return start_unit, count


def _validate_transformed_units(units: np.ndarray, expected_size: int) -> np.ndarray:
    """Check that a chunk transform returned the same number of carrier units."""
    units = _validate_carrier_units(units)
    if units.size != expected_size:
        raise ValueError("chunk transform must return the same number of carrier units")
    return units


class CarrierSource(ABC):
    """Read logical carrier units in a fixed order without loading the whole carrier.

    Every backend must return the same unit values for the same unit index from
    ``read_units`` and ``iter_chunks``. Returned arrays are new one-dimensional
    uint8 arrays that the caller may change.
    """

    @property
    @abstractmethod
    def total_units(self) -> int:
        """Return the number of logical carrier units."""

    @property
    def fixed_byte_count(self) -> int:
        """Return the number of fixed media bytes paired with all unit chunks."""
        return 0

    @abstractmethod
    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        """Return ``count`` units starting at ``start_unit``.

        Raise ``CarrierAccessError`` when the range is outside the carrier or
        the storage cannot supply it.
        """

    @abstractmethod
    def iter_chunks(self) -> Iterator[np.ndarray]:
        """Yield every unit once, in order, in bounded chunks.

        Raise ``CarrierAccessError`` when the storage cannot supply every unit.
        """

    def iter_chunks_with_fixed_bytes(self) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield bounded unit chunks with the fixed media bytes from each chunk.

        Array-backed and other media-neutral sources have no fixed bytes. A
        media backend overrides this method and obtains both outputs from the
        same underlying chunk read.
        """
        for units in self.iter_chunks():
            yield units, b""


class ArrayCarrier(CarrierSource):
    """Expose an in-memory one-dimensional uint8 array as a carrier source.

    The array is referenced, not copied. The caller must not change it while
    the carrier is in use.
    """

    def __init__(self, carrier_units: np.ndarray, chunk_units: int = DEFAULT_CHUNK_BYTES) -> None:
        """Wrap ``carrier_units`` and yield chunks of ``chunk_units`` units."""
        self._units = _validate_carrier_units(carrier_units)
        self._chunk_units = _validate_positive_integer(chunk_units, "chunk_units")

    @property
    def total_units(self) -> int:
        """Return the number of units in the wrapped array."""
        return int(self._units.size)

    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        """Return a copy of ``count`` units starting at ``start_unit``."""
        start_unit, count = _validate_unit_range(start_unit, count, self.total_units)
        return self._units[start_unit:start_unit + count].copy()

    def iter_chunks(self) -> Iterator[np.ndarray]:
        """Yield copies of consecutive chunks of the wrapped array."""
        for offset in range(0, self.total_units, self._chunk_units):
            yield self._units[offset:offset + self._chunk_units].copy()

    def rewrite(self, transform: Callable[[int, np.ndarray], np.ndarray]) -> np.ndarray:
        """Pass each chunk through ``transform`` in order and return the new array.

        ``transform`` receives the chunk's first global unit index and its
        original units, and returns the replacement units.
        """
        result = np.empty(self.total_units, dtype=np.uint8)
        offset = 0
        for chunk in self.iter_chunks():
            replaced = _validate_transformed_units(transform(offset, chunk), chunk.size)
            result[offset:offset + chunk.size] = replaced
            offset += chunk.size
        return result
