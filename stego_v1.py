import base64
import hashlib
import json
import os
import re
import secrets
import struct
import unicodedata
import wave
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike, fspath
from PIL import Image
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import numpy as np




RSA_KEY_SIZE = 2048
PROTOCOL_VERSION = 1
START_MAGIC = bytes.fromhex("d9df721b281169d4335290e30fdb48b1")
SUPPORTED_LSB_COUNTS = tuple(range(1, 9))
HASH_ALGORITHM = "SHA-256"
RSA_ALGORITHM = "RSA-2048"
RSA_SIGNATURE_ALGORITHM = "RSA-PSS"
RSA_MGF_ALGORITHM = "MGF1-SHA-256"
RSA_PSS_SALT_LENGTH = 32
RSA_SIGNATURE_SIZE = RSA_KEY_SIZE // 8
SELECTED_LSB_BIT_ORDER = "MSB-first; selected LSBs from bit k-1 down to bit 0"

MEDIA_PREFIXES = {
    "image": "IMG",
    "audio": "AUD",
}


# Marks a legacy unsupported-file-type error.
class UnSupportedFileType(Exception):
    pass

PNG_CARRIER_MODE = "RGB"
PNG_CARRIER_ORDER = "row-major RGB: top-to-bottom, left-to-right, R, G, B"

RGB_CHANNEL_COUNT = 3

# Validates a decoded RGB uint8 array.
def _validate_rgb_array(image_array):
    """Validate an already-decoded, 8-bit RGB NumPy array."""

    if not isinstance(image_array, np.ndarray):
        raise TypeError("image_array must be a numpy array")
    if image_array.dtype != np.uint8:
        raise TypeError("image_array must have dtype uint8")
    if image_array.ndim != 3 or image_array.shape[2] != RGB_CHANNEL_COUNT:
        raise ValueError("image_array must have shape (height, width, 3)")
    if image_array.shape[0] < 1 or image_array.shape[1] < 1:
        raise ValueError("Image dimensions must be greater than zero")
    return image_array


# Validates the static RGB PNG header.
def _validate_rgb_png_header(image_path):
    """Reject PNGs whose file-level format is not static 8-bit RGB."""

    with open(image_path, "rb") as image_file:
        header = image_file.read(33)

    if (
        len(header) != 33
        or header[:8].hex() != "89504e470d0a1a0a"
        or header[12:16] != b"IHDR"
    ):
        raise ValueError("Invalid PNG header")

    chunk_length = struct.unpack(">I", header[8:12])[0]
    if chunk_length != 13:
        raise ValueError("Invalid PNG IHDR chunk")

    _, _, _, _, bit_depth, colour_type, compression, filter_method, _ = struct.unpack(
        ">I4sIIBBBBB", header[8:29]
    )
    if bit_depth != 8 or colour_type != 2:
        raise ValueError("PNG must use 8-bit RGB samples")
    if compression != 0 or filter_method != 0:
        raise ValueError("Unsupported PNG encoding")


# Loads a strict static RGB PNG.
def load_png_from_path(image_path):
    """Load only a static, 8-bit RGB PNG without colour conversion."""


    if not isinstance(image_path, (str, bytes, PathLike)):
        raise TypeError("image_path must be a filesystem path")

    try:
        with Image.open(image_path) as image:
            if image.format != "PNG":
                raise UnSupportedFileType(
                    f"Unsupported file type: {image.format or 'unknown'}"
                )
            if getattr(image, "is_animated", False) or getattr(image, "n_frames", 1) != 1:
                raise ValueError("Animated PNG images are not supported")
            if image.mode != PNG_CARRIER_MODE:
                raise ValueError("PNG must be RGB without alpha or palette conversion")

            _validate_rgb_png_header(image_path)
            image.load()
            image_array = np.array(image, dtype=np.uint8, copy=True)
            return _validate_rgb_array(image_array)

    except UnSupportedFileType:
        raise
    except (OSError, ValueError) as error:
        raise ValueError("Unreadable or unsupported RGB PNG image") from error

# Flattens an RGB array into copied carrier units.
def rgb_array_to_carrier(image_array):
    _validate_rgb_array(image_array)
    return np.array(image_array, dtype=np.uint8, order="C", copy=True).reshape(-1).copy()


# Rebuilds a copied RGB array from carrier units.
def carrier_to_rgb_array(carrier_sequence, shape):
    if not isinstance(carrier_sequence, np.ndarray):
        raise TypeError("carrier_sequence must be a numpy array")
    if carrier_sequence.dtype != np.uint8:
        raise TypeError("carrier_sequence must have dtype uint8")
    if carrier_sequence.ndim != 1:
        raise ValueError("carrier_sequence must be one-dimensional")

    try:
        shape = tuple(shape)
    except TypeError as error:
        raise TypeError("shape must be a three-dimensional sequence") from error
    if len(shape) != 3 or shape[2] != RGB_CHANNEL_COUNT:
        raise ValueError("shape must be (height, width, 3)")
    if any(not isinstance(dimension, (int, np.integer)) or dimension < 1 for dimension in shape):
        raise ValueError("RGB dimensions must be positive integers")
    if carrier_sequence.size != int(np.prod(shape, dtype=np.int64)):
        raise ValueError("carrier_sequence length does not match shape")

    return np.array(carrier_sequence, dtype=np.uint8, copy=True).reshape(shape)

# Validates a supported LSB count.
def _validate_lsb_count(lsb_count):
    if isinstance(lsb_count, (bool, np.bool_)) or not isinstance(lsb_count, (int, np.integer)):
        raise TypeError("lsb_count must be an integer")
    lsb_count = int(lsb_count)
    if lsb_count not in SUPPORTED_LSB_COUNTS:
        raise ValueError("lsb_count must be between 1 and 8")
    return lsb_count


# Validates a binary uint8 bit sequence.
def _validate_bit_sequence(bit_sequence, byte_aligned=False):
    if not isinstance(bit_sequence, np.ndarray):
        raise TypeError("bit_sequence must be a numpy array")
    if bit_sequence.dtype != np.uint8:
        raise TypeError("bit_sequence must have dtype uint8")
    if bit_sequence.ndim != 1:
        raise ValueError("bit_sequence must be one-dimensional")
    if not np.all((bit_sequence == 0) | (bit_sequence == 1)):
        raise ValueError("bit_sequence may contain only zero and one")
    if byte_aligned and bit_sequence.size % 8 != 0:
        raise ValueError("bit_sequence length must be byte-aligned")
    return bit_sequence


# Validates a non-negative bit length.
def _validate_bit_length(bit_length):
    if isinstance(bit_length, (bool, np.bool_)) or not isinstance(bit_length, (int, np.integer)):
        raise TypeError("bit_length must be a non-negative integer")
    bit_length = int(bit_length)
    if bit_length < 0:
        raise ValueError("bit_length must be non-negative")
    return bit_length


# Validates a one-dimensional uint8 carrier array.
def _validate_carrier_units(carrier_units):
    if not isinstance(carrier_units, np.ndarray):
        raise TypeError("carrier_units must be a numpy array")
    if carrier_units.dtype != np.uint8:
        raise TypeError("carrier_units must have dtype uint8")
    if carrier_units.ndim != 1:
        raise ValueError("carrier_units must be one-dimensional")
    return carrier_units


# Converts bytes to a copied MSB-first bit sequence.
def bytes_to_bit_sequence(data):
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return np.unpackbits(
        np.frombuffer(data, dtype=np.uint8),
        bitorder="big",
    ).astype(np.uint8, copy=True)


# Packs a byte-aligned bit sequence into bytes.
def bit_sequence_to_bytes(bit_sequence):
    _validate_bit_sequence(bit_sequence, byte_aligned=True)
    return np.packbits(bit_sequence, bitorder="big").tobytes()


# Writes bits into copied carrier-unit LSBs.
def write_lsb_bits(carrier_units, bit_sequence, lsb_count):
    carrier_units = _validate_carrier_units(carrier_units)
    bit_sequence = _validate_bit_sequence(bit_sequence)
    lsb_count = _validate_lsb_count(lsb_count)

    capacity = carrier_units.size * lsb_count
    if bit_sequence.size > capacity:
        raise ValueError("bit_sequence exceeds carrier capacity")

    result = np.array(carrier_units, dtype=np.uint8, copy=True)
    bit_index = 0
    units_used = (bit_sequence.size + lsb_count - 1) // lsb_count
    for unit_index in range(units_used):
        bits_in_unit = min(lsb_count, bit_sequence.size - bit_index)
        unit_value = int(result[unit_index])
        for offset in range(bits_in_unit):
            position = lsb_count - 1 - offset
            mask = 1 << position
            bit = int(bit_sequence[bit_index + offset])
            unit_value = (unit_value & ~mask) | (bit << position)
        result[unit_index] = np.uint8(unit_value)
        bit_index += bits_in_unit
    return result


# Reads an exact bit sequence from carrier-unit LSBs.
def read_lsb_bits(carrier_units, bit_length, lsb_count):
    carrier_units = _validate_carrier_units(carrier_units)
    bit_length = _validate_bit_length(bit_length)
    lsb_count = _validate_lsb_count(lsb_count)

    capacity = carrier_units.size * lsb_count
    if bit_length > capacity:
        raise ValueError("requested bit length exceeds carrier capacity")

    result = np.empty(bit_length, dtype=np.uint8)
    for bit_index in range(bit_length):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        result[bit_index] = (int(carrier_units[unit_index]) >> position) & 1
    return result

SIGNATURE_BIT_LENGTH = RSA_KEY_SIZE


# Validates a non-negative integer.
def _validate_non_negative_integer(value, name):
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} must be an integer")
    value = int(value)
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


# Calculates carrier units needed for a bit length.
def ceil_unit_count(bit_length, lsb_count):
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    return (bit_length + lsb_count - 1) // lsb_count


# Calculates required signature alignment padding.
def signature_padding_count(lsb_count):
    lsb_count = _validate_lsb_count(lsb_count)
    return (-SIGNATURE_BIT_LENGTH) % lsb_count


@dataclass(frozen=True)
# Represents the immutable v1 three-region layout.
class RegionLayout:
    lsb_count: int
    start_unit: int
    carrier_unit_count: int
    region2_bit_length: int
    signature_bit_length: int
    signature_padding_bits: int
    region3_bit_length: int
    region2_unit_count: int
    region3_unit_count: int
    region2_range: tuple[int, int]
    region3_range: tuple[int, int]
    region1_ranges: tuple[tuple[int, int], ...]


# Builds a non-wrapping v1 region layout.
def build_region_layout(carrier_unit_count, region2_bit_length, lsb_count, start_unit):
    carrier_unit_count = _validate_non_negative_integer(carrier_unit_count, "carrier_unit_count")
    if carrier_unit_count == 0:
        raise ValueError("carrier capacity must be greater than zero")
    region2_bit_length = _validate_non_negative_integer(region2_bit_length, "region2_bit_length")
    if region2_bit_length == 0:
        raise ValueError("region2_bit_length must be positive")
    lsb_count = _validate_lsb_count(lsb_count)
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")

    region2_unit_count = ceil_unit_count(region2_bit_length, lsb_count)
    region3_unit_count = ceil_unit_count(SIGNATURE_BIT_LENGTH, lsb_count)
    region2_end = start_unit + region2_unit_count
    region3_end = region2_end + region3_unit_count
    if region3_end > carrier_unit_count:
        raise ValueError("complete Regions 2 and 3 do not fit after start_unit")

    region1_ranges = []
    if start_unit > 0:
        region1_ranges.append((0, start_unit))
    if region3_end < carrier_unit_count:
        region1_ranges.append((region3_end, carrier_unit_count))

    return RegionLayout(
        lsb_count=lsb_count,
        start_unit=start_unit,
        carrier_unit_count=carrier_unit_count,
        region2_bit_length=region2_bit_length,
        signature_bit_length=SIGNATURE_BIT_LENGTH,
        signature_padding_bits=signature_padding_count(lsb_count),
        region3_bit_length=SIGNATURE_BIT_LENGTH + signature_padding_count(lsb_count),
        region2_unit_count=region2_unit_count,
        region3_unit_count=region3_unit_count,
        region2_range=(start_unit, region2_end),
        region3_range=(region2_end, region3_end),
        region1_ranges=tuple(region1_ranges),
    )

SHA256_DIGEST_SIZE = 32
UINT64_MAX = (1 << 64) - 1
REGION1_HASH_DOMAIN = b"INF2005-ACW1\x00V1\x00REGION1\x00"
REGION3_HASH_DOMAIN = b"INF2005-ACW1\x00V1\x00REGION3-UPPER\x00"


# Validates an unsigned 64-bit integer.
def _validate_uint64(value, name):
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} must be an integer")
    value = int(value)
    if value < 0 or value > UINT64_MAX:
        raise ValueError(f"{name} must fit in unsigned 64 bits")
    return value


# Validates bits used in a hash preimage.
def _validate_binary_hash_bits(bit_sequence):
    if not isinstance(bit_sequence, np.ndarray):
        raise TypeError("bit_sequence must be a numpy array")
    if bit_sequence.dtype != np.uint8:
        raise TypeError("bit_sequence must have dtype uint8")
    if bit_sequence.ndim != 1:
        raise ValueError("bit_sequence must be one-dimensional")
    if not np.all((bit_sequence == 0) | (bit_sequence == 1)):
        raise ValueError("bit_sequence may contain only zero and one")
    return bit_sequence


# Collects unchanged Region 3 upper bits.
def collect_region3_upper_bits(carrier_units, lsb_count):
    carrier_units = _validate_carrier_units(carrier_units)
    lsb_count = _validate_lsb_count(lsb_count)
    bits_per_unit = 8 - lsb_count
    result = np.empty(carrier_units.size * bits_per_unit, dtype=np.uint8)
    bit_index = 0
    for carrier_unit in carrier_units:
        unit_value = int(carrier_unit)
        for position in range(7, lsb_count - 1, -1):
            result[bit_index] = (unit_value >> position) & 1
            bit_index += 1
    return result


# Packs Region 3 upper bits for hashing.
def pack_region3_upper_bits(bit_sequence):
    bit_sequence = _validate_binary_hash_bits(bit_sequence)
    return np.packbits(bit_sequence, bitorder="big").tobytes()


# Builds the Region 1 hash preimage.
def encode_region1_hash_preimage(carrier_units):
    carrier_units = _validate_carrier_units(carrier_units)
    unit_count = _validate_uint64(carrier_units.size, "carrier-unit count")
    return (
        REGION1_HASH_DOMAIN
        + unit_count.to_bytes(8, byteorder="big")
        + carrier_units.tobytes()
    )


# Calculates the Region 1 carrier hash.
def calculate_region1_hash(carrier_units):
    digest = hashlib.sha256(encode_region1_hash_preimage(carrier_units)).digest()
    assert len(digest) == SHA256_DIGEST_SIZE
    return digest


# Builds the Region 3 upper-bit hash preimage.
def encode_region3_hash_preimage(carrier_units, lsb_count):
    carrier_units = _validate_carrier_units(carrier_units)
    lsb_count = _validate_lsb_count(lsb_count)
    unit_count = _validate_uint64(carrier_units.size, "carrier-unit count")
    upper_bits = collect_region3_upper_bits(carrier_units, lsb_count)
    bit_length = _validate_uint64(upper_bits.size, "upper-bit stream length")
    packed_bits = pack_region3_upper_bits(upper_bits)
    return (
        REGION3_HASH_DOMAIN
        + bytes((lsb_count,))
        + unit_count.to_bytes(8, byteorder="big")
        + bit_length.to_bytes(8, byteorder="big")
        + packed_bits
    )


# Calculates the Region 3 upper-bit hash.
def calculate_region3_hash(carrier_units, lsb_count):
    digest = hashlib.sha256(encode_region3_hash_preimage(carrier_units, lsb_count)).digest()
    assert len(digest) == SHA256_DIGEST_SIZE
    return digest

REGION2_HEADER_FORMAT = ">BBHI"
REGION2_HEADER_SIZE = struct.calcsize(REGION2_HEADER_FORMAT)
REGION2_PREFIX_SIZE = len(START_MAGIC) + REGION2_HEADER_SIZE
V1_HEADER_LENGTH = REGION2_HEADER_SIZE
MAX_PAYLOAD_LENGTH = 16 * 1024 * 1024


# Requires a bytes value.
def _require_bytes(value, name):
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


# Validates a bounded payload length.
def validate_payload_length(payload_length):
    payload_length = _validate_non_negative_integer(payload_length, "payload_length")
    if payload_length > MAX_PAYLOAD_LENGTH:
        raise ValueError("payload exceeds the version-1 payload limit")
    if payload_length > 0xFFFFFFFF:
        raise ValueError("payload length does not fit the header")
    return payload_length


# Validates and copies payload bytes.
def validate_payload_bytes(payload_bytes):
    payload_bytes = _require_bytes(payload_bytes, "payload_bytes")
    validate_payload_length(len(payload_bytes))
    return bytes(bytearray(payload_bytes))


# Validates the v1 protocol version.
def _validate_protocol_version(protocol_version):
    protocol_version = _validate_non_negative_integer(protocol_version, "protocol_version")
    if protocol_version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if protocol_version > 0xFF:
        raise ValueError("protocol version does not fit the header")
    return protocol_version


# Validates the fixed v1 header length.
def _validate_header_length(header_length):
    header_length = _validate_non_negative_integer(header_length, "header_length")
    if header_length != V1_HEADER_LENGTH:
        raise ValueError("header_length must be exactly 8 for version 1")
    if header_length > 0xFFFF:
        raise ValueError("header length does not fit the header")
    return header_length


@dataclass(frozen=True)
# Represents the immutable Region 2 header.
class Region2Header:
    protocol_version: int
    lsb_count: int
    header_length: int
    payload_length: int


# Serializes the fixed Region 2 header.
def serialize_region2_header(
    lsb_count,
    payload_length,
    protocol_version=PROTOCOL_VERSION,
    header_length=V1_HEADER_LENGTH,
):
    protocol_version = _validate_protocol_version(protocol_version)
    lsb_count = _validate_lsb_count(lsb_count)
    header_length = _validate_header_length(header_length)
    payload_length = validate_payload_length(payload_length)
    return struct.pack(
        REGION2_HEADER_FORMAT,
        protocol_version,
        lsb_count,
        header_length,
        payload_length,
    )


# Parses and validates a Region 2 header.
def parse_region2_header(header_bytes):
    header_bytes = _require_bytes(header_bytes, "header_bytes")
    if len(header_bytes) != REGION2_HEADER_SIZE:
        raise ValueError("header must contain exactly 8 bytes")
    protocol_version, lsb_count, header_length, payload_length = struct.unpack(
        REGION2_HEADER_FORMAT, header_bytes
    )
    return Region2Header(
        protocol_version=_validate_protocol_version(protocol_version),
        lsb_count=_validate_lsb_count(lsb_count),
        header_length=_validate_header_length(header_length),
        payload_length=validate_payload_length(payload_length),
    )


# Frames a payload into a Region 2 stream.
def build_region2_stream(payload_bytes, lsb_count):
    payload_bytes = validate_payload_bytes(payload_bytes)
    header = serialize_region2_header(lsb_count, len(payload_bytes))
    return START_MAGIC + header + payload_bytes


# Parses a complete Region 2 stream.
def parse_region2_stream(region2_stream):
    region2_stream = _require_bytes(region2_stream, "region2_stream")
    if len(region2_stream) < REGION2_PREFIX_SIZE:
        raise ValueError("Region 2 stream is truncated before the payload")
    if region2_stream[:len(START_MAGIC)] != START_MAGIC:
        raise ValueError("Region 2 stream has the wrong start magic")
    header = parse_region2_header(
        region2_stream[len(START_MAGIC):REGION2_PREFIX_SIZE]
    )
    expected_length = REGION2_PREFIX_SIZE + header.payload_length
    if len(region2_stream) != expected_length:
        raise ValueError("Region 2 stream length does not match payload_length")
    payload_start = REGION2_PREFIX_SIZE
    payload = bytes(bytearray(region2_stream[payload_start:expected_length]))
    return header, payload


# Calculates the exact Region 2 bit length.
def calculate_region2_bit_length(payload_length, lsb_count):
    payload_length = validate_payload_length(payload_length)
    _validate_lsb_count(lsb_count)
    return (REGION2_PREFIX_SIZE + payload_length) * 8

MAX_MAGIC_CANDIDATES = 64


@dataclass(frozen=True)
# Represents one magic-scan candidate.
class StartMagicCandidate:
    start_unit: int
    lsb_count: int


# Validates a positive integer.
def _validate_positive_integer(value, name):
    value = _validate_non_negative_integer(value, name)
    if value == 0:
        raise ValueError(f"{name} must be positive")
    return value


# Builds masks and values for magic matching.
def _magic_unit_masks_and_values(lsb_count):
    lsb_count = _validate_lsb_count(lsb_count)
    magic_bits = bytes_to_bit_sequence(START_MAGIC)
    unit_count = ceil_unit_count(magic_bits.size, lsb_count)
    masks = np.zeros(unit_count, dtype=np.uint8)
    values = np.zeros(unit_count, dtype=np.uint8)
    bit_index = 0
    for unit_index in range(unit_count):
        bits_in_unit = min(lsb_count, magic_bits.size - bit_index)
        for offset in range(bits_in_unit):
            position = lsb_count - 1 - offset
            masks[unit_index] |= np.uint8(1 << position)
            values[unit_index] |= np.uint8(int(magic_bits[bit_index + offset]) << position)
        bit_index += bits_in_unit
    return masks, values


# Finds matching magic windows for one LSB count.
def _find_magic_start_mask(carrier_units, lsb_count):
    lsb_count = _validate_lsb_count(lsb_count)
    masks, values = _magic_unit_masks_and_values(lsb_count)
    unit_count = masks.size
    if carrier_units.size < unit_count:
        return np.empty(0, dtype=bool), 0

    candidate_count = carrier_units.size - unit_count + 1
    matches = np.ones(candidate_count, dtype=bool)
    for unit_offset in range(unit_count):
        matches &= (
            carrier_units[unit_offset:unit_offset + candidate_count] & masks[unit_offset]
        ) == values[unit_offset]
    return matches, int(np.count_nonzero(matches))


# Scans bounded magic candidates for one LSB count.
def scan_start_magic_for_lsb(
    carrier_units,
    lsb_count,
    max_candidates=MAX_MAGIC_CANDIDATES,
):
    carrier_units = _validate_carrier_units(carrier_units)
    lsb_count = _validate_lsb_count(lsb_count)
    max_candidates = _validate_positive_integer(max_candidates, "max_candidates")
    matches, match_count = _find_magic_start_mask(carrier_units, lsb_count)
    if match_count > max_candidates:
        raise ValueError("magic candidate limit exceeded")
    start_indices = np.flatnonzero(matches)
    return tuple(
        StartMagicCandidate(int(start_unit), lsb_count)
        for start_unit in start_indices
    )


# Scans bounded magic candidates for all LSB counts.
def scan_start_magic(
    carrier_units,
    max_candidates=MAX_MAGIC_CANDIDATES,
):
    carrier_units = _validate_carrier_units(carrier_units)
    max_candidates = _validate_positive_integer(max_candidates, "max_candidates")
    candidates = []
    for lsb_count in SUPPORTED_LSB_COUNTS:
        remaining = max_candidates - len(candidates)
        matches, match_count = _find_magic_start_mask(carrier_units, lsb_count)
        if match_count > remaining:
            raise ValueError("magic candidate limit exceeded")
        start_indices = np.flatnonzero(matches)
        candidates.extend(
            StartMagicCandidate(int(start_unit), lsb_count)
            for start_unit in start_indices
        )
    return tuple(sorted(candidates, key=lambda candidate: (candidate.start_unit, candidate.lsb_count)))


RSA_PUBLIC_EXPONENT = 65537
RSA_PUBLIC_KEY_SIZE = 2048
MAX_PUBLIC_KEY_ENCODING_LENGTH = 512
FINGERPRINT_DISPLAY_PREFIX = "SHA256:"


# Validates a v1 RSA public key.
def validate_rsa_public_key(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")
    if public_key.key_size != RSA_PUBLIC_KEY_SIZE:
        raise ValueError("public_key must be RSA-2048")
    if public_key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("public_key exponent must be 65537")
    return public_key


# Serializes a canonical RSA public key.
def serialize_rsa_public_key(public_key):
    public_key = validate_rsa_public_key(public_key)
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not isinstance(encoded, bytes):
        raise TypeError("canonical public-key encoding must be bytes")
    if len(encoded) > MAX_PUBLIC_KEY_ENCODING_LENGTH:
        raise ValueError("canonical public-key encoding exceeds the limit")
    return bytes(encoded)


# Parses canonical RSA public-key DER.
def parse_rsa_public_key(encoded):
    if not isinstance(encoded, bytes):
        raise TypeError("encoded public key must be bytes")
    if len(encoded) == 0 or len(encoded) > MAX_PUBLIC_KEY_ENCODING_LENGTH:
        raise ValueError("encoded public key has an invalid length")
    try:
        public_key = serialization.load_der_public_key(encoded)
    except (ValueError, TypeError) as error:
        raise ValueError("encoded public key is not valid DER") from error
    validate_rsa_public_key(public_key)
    canonical = serialize_rsa_public_key(public_key)
    if canonical != encoded:
        raise ValueError("encoded public key is not canonical DER")
    return public_key


# Calculates the RSA public-key fingerprint.
def fingerprint_rsa_public_key(public_key):
    return hashlib.sha256(serialize_rsa_public_key(public_key)).digest()


# Formats the RSA fingerprint for display.
def display_rsa_public_key_fingerprint(public_key):
    fingerprint = fingerprint_rsa_public_key(public_key)
    return FINGERPRINT_DISPLAY_PREFIX + base64.b64encode(fingerprint).decode("ascii").rstrip("=")

# Requires a bytes value for v1 signing.
def _require_v1_bytes(value, name):
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


# Validates a v1 RSA private key.
def validate_rsa_private_key(private_key):
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")
    if private_key.key_size != RSA_KEY_SIZE:
        raise ValueError("private_key must be RSA-2048")
    if private_key.private_numbers().public_numbers.e != RSA_PUBLIC_EXPONENT:
        raise ValueError("private_key exponent must be 65537")
    return private_key


# Generates a validated v1 RSA key pair.
def generate_v1_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()
    return validate_rsa_private_key(private_key), validate_rsa_public_key(public_key)


# Builds the fixed v1 RSA-PSS padding.
def v1_rsa_pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=RSA_PSS_SALT_LENGTH,
    )


# Signs bytes with fixed v1 RSA-PSS.
def sign_v1_bytes(signing_input, private_key):
    signing_input = _require_v1_bytes(signing_input, "signing_input")
    private_key = validate_rsa_private_key(private_key)
    signature = private_key.sign(signing_input, v1_rsa_pss_padding(), hashes.SHA256())
    if len(signature) != RSA_SIGNATURE_SIZE:
        raise ValueError("v1 RSA signature must contain exactly 256 bytes")
    return bytes(signature)


# Verifies a fixed v1 RSA-PSS signature.
def verify_v1_signature(signing_input, signature, public_key):
    signing_input = _require_v1_bytes(signing_input, "signing_input")
    signature = _require_v1_bytes(signature, "signature")
    public_key = validate_rsa_public_key(public_key)
    if len(signature) != RSA_SIGNATURE_SIZE:
        return False
    try:
        public_key.verify(
            signature,
            signing_input,
            v1_rsa_pss_padding(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


# Checks whether an RSA key pair matches.
def rsa_private_key_matches_public_key(private_key, public_key):
    private_key = validate_rsa_private_key(private_key)
    public_key = validate_rsa_public_key(public_key)
    return private_key.public_key().public_numbers() == public_key.public_numbers()

REGION2_SIGNING_DOMAIN = b"INF2005-ACW1\x00V1\x00REGION2-SIGN\x00"
IMAGE_MEDIA_CODE = 1
AUDIO_MEDIA_CODE = 2
SUPPORTED_MEDIA_CODES = (IMAGE_MEDIA_CODE, AUDIO_MEDIA_CODE)
MAX_MEDIA_CONTEXT_LENGTH = 4096
REGION2_SIGNING_CONTEXT_FORMAT = ">BBIBQQQQQQHB"
REGION2_SIGNING_CONTEXT_SIZE = struct.calcsize(REGION2_SIGNING_CONTEXT_FORMAT)


# Validates a positive unsigned 32-bit value.
def _validate_positive_uint32(value, name):
    value = _validate_non_negative_integer(value, name)
    if value == 0 or value > 0xFFFFFFFF:
        raise ValueError(f"{name} must be a positive uint32")
    return value


# Validates a supported media code.
def _validate_media_type(media_type):
    media_type = _validate_non_negative_integer(media_type, "media_type")
    if media_type not in SUPPORTED_MEDIA_CODES:
        raise ValueError("unsupported media type")
    return media_type


# Validates and copies bounded media context.
def _validate_media_context(media_context):
    media_context = _require_bytes(media_context, "media_context")
    if len(media_context) > MAX_MEDIA_CONTEXT_LENGTH:
        raise ValueError("media_context exceeds the version-1 limit")
    if len(media_context) > 0xFFFFFFFF:
        raise ValueError("media_context does not fit the signing context")
    return bytes(bytearray(media_context))


# Validates one non-decreasing region range.
def _validate_region_range(region_range, name):
    if not isinstance(region_range, tuple) or len(region_range) != 2:
        raise TypeError(f"{name} must be a two-item tuple")
    start = _validate_non_negative_integer(region_range[0], f"{name} start")
    end = _validate_non_negative_integer(region_range[1], f"{name} end")
    if end < start:
        raise ValueError(f"{name} must be non-decreasing")
    return start, end


# Validates the complete v1 region layout.
def _validate_v1_layout(layout):
    if not isinstance(layout, RegionLayout):
        raise TypeError("layout must be a RegionLayout")
    lsb_count = _validate_lsb_count(layout.lsb_count)
    carrier_unit_count = _validate_uint64(layout.carrier_unit_count, "carrier-unit count")
    if carrier_unit_count == 0:
        raise ValueError("carrier-unit count must be positive")
    start_unit = _validate_uint64(layout.start_unit, "start unit")
    region2_bit_length = _validate_uint64(layout.region2_bit_length, "Region 2 bit length")
    if region2_bit_length == 0:
        raise ValueError("Region 2 bit length must be positive")
    signature_bit_length = _validate_uint64(layout.signature_bit_length, "signature bit length")
    if signature_bit_length != SIGNATURE_BIT_LENGTH:
        raise ValueError("signature bit length is not the v1 value")
    signature_padding_bits = _validate_uint64(layout.signature_padding_bits, "signature padding bits")
    expected_padding = signature_padding_count(lsb_count)
    if signature_padding_bits != expected_padding:
        raise ValueError("signature padding does not match v1")
    region3_bit_length = _validate_uint64(layout.region3_bit_length, "Region 3 bit length")
    if region3_bit_length != signature_bit_length + signature_padding_bits:
        raise ValueError("Region 3 bit length is inconsistent")

    region2_unit_count = _validate_uint64(layout.region2_unit_count, "Region 2 unit count")
    region3_unit_count = _validate_uint64(layout.region3_unit_count, "Region 3 unit count")
    if region2_unit_count != ceil_unit_count(region2_bit_length, lsb_count):
        raise ValueError("Region 2 unit count is inconsistent")
    if region3_unit_count != ceil_unit_count(SIGNATURE_BIT_LENGTH, lsb_count):
        raise ValueError("Region 3 unit count is inconsistent")

    region2_start, region2_end = _validate_region_range(layout.region2_range, "Region 2 range")
    region3_start, region3_end = _validate_region_range(layout.region3_range, "Region 3 range")
    if region2_start != start_unit or region2_end != start_unit + region2_unit_count:
        raise ValueError("Region 2 range is inconsistent")
    if region3_start != region2_end or region3_end != region3_start + region3_unit_count:
        raise ValueError("Region 3 range is inconsistent")
    if region3_end > carrier_unit_count:
        raise ValueError("Regions do not fit in carrier")

    if not isinstance(layout.region1_ranges, tuple):
        raise TypeError("Region 1 ranges must be a tuple")
    region1_ranges = tuple(
        _validate_region_range(region_range, "Region 1 range")
        for region_range in layout.region1_ranges
    )
    expected_region1_ranges = []
    if start_unit > 0:
        expected_region1_ranges.append((0, start_unit))
    if region3_end < carrier_unit_count:
        expected_region1_ranges.append((region3_end, carrier_unit_count))
    if region1_ranges != tuple(expected_region1_ranges):
        raise ValueError("Region 1 complement ranges are inconsistent")
    return {
        "lsb_count": lsb_count,
        "carrier_unit_count": carrier_unit_count,
        "start_unit": start_unit,
        "region2_bit_length": region2_bit_length,
        "region2_unit_count": region2_unit_count,
        "region3_start_unit": region3_start,
        "region3_unit_count": region3_unit_count,
        "region3_bit_length": region3_bit_length,
        "signature_bit_length": signature_bit_length,
        "signature_padding_bits": signature_padding_bits,
    }
# Builds the canonical Region 2 signing input.
def encode_region2_signing_input(media_type, media_context, layout, region2_values):
    """Serialize the media-neutral, authenticated Region 2 signing input."""
    media_type = _validate_media_type(media_type)
    media_context = _validate_media_context(media_context)
    validated_layout = _validate_v1_layout(layout)
    region2_values = _validate_carrier_units(region2_values)
    if region2_values.size != validated_layout["region2_unit_count"]:
        raise ValueError("Region 2 values do not match the layout")

    context = struct.pack(
        REGION2_SIGNING_CONTEXT_FORMAT,
        PROTOCOL_VERSION,
        media_type,
        len(media_context),
        validated_layout["lsb_count"],
        validated_layout["carrier_unit_count"],
        validated_layout["start_unit"],
        validated_layout["region2_bit_length"],
        validated_layout["region2_unit_count"],
        validated_layout["region3_start_unit"],
        validated_layout["region3_unit_count"],
        validated_layout["signature_bit_length"],
        validated_layout["signature_padding_bits"],
    )
    return REGION2_SIGNING_DOMAIN + context + media_context + region2_values.tobytes()

PNG_RGB8_CONTEXT_DOMAIN = b"PNG-RGB8\x00"

# Builds the canonical PNG media context.
def encode_png_media_context(image_shape, carrier_unit_count):
    """Return the canonical context for a static 8-bit RGB PNG carrier."""
    if not isinstance(image_shape, tuple) or len(image_shape) != 3:
        raise TypeError("image_shape must be a (height, width, 3) tuple")
    height = _validate_positive_uint32(image_shape[0], "height")
    width = _validate_positive_uint32(image_shape[1], "width")
    channels = _validate_non_negative_integer(image_shape[2], "channel count")
    if channels != RGB_CHANNEL_COUNT:
        raise ValueError("image_shape must describe RGB data")
    carrier_unit_count = _validate_uint64(carrier_unit_count, "carrier-unit count")
    expected_carrier_unit_count = height * width * RGB_CHANNEL_COUNT
    if carrier_unit_count != expected_carrier_unit_count:
        raise ValueError("image shape does not match carrier count")
    return PNG_RGB8_CONTEXT_DOMAIN + struct.pack(">II", width, height)


V1_PAYLOAD_FIELDS = frozenset({
    "media_type",
    "media_context",
    "unembedded_carrier_hash",
    "reserved_upper_bits_hash",
    "media_id",
    "timestamp",
    "nonce",
    "message",
    "metadata",
})
MAX_MEDIA_ID_LENGTH = 128
MAX_MESSAGE_LENGTH = 15 * 1024 * 1024
V1_NONCE_SIZE = 16
MAX_METADATA_ENTRIES = 32
MAX_METADATA_KEY_LENGTH = 64
MAX_METADATA_VALUE_LENGTH = 1024
V1_TIMESTAMP_PATTERN = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


# Validates and copies bounded v1 bytes.
def _copy_v1_bytes(value, name, exact_length=None, maximum_length=None):
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    copied = bytes(bytearray(value))
    if exact_length is not None and len(copied) != exact_length:
        raise ValueError(f"{name} must contain exactly {exact_length} bytes")
    if maximum_length is not None and len(copied) > maximum_length:
        raise ValueError(f"{name} exceeds the version-1 limit")
    return copied


# Validates bounded v1 text.
def _validate_v1_text(value, name, maximum_length, nonempty=False, reject_controls=False):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if nonempty and value == "":
        raise ValueError(f"{name} must not be empty")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must be valid UTF-8") from error
    if len(encoded) > maximum_length:
        raise ValueError(f"{name} exceeds the version-1 limit")
    if reject_controls and any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return str(value)


# Validates canonical bounded Base64.
def _validate_v1_base64(value, name, maximum_length):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a Base64 string")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise ValueError(f"{name} is not valid standard Base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{name} is not canonically padded Base64")
    if len(decoded) > maximum_length:
        raise ValueError(f"{name} exceeds the version-1 limit")
    return bytes(bytearray(decoded))


# Validates canonical fixed-length hexadecimal.
def _validate_v1_hex(value, name, byte_length):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hexadecimal string")
    if not re.fullmatch(r"[0-9a-f]+", value) or len(value) != byte_length * 2:
        raise ValueError(f"{name} must be lowercase hex for exactly {byte_length} bytes")
    decoded = bytes.fromhex(value)
    if decoded.hex() != value:
        raise ValueError(f"{name} is not canonical lowercase hex")
    return bytes(bytearray(decoded))


# Validates the exact UTC timestamp form.
def _validate_v1_timestamp(value):
    value = _validate_v1_text(value, "timestamp", 20)
    if not V1_TIMESTAMP_PATTERN.fullmatch(value):
        raise ValueError("timestamp must use exact UTC form YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("timestamp is not a real UTC date/time") from error
    return value


# Normalizes and validates payload metadata.
def _normalize_v1_metadata(metadata):
    if isinstance(metadata, Mapping):
        pairs = tuple(metadata.items())
    else:
        try:
            pairs = tuple(metadata)
        except TypeError as error:
            raise TypeError("metadata must be an object or pairs") from error
    if len(pairs) > MAX_METADATA_ENTRIES:
        raise ValueError("metadata exceeds the version-1 entry limit")
    normalized = []
    seen = set()
    for pair in pairs:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise TypeError("metadata entries must be two-item tuples")
        key = _validate_v1_text(
            pair[0], "metadata key", MAX_METADATA_KEY_LENGTH,
            nonempty=True, reject_controls=True,
        )
        value = _validate_v1_text(
            pair[1], "metadata value", MAX_METADATA_VALUE_LENGTH,
            reject_controls=True,
        )
        if key in seen:
            raise ValueError("metadata keys must be unique")
        seen.add(key)
        normalized.append((key, value))
    return tuple(sorted(normalized))


@dataclass(frozen=True)
# Represents the immutable v1 payload record.
class V1PayloadRecord:
    media_type: int
    media_context: bytes
    unembedded_carrier_hash: bytes
    reserved_upper_bits_hash: bytes
    media_id: str
    timestamp: str
    nonce: bytes
    message: str
    metadata: tuple[tuple[str, str], ...]

    # Validates and normalizes payload record fields.
    def __post_init__(self):
        media_type = _validate_non_negative_integer(self.media_type, "media_type")
        if media_type not in SUPPORTED_MEDIA_CODES:
            raise ValueError("unsupported media type")
        object.__setattr__(self, "media_type", media_type)
        object.__setattr__(
            self, "media_context",
            _copy_v1_bytes(self.media_context, "media_context", maximum_length=MAX_MEDIA_CONTEXT_LENGTH),
        )
        object.__setattr__(
            self, "unembedded_carrier_hash",
            _copy_v1_bytes(self.unembedded_carrier_hash, "unembedded_carrier_hash", exact_length=SHA256_DIGEST_SIZE),
        )
        object.__setattr__(
            self, "reserved_upper_bits_hash",
            _copy_v1_bytes(self.reserved_upper_bits_hash, "reserved_upper_bits_hash", exact_length=SHA256_DIGEST_SIZE),
        )
        object.__setattr__(
            self, "media_id",
            _validate_v1_text(self.media_id, "media_id", MAX_MEDIA_ID_LENGTH, nonempty=True, reject_controls=True),
        )
        object.__setattr__(self, "timestamp", _validate_v1_timestamp(self.timestamp))
        object.__setattr__(self, "nonce", _copy_v1_bytes(self.nonce, "nonce", exact_length=V1_NONCE_SIZE))
        object.__setattr__(
            self, "message", _validate_v1_text(self.message, "message", MAX_MESSAGE_LENGTH),
        )
        object.__setattr__(self, "metadata", _normalize_v1_metadata(self.metadata))


# Rejects duplicate JSON object keys.
def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


# Rejects non-finite JSON constants.
def _reject_json_constant(value):
    raise ValueError(f"non-finite JSON value is not allowed: {value}")


# Serializes a canonical v1 payload record.
def serialize_v1_payload(record):
    if not isinstance(record, V1PayloadRecord):
        raise TypeError("record must be a V1PayloadRecord")
    document = {
        "media_type": record.media_type,
        "media_context": base64.b64encode(bytes(record.media_context)).decode("ascii"),
        "unembedded_carrier_hash": bytes(record.unembedded_carrier_hash).hex(),
        "reserved_upper_bits_hash": bytes(record.reserved_upper_bits_hash).hex(),
        "media_id": record.media_id,
        "timestamp": record.timestamp,
        "nonce": bytes(record.nonce).hex(),
        "message": record.message,
        "metadata": dict(record.metadata),
    }
    try:
        serialized = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise ValueError("record cannot be serialized canonically") from error
    if len(serialized) > MAX_PAYLOAD_LENGTH:
        raise ValueError("serialized payload exceeds the version-1 limit")
    return bytes(bytearray(serialized))


# Parses and validates a canonical v1 payload.
def parse_v1_payload(payload_bytes):
    payload_bytes = _copy_v1_bytes(payload_bytes, "payload_bytes", maximum_length=MAX_PAYLOAD_LENGTH)
    try:
        document = json.loads(
            payload_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise ValueError("payload is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ValueError("payload top level must be a JSON object")
    if set(document) != V1_PAYLOAD_FIELDS:
        raise ValueError("payload fields do not match the version-1 schema")
    try:
        record = V1PayloadRecord(
            media_type=document["media_type"],
            media_context=_validate_v1_base64(document["media_context"], "media_context", MAX_MEDIA_CONTEXT_LENGTH),
            unembedded_carrier_hash=_validate_v1_hex(document["unembedded_carrier_hash"], "unembedded_carrier_hash", 32),
            reserved_upper_bits_hash=_validate_v1_hex(document["reserved_upper_bits_hash"], "reserved_upper_bits_hash", 32),
            media_id=document["media_id"],
            timestamp=document["timestamp"],
            nonce=_validate_v1_hex(document["nonce"], "nonce", V1_NONCE_SIZE),
            message=document["message"],
            metadata=document["metadata"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError("payload contains an invalid version-1 field") from error
    if serialize_v1_payload(record) != payload_bytes:
        raise ValueError("payload is not canonical JSON")
    return record

V1_MEDIA_ID_PREFIXES = {
    IMAGE_MEDIA_CODE: "IMG",
    AUDIO_MEDIA_CODE: "AUD",
}
V1_MEDIA_ID_RANDOM_SIZE = 16


# Creates a v1 payload with generated identity fields.
def create_v1_payload_record(
    media_type,
    media_context,
    unembedded_carrier_hash,
    reserved_upper_bits_hash,
    message,
    metadata,
):
    media_type = _validate_media_type(media_type)
    media_id = f"{V1_MEDIA_ID_PREFIXES[media_type]}-{secrets.token_hex(V1_MEDIA_ID_RANDOM_SIZE)}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_bytes(V1_NONCE_SIZE)
    return V1PayloadRecord(
        media_type=media_type,
        media_context=media_context,
        unembedded_carrier_hash=unembedded_carrier_hash,
        reserved_upper_bits_hash=reserved_upper_bits_hash,
        media_id=media_id,
        timestamp=timestamp,
        nonce=nonce,
        message=message,
        metadata=metadata,
    )

# Validates carrier units against a v1 layout.
def _validate_v1_carrier_layout(carrier_units, layout):
    carrier_units = _validate_carrier_units(carrier_units)
    validated_layout = _validate_v1_layout(layout)
    if carrier_units.size != validated_layout["carrier_unit_count"]:
        raise ValueError("carrier length does not match layout")
    return carrier_units, validated_layout


# Selects copied carrier units from ranges.
def _select_v1_ranges(carrier_units, ranges):
    if not ranges:
        return np.empty(0, dtype=np.uint8)
    selected = [carrier_units[start:end] for start, end in ranges]
    if len(selected) == 1:
        return selected[0].copy()
    return np.concatenate(selected).astype(np.uint8, copy=True)


# Selects copied Region 1 carrier units.
def select_region1_units(carrier_units, layout):
    carrier_units, _ = _validate_v1_carrier_layout(carrier_units, layout)
    return _select_v1_ranges(carrier_units, layout.region1_ranges)


# Selects copied Region 2 carrier units.
def select_region2_units(carrier_units, layout):
    carrier_units, _ = _validate_v1_carrier_layout(carrier_units, layout)
    return _select_v1_ranges(carrier_units, (layout.region2_range,))


# Selects copied Region 3 carrier units.
def select_region3_units(carrier_units, layout):
    carrier_units, _ = _validate_v1_carrier_layout(carrier_units, layout)
    return _select_v1_ranges(carrier_units, (layout.region3_range,))


# Calculates both hashes for a v1 layout.
def calculate_layout_hashes(carrier_units, layout):
    carrier_units, validated_layout = _validate_v1_carrier_layout(carrier_units, layout)
    region1_units = _select_v1_ranges(carrier_units, layout.region1_ranges)
    region3_units = _select_v1_ranges(carrier_units, (layout.region3_range,))
    return (
        calculate_region1_hash(region1_units),
        calculate_region3_hash(region3_units, validated_layout["lsb_count"]),
    )

# Validates Region 2 embedding inputs.
def _validate_region2_stream_input(carrier_units, layout, region2_stream):
    carrier_units, validated_layout = _validate_v1_carrier_layout(carrier_units, layout)
    region2_stream = _require_bytes(region2_stream, "region2_stream")
    if len(region2_stream) * 8 != validated_layout["region2_bit_length"]:
        raise ValueError("Region 2 stream length does not match layout")
    return carrier_units, validated_layout, region2_stream


# Embeds a Region 2 stream into copied carriers.
def embed_region2_stream(carrier_units, layout, region2_stream):
    carrier_units, validated_layout, region2_stream = _validate_region2_stream_input(
        carrier_units, layout, region2_stream
    )
    region2_start, region2_end = layout.region2_range
    region2_bits = bytes_to_bit_sequence(region2_stream)
    embedded_region2 = write_lsb_bits(
        select_region2_units(carrier_units, layout),
        region2_bits,
        validated_layout["lsb_count"],
    )
    result = carrier_units.copy()
    result[region2_start:region2_end] = embedded_region2
    return result


# Extracts the Region 2 stream.
def extract_region2_stream(carrier_units, layout):
    carrier_units, validated_layout = _validate_v1_carrier_layout(carrier_units, layout)
    region2_units = select_region2_units(carrier_units, layout)
    region2_bits = read_lsb_bits(
        region2_units,
        validated_layout["region2_bit_length"],
        validated_layout["lsb_count"],
    )
    return bit_sequence_to_bytes(region2_bits)

# Builds signature bits with zero padding.
def encode_region3_signature_bits(signature, lsb_count):
    signature = _require_bytes(signature, "signature")
    if len(signature) != RSA_SIGNATURE_SIZE:
        raise ValueError("signature must contain exactly 256 bytes")
    lsb_count = _validate_lsb_count(lsb_count)
    signature_bits = bytes_to_bit_sequence(signature)
    padding_bits = signature_padding_count(lsb_count)
    result = np.zeros(SIGNATURE_BIT_LENGTH + padding_bits, dtype=np.uint8)
    result[:SIGNATURE_BIT_LENGTH] = signature_bits
    return result


# Decodes and validates signature padding.
def decode_region3_signature_bits(region3_bits, lsb_count):
    lsb_count = _validate_lsb_count(lsb_count)
    region3_bits = _validate_bit_sequence(region3_bits)
    expected_length = SIGNATURE_BIT_LENGTH + signature_padding_count(lsb_count)
    if region3_bits.size != expected_length:
        raise ValueError("Region 3 bit sequence has the wrong length")
    padding_start = SIGNATURE_BIT_LENGTH
    if np.any(region3_bits[padding_start:] != 0):
        raise ValueError("Region 3 signature alignment padding must be zero")
    return bit_sequence_to_bytes(region3_bits[:SIGNATURE_BIT_LENGTH])


# Embeds a signature into copied Region 3 carriers.
def embed_region3_signature(carrier_units, layout, signature):
    carrier_units, validated_layout = _validate_v1_carrier_layout(carrier_units, layout)
    signature_bits = encode_region3_signature_bits(signature, validated_layout["lsb_count"])
    region3_start, region3_end = layout.region3_range
    embedded_region3 = write_lsb_bits(
        select_region3_units(carrier_units, layout),
        signature_bits,
        validated_layout["lsb_count"],
    )
    result = carrier_units.copy()
    result[region3_start:region3_end] = embedded_region3
    return result


# Extracts and validates the Region 3 signature.
def extract_region3_signature(carrier_units, layout):
    carrier_units, validated_layout = _validate_v1_carrier_layout(carrier_units, layout)
    region3_bits = read_lsb_bits(
        select_region3_units(carrier_units, layout),
        validated_layout["region3_bit_length"],
        validated_layout["lsb_count"],
    )
    return decode_region3_signature_bits(region3_bits, validated_layout["lsb_count"])

@dataclass(frozen=True)
# Represents a resolved candidate, header, and layout.
class ResolvedRegion2Candidate:
    candidate: StartMagicCandidate
    header: Region2Header
    layout: RegionLayout


# Validates a v1 start-magic candidate.
def _validate_v1_start_magic_candidate(candidate):
    if not isinstance(candidate, StartMagicCandidate):
        raise TypeError("candidate must be a StartMagicCandidate")
    start_unit = _validate_non_negative_integer(candidate.start_unit, "candidate start unit")
    lsb_count = _validate_lsb_count(candidate.lsb_count)
    return StartMagicCandidate(start_unit, lsb_count)


# Resolves a candidate into header and layout.
def resolve_region2_candidate(carrier_units, candidate):
    carrier_units = _validate_carrier_units(carrier_units)
    candidate = _validate_v1_start_magic_candidate(candidate)
    prefix_bit_length = REGION2_PREFIX_SIZE * 8
    prefix_unit_count = ceil_unit_count(prefix_bit_length, candidate.lsb_count)
    prefix_end = candidate.start_unit + prefix_unit_count
    if candidate.start_unit >= carrier_units.size or prefix_end > carrier_units.size:
        raise ValueError("carrier does not contain the complete Region 2 prefix")
    prefix_bits = read_lsb_bits(
        carrier_units[candidate.start_unit:prefix_end],
        prefix_bit_length,
        candidate.lsb_count,
    )
    prefix = bit_sequence_to_bytes(prefix_bits)
    if prefix[:len(START_MAGIC)] != START_MAGIC:
        raise ValueError("candidate does not contain the start magic")
    header = parse_region2_header(prefix[len(START_MAGIC):REGION2_PREFIX_SIZE])
    if header.lsb_count != candidate.lsb_count:
        raise ValueError("header LSB count does not match candidate")
    region2_bit_length = calculate_region2_bit_length(header.payload_length, candidate.lsb_count)
    layout = build_region_layout(
        carrier_units.size,
        region2_bit_length,
        candidate.lsb_count,
        candidate.start_unit,
    )
    return ResolvedRegion2Candidate(candidate, header, layout)

# Validates the canonical PNG media context.
def validate_png_media_context(media_context, image_shape, carrier_unit_count):
    media_context = _validate_media_context(media_context)
    expected_context = encode_png_media_context(image_shape, carrier_unit_count)
    if media_context != expected_context:
        raise ValueError("PNG media context is not canonical for the carrier")
    return media_context


# Saves a validated RGB PNG.
def save_rgb_png_to_path(image_array, output_path):
    image_array = _validate_rgb_array(image_array)

    if not isinstance(output_path, (str, bytes, PathLike)):
        raise TypeError("output_path must be a filesystem path")
    try:
        Image.fromarray(image_array, mode="RGB").save(output_path, format="PNG")
    except (OSError, ValueError) as error:
        raise ValueError("could not save RGB PNG") from error


MAX_WAV_FRAME_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
# Represents validated uncompressed PCM WAV data.
class WavPcmData:
    channels: int
    sample_width: int
    frame_rate: int
    frame_count: int
    frame_bytes: bytes

    # Validates and normalizes PCM WAV fields.
    def __post_init__(self):
        channels = _validate_non_negative_integer(self.channels, "channels")
        if channels == 0:
            raise ValueError("channels must be positive")
        sample_width = _validate_non_negative_integer(self.sample_width, "sample_width")
        if sample_width not in range(1, 5):
            raise ValueError("sample_width must be between 1 and 4 bytes")
        frame_rate = _validate_non_negative_integer(self.frame_rate, "frame_rate")
        if frame_rate == 0:
            raise ValueError("frame_rate must be positive")
        frame_count = _validate_non_negative_integer(self.frame_count, "frame_count")
        frame_bytes = _require_bytes(self.frame_bytes, "frame_bytes")
        expected_length = frame_count * channels * sample_width
        if expected_length > MAX_WAV_FRAME_BYTES:
            raise ValueError("decoded WAV frame bytes exceed the version-1 limit")
        if len(frame_bytes) != expected_length:
            raise ValueError("frame_bytes length does not match WAV parameters")
        object.__setattr__(self, "channels", channels)
        object.__setattr__(self, "sample_width", sample_width)
        object.__setattr__(self, "frame_rate", frame_rate)
        object.__setattr__(self, "frame_count", frame_count)
        object.__setattr__(self, "frame_bytes", bytes(bytearray(frame_bytes)))


# Loads bounded uncompressed PCM WAV data.
def load_pcm_wav_from_path(path):

    if not isinstance(path, (str, bytes, PathLike)):
        raise TypeError("path must be a filesystem path")
    try:
        with wave.open(fspath(path), "rb") as wav_file:
            channels = _validate_non_negative_integer(wav_file.getnchannels(), "channels")
            sample_width = _validate_non_negative_integer(wav_file.getsampwidth(), "sample_width")
            frame_rate = _validate_non_negative_integer(wav_file.getframerate(), "frame_rate")
            frame_count = _validate_non_negative_integer(wav_file.getnframes(), "frame_count")
            if channels == 0 or frame_rate == 0:
                raise ValueError("WAV channels and frame rate must be positive")
            if sample_width not in range(1, 5):
                raise ValueError("WAV sample width must be between 1 and 4 bytes")
            expected_length = frame_count * channels * sample_width
            if expected_length > MAX_WAV_FRAME_BYTES:
                raise ValueError("decoded WAV frame bytes exceed the version-1 limit")
            if wav_file.getcomptype() != "NONE":
                raise ValueError("WAV must use uncompressed PCM")
            frame_bytes = wav_file.readframes(frame_count)
            if len(frame_bytes) != expected_length:
                raise ValueError("WAV frame data length is inconsistent")
            return WavPcmData(
                channels, sample_width, frame_rate, frame_count, frame_bytes
            )
    except ValueError:
        raise
    except (OSError, EOFError, wave.Error, struct.error) as error:
        raise ValueError("invalid or unreadable uncompressed PCM WAV") from error


# Copies WAV frame bytes into carrier units.
def wav_frame_bytes_to_carrier(frame_bytes):
    frame_bytes = _require_bytes(frame_bytes, "frame_bytes")
    return np.frombuffer(frame_bytes, dtype=np.uint8).copy()


# Converts carrier units into WAV frame bytes.
def carrier_to_wav_frame_bytes(carrier_units):
    carrier_units = _validate_carrier_units(carrier_units)
    return carrier_units.tobytes()

WAV_PCM_CONTEXT_DOMAIN = b"WAV-PCM\x00"
WAV_PCM_CONTEXT_FORMAT = ">HBIQ"
WAV_PCM_CONTEXT_SIZE = struct.calcsize(WAV_PCM_CONTEXT_FORMAT)


# Builds the canonical WAV media context.
def encode_wav_media_context(wav_data, carrier_unit_count):
    if not isinstance(wav_data, WavPcmData):
        raise TypeError("wav_data must be a WavPcmData")
    if wav_data.channels > 0xFFFF:
        raise ValueError("WAV channel count does not fit the context")
    if wav_data.frame_rate > 0xFFFFFFFF:
        raise ValueError("WAV frame rate does not fit the context")
    if wav_data.frame_count > (1 << 64) - 1:
        raise ValueError("WAV frame count does not fit the context")
    carrier_unit_count = _validate_uint64(carrier_unit_count, "carrier-unit count")
    expected_count = wav_data.frame_count * wav_data.channels * wav_data.sample_width
    if (
        carrier_unit_count != len(wav_data.frame_bytes)
        or carrier_unit_count != expected_count
    ):
        raise ValueError("carrier count does not match WAV frame bytes")
    return WAV_PCM_CONTEXT_DOMAIN + struct.pack(
        WAV_PCM_CONTEXT_FORMAT,
        wav_data.channels,
        wav_data.sample_width,
        wav_data.frame_rate,
        wav_data.frame_count,
    )


# Validates the canonical WAV media context.
def validate_wav_media_context(media_context, wav_data, carrier_unit_count):
    media_context = _validate_media_context(media_context)
    expected_context = encode_wav_media_context(wav_data, carrier_unit_count)
    if media_context != expected_context:
        raise ValueError("WAV media context is not canonical for the carrier")
    return media_context


# Rebuilds WAV data with copied carrier bytes.
def wav_data_with_carrier(wav_data, carrier_units):
    if not isinstance(wav_data, WavPcmData):
        raise TypeError("wav_data must be a WavPcmData")
    carrier_units = _validate_carrier_units(carrier_units)
    if carrier_units.size != len(wav_data.frame_bytes):
        raise ValueError("carrier length does not match WAV frame bytes")
    return WavPcmData(
        wav_data.channels,
        wav_data.sample_width,
        wav_data.frame_rate,
        wav_data.frame_count,
        carrier_units.tobytes(),
    )


# Saves validated uncompressed PCM WAV data.
def save_pcm_wav_to_path(wav_data, output_path):
    if not isinstance(wav_data, WavPcmData):
        raise TypeError("wav_data must be a WavPcmData")

    if not isinstance(output_path, (str, bytes, PathLike)):
        raise TypeError("output_path must be a filesystem path")
    try:
        with wave.open(fspath(output_path), "wb") as wav_file:
            wav_file.setnchannels(wav_data.channels)
            wav_file.setsampwidth(wav_data.sample_width)
            wav_file.setframerate(wav_data.frame_rate)
            wav_file.writeframes(wav_data.frame_bytes)
    except (OSError, EOFError, wave.Error, struct.error, ValueError) as error:
        raise ValueError("could not save uncompressed PCM WAV") from error


# Saves an assignment-demo RSA private key as PEM; this is not production key management.
def save_rsa_private_key_pem(private_key, path, password=None):
    """Save an assignment demo key as PKCS8 PEM, not production key management."""
    private_key = validate_rsa_private_key(private_key)
    encryption_algorithm = (
        serialization.NoEncryption()
        if password is None
        else serialization.BestAvailableEncryption(password)
    )
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    with open(path, "wb") as key_file:
        key_file.write(pem_bytes)


# Loads an assignment-demo RSA private key from PEM; this is not production key management.
def load_rsa_private_key_pem(path, password=None):
    """Load an assignment demo key from PKCS8 PEM, not production key management."""
    with open(path, "rb") as key_file:
        pem_bytes = key_file.read()
    private_key = serialization.load_pem_private_key(pem_bytes, password=password)
    return validate_rsa_private_key(private_key)


# Saves an assignment-demo RSA public key as PEM; this is not production key management.
def save_rsa_public_key_pem(public_key, path):
    """Save an assignment demo key as SubjectPublicKeyInfo PEM, not production key management."""
    public_key = validate_rsa_public_key(public_key)
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as key_file:
        key_file.write(pem_bytes)


# Loads an assignment-demo RSA public key from PEM; this is not production key management.
def load_rsa_public_key_pem(path):
    """Load an assignment demo key from SubjectPublicKeyInfo PEM, not production key management."""
    with open(path, "rb") as key_file:
        pem_bytes = key_file.read()
    public_key = serialization.load_pem_public_key(pem_bytes)
    return validate_rsa_public_key(public_key)

# Encodes a v1 payload and signature into carriers.
def encode_v1_carrier(
    carrier_units,
    media_type,
    media_context,
    private_key,
    start_unit,
    lsb_count,
    message,
    metadata,
):
    carrier_units = np.array(
        _validate_carrier_units(carrier_units), dtype=np.uint8, copy=True
    )
    media_type = _validate_media_type(media_type)
    media_context = _validate_media_context(media_context)
    private_key = validate_rsa_private_key(private_key)
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    zero_hash = bytes(SHA256_DIGEST_SIZE)
    provisional_payload = create_v1_payload_record(
        media_type,
        media_context,
        zero_hash,
        zero_hash,
        message,
        metadata,
    )
    provisional_payload_bytes = serialize_v1_payload(provisional_payload)
    provisional_stream = build_region2_stream(
        provisional_payload_bytes, lsb_count
    )
    region2_bit_length = calculate_region2_bit_length(
        len(provisional_payload_bytes), lsb_count
    )
    if len(provisional_stream) * 8 != region2_bit_length:
        raise ValueError("provisional Region 2 length is inconsistent")
    layout = build_region_layout(
        carrier_units.size, region2_bit_length, lsb_count, start_unit
    )

    unembedded_hash, reserved_upper_bits_hash = calculate_layout_hashes(
        carrier_units, layout
    )
    final_payload = V1PayloadRecord(
        media_type=provisional_payload.media_type,
        media_context=provisional_payload.media_context,
        unembedded_carrier_hash=unembedded_hash,
        reserved_upper_bits_hash=reserved_upper_bits_hash,
        media_id=provisional_payload.media_id,
        timestamp=provisional_payload.timestamp,
        nonce=provisional_payload.nonce,
        message=provisional_payload.message,
        metadata=provisional_payload.metadata,
    )
    final_stream = build_region2_stream(
        serialize_v1_payload(final_payload), lsb_count
    )
    if len(final_stream) != len(provisional_stream):
        raise ValueError("final Region 2 length differs from provisional length")
    if len(final_stream) * 8 != layout.region2_bit_length:
        raise ValueError("final Region 2 length does not match layout")

    region2_carrier = embed_region2_stream(carrier_units, layout, final_stream)
    region2_values = select_region2_units(region2_carrier, layout)
    signing_input = encode_region2_signing_input(
        media_type, media_context, layout, region2_values
    )
    signature = sign_v1_bytes(signing_input, private_key)
    final_carrier = embed_region3_signature(region2_carrier, layout, signature)
    return final_carrier, layout, final_payload

# Verifies one resolved v1 candidate.
def verify_resolved_v1_candidate(
    carrier_units,
    media_type,
    media_context,
    public_key,
    resolved_candidate,
):
    carrier_units = _validate_carrier_units(carrier_units)
    media_type = _validate_media_type(media_type)
    media_context = _validate_media_context(media_context)
    public_key = validate_rsa_public_key(public_key)
    if not isinstance(resolved_candidate, ResolvedRegion2Candidate):
        raise TypeError("resolved_candidate must be a ResolvedRegion2Candidate")

    resolved_again = resolve_region2_candidate(
        carrier_units, resolved_candidate.candidate
    )
    if resolved_again != resolved_candidate:
        raise ValueError("resolved candidate does not match the current carrier")

    region2_stream = extract_region2_stream(carrier_units, resolved_candidate.layout)
    parsed_header, payload_bytes = parse_region2_stream(region2_stream)
    if parsed_header != resolved_candidate.header:
        raise ValueError("parsed Region 2 header does not match resolved candidate")
    payload = parse_v1_payload(payload_bytes)
    if payload.media_type != media_type:
        raise ValueError("payload media type does not match expected media type")
    if payload.media_context != media_context:
        raise ValueError("payload media context does not match expected media context")

    signature = extract_region3_signature(carrier_units, resolved_candidate.layout)
    region2_values = select_region2_units(carrier_units, resolved_candidate.layout)
    signing_input = encode_region2_signing_input(
        media_type, media_context, resolved_candidate.layout, region2_values
    )
    if not verify_v1_signature(signing_input, signature, public_key):
        raise ValueError("Region 3 RSA-PSS signature verification failed")

    calculated_region1_hash, calculated_region3_hash = calculate_layout_hashes(
        carrier_units, resolved_candidate.layout
    )
    hash_mismatches = []
    if calculated_region1_hash != payload.unembedded_carrier_hash:
        hash_mismatches.append("Region 1 hash mismatch")
    if calculated_region3_hash != payload.reserved_upper_bits_hash:
        hash_mismatches.append("Region 3 hash mismatch")
    if hash_mismatches:
        raise ValueError("; ".join(hash_mismatches))
    return payload, public_key

@dataclass(frozen=True)
# Represents one immutable v1 verification result.
class V1VerificationResult:
    valid: bool
    verdict: str
    detail: str
    payload: V1PayloadRecord | None
    key_fingerprint: str | None
    candidate: StartMagicCandidate | None

    # Validates authenticated result field combinations.
    def __post_init__(self):
        if self.valid:
            if self.verdict != "Authentic":
                raise ValueError("valid result has an unsupported verdict")
            if self.payload is None or self.key_fingerprint is None or self.candidate is None:
                raise ValueError("valid result is missing authenticated fields")
        elif any(value is not None for value in (self.payload, self.key_fingerprint, self.candidate)):
            raise ValueError("invalid result must not expose authenticated fields")


# Scans, verifies, and classifies v1 carrier candidates.
def decode_v1_carrier(
    carrier_units,
    media_type,
    media_context,
    public_key,
):
    carrier_units = _validate_carrier_units(carrier_units)
    media_type = _validate_media_type(media_type)
    media_context = _validate_media_context(media_context)
    public_key = validate_rsa_public_key(public_key)

    try:
        candidates = scan_start_magic(carrier_units)
    except (TypeError, ValueError) as error:
        detail = "Scanner failure: " + " ".join(str(error).split())[:160]
        return V1VerificationResult(False, "Cannot Verify", detail, None, None, None)
    if not candidates:
        return V1VerificationResult(
            False,
            "Payload Missing",
            "No start-magic candidate was found.",
            None,
            None,
            None,
        )

    valid_results = []
    failure_errors = []
    for candidate in candidates:
        try:
            resolved_candidate = resolve_region2_candidate(carrier_units, candidate)
            payload, verified_public_key = verify_resolved_v1_candidate(
                carrier_units, media_type, media_context, public_key, resolved_candidate
            )
            valid_results.append((payload, verified_public_key, candidate))
        except (TypeError, ValueError) as error:
            reason = " ".join(str(error).split())[:120]
            if not reason:
                reason = error.__class__.__name__
            if isinstance(candidate, StartMagicCandidate):
                location = f"{candidate.start_unit}/{candidate.lsb_count}"
            else:
                location = "unknown"
            failure = f"candidate {location}: {reason}"
            if failure not in failure_errors:
                failure_errors.append(failure)

    if len(valid_results) > 1:
        return V1VerificationResult(
            False,
            "Cannot Verify",
            "Ambiguous valid candidates were found.",
            None,
            None,
            None,
        )
    if len(valid_results) == 1:
        payload, verified_public_key, candidate = valid_results[0]
        key_fingerprint = display_rsa_public_key_fingerprint(public_key)
        return V1VerificationResult(
            True,
            "Authentic",
            "Cryptographic checks passed under the supplied public key.",
            payload,
            key_fingerprint,
            candidate,
        )

    lowered_errors = [error.lower() for error in failure_errors]
    if any("hash mismatch" in error for error in lowered_errors):
        verdict = "Tampered"
    elif any("padding" in error for error in lowered_errors):
        verdict = "Tampered"
    elif any("signature" in error for error in lowered_errors):
        verdict = "Signature Invalid"
    else:
        verdict = "Cannot Verify"
    detail = "; ".join(failure_errors[:8])
    if not detail:
        detail = "No candidate passed verification."
    return V1VerificationResult(False, verdict, detail, None, None, None)

# Checks whether two paths resolve to the same file.
def _paths_resolve_same(first_path, second_path):

    for path in (first_path, second_path):
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
    first = os.fsdecode(fspath(first_path))
    second = os.fsdecode(fspath(second_path))
    return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(second))


# Encodes and saves a v1 PNG through fixed adapters.
def encode_png_v1(
    input_path,
    output_path,
    private_key,
    start_unit,
    lsb_count,
    message,
    metadata,
):
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    image_array = load_png_from_path(input_path)
    carrier_units = rgb_array_to_carrier(image_array)
    media_context = encode_png_media_context(image_array.shape, carrier_units.size)
    encoded_carrier, layout, payload = encode_v1_carrier(
        carrier_units,
        IMAGE_MEDIA_CODE,
        media_context,
        private_key,
        start_unit,
        lsb_count,
        message,
        metadata,
    )
    save_rgb_png_to_path(
        carrier_to_rgb_array(encoded_carrier, image_array.shape), output_path
    )
    return layout, payload


# Loads and verifies a v1 PNG through fixed adapters.
def verify_png_v1(input_path, public_key):
    image_array = load_png_from_path(input_path)
    carrier_units = rgb_array_to_carrier(image_array)
    media_context = encode_png_media_context(image_array.shape, carrier_units.size)
    return decode_v1_carrier(
        carrier_units, IMAGE_MEDIA_CODE, media_context, public_key
    )


# Encodes and saves a v1 WAV through fixed adapters.
def encode_wav_v1(
    input_path,
    output_path,
    private_key,
    start_unit,
    lsb_count,
    message,
    metadata,
):
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    wav_data = load_pcm_wav_from_path(input_path)
    carrier_units = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
    media_context = encode_wav_media_context(wav_data, carrier_units.size)
    encoded_carrier, layout, payload = encode_v1_carrier(
        carrier_units,
        AUDIO_MEDIA_CODE,
        media_context,
        private_key,
        start_unit,
        lsb_count,
        message,
        metadata,
    )
    save_pcm_wav_to_path(
        wav_data_with_carrier(wav_data, encoded_carrier), output_path
    )
    return layout, payload


# Loads and verifies a v1 WAV through fixed adapters.
def verify_wav_v1(input_path, public_key):
    wav_data = load_pcm_wav_from_path(input_path)
    carrier_units = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
    media_context = encode_wav_media_context(wav_data, carrier_units.size)
    return decode_v1_carrier(
        carrier_units, AUDIO_MEDIA_CODE, media_context, public_key
    )
