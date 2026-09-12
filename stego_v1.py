"""Version-1 masked-media steganography for strict RGB PNG and PCM WAV files.

Invariant: every carrier bit that embedding intentionally preserves is represented
in the masked media hash. The signed payload contains that hash and the user
content. The signature also binds the media interpretation and embedding layout.
RSA-PSS verification validates the signature bytes themselves.
"""

import base64
import hashlib
import os
import secrets
import struct
import wave
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike, fspath

import numpy as np
from PIL import Image
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
RSA_SIGNATURE_SIZE = RSA_KEY_SIZE // 8
RSA_PSS_SALT_LENGTH = 32
PROTOCOL_VERSION = 1
START_MAGIC = bytes.fromhex("d9df721b281169d4335290e30fdb48b1")
SUPPORTED_LSB_COUNTS = tuple(range(1, 9))
SELECTED_LSB_BIT_ORDER = "MSB-first; selected LSBs from bit k-1 down to bit 0"

IMAGE_MEDIA_CODE = 1
AUDIO_MEDIA_CODE = 2
SUPPORTED_MEDIA_CODES = (IMAGE_MEDIA_CODE, AUDIO_MEDIA_CODE)
MEDIA_PREFIXES = {IMAGE_MEDIA_CODE: "IMG", AUDIO_MEDIA_CODE: "AUD"}

SHA256_DIGEST_SIZE = 32
MEDIA_HASH_DOMAIN = b"INF2005-ACW1\x00MEDIA-HASH\x00"
SIGNING_DOMAIN = b"INF2005-ACW1\x00SIGN\x00"
MEDIA_HASH_CONTEXT_FORMAT = ">BBQQQ"
SIGNING_CONTEXT_FORMAT = ">BBBQQQI"

PACKET_HEADER_FORMAT = ">16sBBBI"
PACKET_HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)
MAX_PAYLOAD_LENGTH = 16 * 1024 * 1024
V1_NONCE_SIZE = 16
MAX_MEDIA_ID_BYTES = 255
MAX_MAGIC_CANDIDATES = 64

PNG_CARRIER_MODE = "RGB"
RGB_CHANNEL_COUNT = 3
PNG_MEDIA_CONTEXT_FORMAT = ">II"
WAV_MEDIA_CONTEXT_FORMAT = ">HBIQ"
MAX_WAV_FRAME_BYTES = 64 * 1024 * 1024

MAX_PUBLIC_KEY_ENCODING_LENGTH = 512
FINGERPRINT_DISPLAY_PREFIX = "SHA256:"


class UnSupportedFileType(Exception):
    """Marks an unsupported file type."""


def _validate_non_negative_integer(value, name):
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} must be an integer")
    value = int(value)
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _validate_positive_integer(value, name):
    value = _validate_non_negative_integer(value, name)
    if value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _validate_uint64(value, name):
    value = _validate_non_negative_integer(value, name)
    if value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{name} must fit in unsigned 64 bits")
    return value


def _validate_lsb_count(lsb_count):
    if isinstance(lsb_count, (bool, np.bool_)) or not isinstance(lsb_count, (int, np.integer)):
        raise TypeError("lsb_count must be an integer")
    lsb_count = int(lsb_count)
    if lsb_count not in SUPPORTED_LSB_COUNTS:
        raise ValueError("lsb_count must be between 1 and 8")
    return lsb_count


def _validate_media_code(media_code):
    if isinstance(media_code, (bool, np.bool_)) or not isinstance(media_code, (int, np.integer)):
        raise TypeError("media_code must be an integer")
    media_code = int(media_code)
    if media_code not in SUPPORTED_MEDIA_CODES:
        raise ValueError("unsupported media code")
    return media_code


def _require_bytes(value, name):
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def _validate_carrier_units(carrier_units):
    if not isinstance(carrier_units, np.ndarray):
        raise TypeError("carrier_units must be a numpy array")
    if carrier_units.dtype != np.uint8:
        raise TypeError("carrier_units must have dtype uint8")
    if carrier_units.ndim != 1:
        raise ValueError("carrier_units must be one-dimensional")
    return carrier_units


def _validate_bit_sequence(bit_sequence, byte_aligned=False):
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
    data = _require_bytes(data, "data")
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big").astype(np.uint8, copy=True)


def bit_sequence_to_bytes(bit_sequence):
    _validate_bit_sequence(bit_sequence, byte_aligned=True)
    return np.packbits(bit_sequence, bitorder="big").tobytes()


def write_lsb_bits(carrier_units, bit_sequence, lsb_count):
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


def ceil_unit_count(bit_length, lsb_count):
    bit_length = _validate_non_negative_integer(bit_length, "bit_length")
    lsb_count = _validate_lsb_count(lsb_count)
    return (bit_length + lsb_count - 1) // lsb_count


@dataclass(frozen=True)
class EmbeddingLayout:
    total_units: int
    start_unit: int
    footprint: int
    lsb_count: int
    payload_length: int
    pad_bits: int


def build_embedding_layout(total_units, start_unit, lsb_count, payload_length):
    total_units = _validate_uint64(total_units, "total_units")
    start_unit = _validate_uint64(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    payload_length = validate_payload_length(payload_length)
    packet_bits = (PACKET_HEADER_SIZE + payload_length + RSA_SIGNATURE_SIZE) * 8
    footprint = ceil_unit_count(packet_bits, lsb_count)
    pad_bits = footprint * lsb_count - packet_bits
    if start_unit + footprint > total_units:
        raise ValueError("embedding footprint does not fit after start_unit")
    return EmbeddingLayout(total_units, start_unit, footprint, lsb_count, payload_length, pad_bits)


def preserved_bit_count(total_units, footprint, lsb_count):
    total_units = _validate_uint64(total_units, "total_units")
    footprint = _validate_uint64(footprint, "footprint")
    lsb_count = _validate_lsb_count(lsb_count)
    if footprint > total_units:
        raise ValueError("footprint exceeds total_units")
    return 8 * (total_units - footprint) + (8 - lsb_count) * footprint


def calculate_masked_media_hash(carrier_units, media_code, lsb_count, start_unit, footprint):
    """Hash all intentionally preserved carrier bits without expanding them to bits."""
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    lsb_count = _validate_lsb_count(lsb_count)
    total_units = _validate_uint64(carrier_units.size, "total_units")
    start_unit = _validate_uint64(start_unit, "start_unit")
    footprint = _validate_uint64(footprint, "footprint")
    if start_unit + footprint > total_units:
        raise ValueError("masked media footprint is out of range")
    masked = carrier_units.copy()
    mask = (~((1 << lsb_count) - 1)) & 0xFF
    masked[start_unit:start_unit + footprint] &= np.uint8(mask)
    preimage = (
        MEDIA_HASH_DOMAIN
        + struct.pack(MEDIA_HASH_CONTEXT_FORMAT, media_code, lsb_count, total_units, start_unit, footprint)
        + masked.tobytes()
    )
    return hashlib.sha256(preimage).digest()


def encode_signing_input(media_code, media_context, layout, payload_bytes):
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    if not isinstance(layout, EmbeddingLayout):
        raise TypeError("layout must be an EmbeddingLayout")
    payload_bytes = validate_payload_bytes(payload_bytes)
    if len(payload_bytes) != layout.payload_length:
        raise ValueError("payload length does not match layout")
    return (
        SIGNING_DOMAIN
        + struct.pack(
            SIGNING_CONTEXT_FORMAT,
            PROTOCOL_VERSION,
            media_code,
            layout.lsb_count,
            layout.total_units,
            layout.start_unit,
            layout.footprint,
            layout.payload_length,
        )
        + media_context
        + payload_bytes
    )


def validate_payload_length(payload_length):
    payload_length = _validate_non_negative_integer(payload_length, "payload_length")
    if payload_length > MAX_PAYLOAD_LENGTH:
        raise ValueError("payload exceeds the version-1 payload limit")
    if payload_length > 0xFFFFFFFF:
        raise ValueError("payload length does not fit the header")
    return payload_length


def validate_payload_bytes(payload_bytes):
    payload_bytes = _require_bytes(payload_bytes, "payload_bytes")
    validate_payload_length(len(payload_bytes))
    return bytes(payload_bytes)


@dataclass(frozen=True)
class PacketHeader:
    version: int
    lsb_count: int
    media_code: int
    payload_length: int


def serialize_packet_header(lsb_count, media_code, payload_length):
    return struct.pack(
        PACKET_HEADER_FORMAT,
        START_MAGIC,
        PROTOCOL_VERSION,
        _validate_lsb_count(lsb_count),
        _validate_media_code(media_code),
        validate_payload_length(payload_length),
    )


def parse_packet_header(header_bytes):
    header_bytes = _require_bytes(header_bytes, "header_bytes")
    if len(header_bytes) != PACKET_HEADER_SIZE:
        raise ValueError("header must contain exactly 23 bytes")
    magic, version, lsb_count, media_code, payload_length = struct.unpack(PACKET_HEADER_FORMAT, header_bytes)
    if magic != START_MAGIC:
        raise ValueError("header has the wrong start magic")
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    return PacketHeader(version, _validate_lsb_count(lsb_count), _validate_media_code(media_code), validate_payload_length(payload_length))


@dataclass(frozen=True)
class V1PayloadRecord:
    media_id: str
    timestamp: int
    nonce: bytes
    media_hash: bytes
    user_payload: bytes
    metadata: bytes

    def __post_init__(self):
        if not isinstance(self.media_id, str):
            raise TypeError("media_id must be text")
        media_id_bytes = self.media_id.encode("utf-8")
        if not media_id_bytes or len(media_id_bytes) > MAX_MEDIA_ID_BYTES:
            raise ValueError("media_id UTF-8 length must be between 1 and 255 bytes")
        timestamp = _validate_uint64(self.timestamp, "timestamp")
        nonce = _require_bytes(self.nonce, "nonce")
        media_hash = _require_bytes(self.media_hash, "media_hash")
        user_payload = _require_bytes(self.user_payload, "user_payload")
        metadata = _require_bytes(self.metadata, "metadata")
        if len(nonce) != V1_NONCE_SIZE:
            raise ValueError("nonce must contain exactly 16 bytes")
        if len(media_hash) != SHA256_DIGEST_SIZE:
            raise ValueError("media_hash must contain exactly 32 bytes")
        if len(user_payload) > 0xFFFFFFFF or len(metadata) > 0xFFFFFFFF:
            raise ValueError("payload field length exceeds unsigned 32-bit range")
        try:
            metadata.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("metadata must contain valid UTF-8 bytes") from error
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "nonce", bytes(nonce))
        object.__setattr__(self, "media_hash", bytes(media_hash))
        object.__setattr__(self, "user_payload", bytes(user_payload))
        object.__setattr__(self, "metadata", bytes(metadata))


def serialize_v1_payload(record):
    if not isinstance(record, V1PayloadRecord):
        raise TypeError("record must be a V1PayloadRecord")
    media_id = record.media_id.encode("utf-8")
    payload = (
        bytes((len(media_id),))
        + media_id
        + struct.pack(">Q", record.timestamp)
        + record.nonce
        + record.media_hash
        + struct.pack(">I", len(record.user_payload))
        + record.user_payload
        + struct.pack(">I", len(record.metadata))
        + record.metadata
    )
    return validate_payload_bytes(payload)


def _take_payload_field(payload_bytes, offset, length, name):
    end = offset + length
    if end > len(payload_bytes):
        raise ValueError(f"payload is truncated in {name}")
    return payload_bytes[offset:end], end


def parse_v1_payload(payload_bytes):
    payload_bytes = validate_payload_bytes(payload_bytes)
    if not payload_bytes:
        raise ValueError("payload is truncated before media_id length")
    media_id_length = payload_bytes[0]
    offset = 1
    media_id_bytes, offset = _take_payload_field(payload_bytes, offset, media_id_length, "media_id")
    fixed, offset = _take_payload_field(payload_bytes, offset, 8 + V1_NONCE_SIZE + SHA256_DIGEST_SIZE, "fixed fields")
    timestamp = struct.unpack(">Q", fixed[:8])[0]
    nonce = fixed[8:24]
    media_hash = fixed[24:56]
    user_length_bytes, offset = _take_payload_field(payload_bytes, offset, 4, "user length")
    user_length = struct.unpack(">I", user_length_bytes)[0]
    user_payload, offset = _take_payload_field(payload_bytes, offset, user_length, "user payload")
    metadata_length_bytes, offset = _take_payload_field(payload_bytes, offset, 4, "metadata length")
    metadata_length = struct.unpack(">I", metadata_length_bytes)[0]
    metadata, offset = _take_payload_field(payload_bytes, offset, metadata_length, "metadata")
    if offset != len(payload_bytes):
        raise ValueError("payload contains trailing bytes")
    try:
        media_id = media_id_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("media_id must contain valid UTF-8") from error
    return V1PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)


def create_v1_payload_record(media_code, media_hash, user_payload, metadata):
    media_code = _validate_media_code(media_code)
    media_id = f"{MEDIA_PREFIXES[media_code]}-{secrets.token_hex(16)}"
    timestamp = int(datetime.now(timezone.utc).timestamp())
    return V1PayloadRecord(media_id, timestamp, secrets.token_bytes(V1_NONCE_SIZE), media_hash, user_payload, metadata)


@dataclass(frozen=True)
class StartMagicCandidate:
    start_unit: int
    lsb_count: int


def _magic_unit_masks_and_values(lsb_count):
    lsb_count = _validate_lsb_count(lsb_count)
    magic_bits = bytes_to_bit_sequence(START_MAGIC)
    unit_count = ceil_unit_count(magic_bits.size, lsb_count)
    masks = np.zeros(unit_count, dtype=np.uint8)
    values = np.zeros(unit_count, dtype=np.uint8)
    for bit_index, bit in enumerate(magic_bits):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        masks[unit_index] |= np.uint8(1 << position)
        values[unit_index] |= np.uint8(int(bit) << position)
    return masks, values


def _find_magic_start_mask(carrier_units, lsb_count):
    carrier_units = _validate_carrier_units(carrier_units)
    masks, values = _magic_unit_masks_and_values(lsb_count)
    if carrier_units.size < masks.size:
        return np.empty(0, dtype=bool), 0
    candidate_count = carrier_units.size - masks.size + 1
    matches = np.ones(candidate_count, dtype=bool)
    for offset in range(masks.size):
        matches &= (carrier_units[offset:offset + candidate_count] & masks[offset]) == values[offset]
    return matches, int(np.count_nonzero(matches))


def scan_start_magic_for_lsb(carrier_units, lsb_count, max_candidates=MAX_MAGIC_CANDIDATES):
    carrier_units = _validate_carrier_units(carrier_units)
    lsb_count = _validate_lsb_count(lsb_count)
    max_candidates = _validate_positive_integer(max_candidates, "max_candidates")
    matches, count = _find_magic_start_mask(carrier_units, lsb_count)
    if count > max_candidates:
        raise ValueError("magic candidate limit exceeded")
    return tuple(StartMagicCandidate(int(start), lsb_count) for start in np.flatnonzero(matches))


def scan_start_magic(carrier_units, max_candidates=MAX_MAGIC_CANDIDATES):
    carrier_units = _validate_carrier_units(carrier_units)
    max_candidates = _validate_positive_integer(max_candidates, "max_candidates")
    candidates = []
    for lsb_count in SUPPORTED_LSB_COUNTS:
        matches, count = _find_magic_start_mask(carrier_units, lsb_count)
        if count > max_candidates - len(candidates):
            raise ValueError("magic candidate limit exceeded")
        candidates.extend(StartMagicCandidate(int(start), lsb_count) for start in np.flatnonzero(matches))
    return tuple(sorted(candidates, key=lambda item: (item.start_unit, item.lsb_count)))


def validate_rsa_public_key(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")
    if public_key.key_size != RSA_KEY_SIZE:
        raise ValueError("public_key must be RSA-2048")
    if public_key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("public_key exponent must be 65537")
    return public_key


def validate_rsa_private_key(private_key):
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")
    if private_key.key_size != RSA_KEY_SIZE:
        raise ValueError("private_key must be RSA-2048")
    if private_key.private_numbers().public_numbers.e != RSA_PUBLIC_EXPONENT:
        raise ValueError("private_key exponent must be 65537")
    return private_key


def generate_v1_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def serialize_rsa_public_key(public_key):
    public_key = validate_rsa_public_key(public_key)
    encoded = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if len(encoded) > MAX_PUBLIC_KEY_ENCODING_LENGTH:
        raise ValueError("canonical public-key encoding exceeds the limit")
    return encoded


def parse_rsa_public_key(encoded):
    encoded = _require_bytes(encoded, "encoded public key")
    if not encoded or len(encoded) > MAX_PUBLIC_KEY_ENCODING_LENGTH:
        raise ValueError("encoded public key has an invalid length")
    try:
        public_key = serialization.load_der_public_key(encoded)
    except (TypeError, ValueError) as error:
        raise ValueError("encoded public key is not valid DER") from error
    validate_rsa_public_key(public_key)
    if serialize_rsa_public_key(public_key) != encoded:
        raise ValueError("encoded public key is not canonical DER")
    return public_key


def fingerprint_rsa_public_key(public_key):
    return hashlib.sha256(serialize_rsa_public_key(public_key)).digest()


def display_rsa_public_key_fingerprint(public_key):
    encoded = base64.b64encode(fingerprint_rsa_public_key(public_key)).decode("ascii").rstrip("=")
    return FINGERPRINT_DISPLAY_PREFIX + encoded


def v1_rsa_pss_padding():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=RSA_PSS_SALT_LENGTH)


def sign_v1_bytes(signing_input, private_key):
    signing_input = _require_bytes(signing_input, "signing_input")
    signature = validate_rsa_private_key(private_key).sign(signing_input, v1_rsa_pss_padding(), hashes.SHA256())
    if len(signature) != RSA_SIGNATURE_SIZE:
        raise ValueError("RSA signature has an unexpected length")
    return signature


def verify_v1_signature(signing_input, signature, public_key):
    signing_input = _require_bytes(signing_input, "signing_input")
    signature = _require_bytes(signature, "signature")
    public_key = validate_rsa_public_key(public_key)
    if len(signature) != RSA_SIGNATURE_SIZE:
        return False
    try:
        public_key.verify(signature, signing_input, v1_rsa_pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def save_rsa_private_key_pem(private_key, path, password=None):
    private_key = validate_rsa_private_key(private_key)
    algorithm = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    with open(path, "wb") as key_file:
        key_file.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm))


def load_rsa_private_key_pem(path, password=None):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=password)
    return validate_rsa_private_key(private_key)


def save_rsa_public_key_pem(public_key, path):
    public_key = validate_rsa_public_key(public_key)
    with open(path, "wb") as key_file:
        key_file.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_rsa_public_key_pem(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return validate_rsa_public_key(public_key)


def _validate_rgb_array(image_array):
    if not isinstance(image_array, np.ndarray):
        raise TypeError("image_array must be a numpy array")
    if image_array.dtype != np.uint8:
        raise TypeError("image_array must have dtype uint8")
    if image_array.ndim != 3 or image_array.shape[2] != RGB_CHANNEL_COUNT:
        raise ValueError("image_array must have shape (height, width, 3)")
    if image_array.shape[0] < 1 or image_array.shape[1] < 1:
        raise ValueError("image dimensions must be greater than zero")
    return image_array


def _validate_rgb_png_header(image_path):
    with open(image_path, "rb") as image_file:
        header = image_file.read(33)
    if len(header) != 33 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        raise ValueError("invalid PNG header")
    chunk_length = struct.unpack(">I", header[8:12])[0]
    if chunk_length != 13:
        raise ValueError("invalid PNG IHDR chunk")
    _, _, _, _, bit_depth, colour_type, compression, filter_method, _ = struct.unpack(">I4sIIBBBBB", header[8:29])
    if bit_depth != 8 or colour_type != 2:
        raise ValueError("PNG must use 8-bit RGB samples")
    if compression != 0 or filter_method != 0:
        raise ValueError("unsupported PNG encoding")


def load_png_from_path(image_path):
    if not isinstance(image_path, (str, bytes, PathLike)):
        raise TypeError("image_path must be a filesystem path")
    try:
        with Image.open(image_path) as image:
            if image.format != "PNG":
                raise UnSupportedFileType(f"unsupported file type: {image.format or 'unknown'}")
            if getattr(image, "is_animated", False) or getattr(image, "n_frames", 1) != 1:
                raise ValueError("animated PNG images are not supported")
            if image.mode != PNG_CARRIER_MODE:
                raise ValueError("PNG must be RGB without alpha or palette conversion")
            _validate_rgb_png_header(image_path)
            image.load()
            return _validate_rgb_array(np.array(image, dtype=np.uint8, copy=True))
    except UnSupportedFileType:
        raise
    except (OSError, ValueError) as error:
        raise ValueError("unreadable or unsupported RGB PNG image") from error


def rgb_array_to_carrier(image_array):
    return np.array(_validate_rgb_array(image_array), dtype=np.uint8, order="C", copy=True).reshape(-1).copy()


def carrier_to_rgb_array(carrier_sequence, shape):
    carrier_sequence = _validate_carrier_units(carrier_sequence)
    try:
        shape = tuple(shape)
    except TypeError as error:
        raise TypeError("shape must be a three-dimensional sequence") from error
    if len(shape) != 3 or shape[2] != RGB_CHANNEL_COUNT or any(not isinstance(value, (int, np.integer)) or value < 1 for value in shape):
        raise ValueError("shape must contain positive (height, width, 3) dimensions")
    if carrier_sequence.size != int(np.prod(shape, dtype=np.int64)):
        raise ValueError("carrier_sequence length does not match shape")
    return carrier_sequence.copy().reshape(shape)


def encode_png_media_context(image_shape, carrier_unit_count=None):
    try:
        height, width, channels = tuple(image_shape)
    except (TypeError, ValueError) as error:
        raise ValueError("image_shape must be (height, width, 3)") from error
    if channels != RGB_CHANNEL_COUNT or height < 1 or width < 1 or height > 0xFFFFFFFF or width > 0xFFFFFFFF:
        raise ValueError("image_shape must be bounded (height, width, 3)")
    if carrier_unit_count is not None and carrier_unit_count != height * width * channels:
        raise ValueError("carrier count does not match PNG dimensions")
    return struct.pack(PNG_MEDIA_CONTEXT_FORMAT, width, height)


def save_rgb_png_to_path(image_array, output_path):
    image_array = _validate_rgb_array(image_array)
    if not isinstance(output_path, (str, bytes, PathLike)):
        raise TypeError("output_path must be a filesystem path")
    try:
        Image.fromarray(image_array, mode="RGB").save(output_path, format="PNG")
    except (OSError, ValueError) as error:
        raise ValueError("could not save RGB PNG") from error


@dataclass(frozen=True)
class WavPcmData:
    channels: int
    sample_width: int
    frame_rate: int
    frame_count: int
    frame_bytes: bytes

    def __post_init__(self):
        channels = _validate_positive_integer(self.channels, "channels")
        sample_width = _validate_positive_integer(self.sample_width, "sample_width")
        frame_rate = _validate_positive_integer(self.frame_rate, "frame_rate")
        frame_count = _validate_non_negative_integer(self.frame_count, "frame_count")
        frame_bytes = _require_bytes(self.frame_bytes, "frame_bytes")
        if sample_width not in range(1, 5):
            raise ValueError("sample_width must be between 1 and 4 bytes")
        expected = channels * sample_width * frame_count
        if expected > MAX_WAV_FRAME_BYTES or len(frame_bytes) != expected:
            raise ValueError("frame_bytes length does not match WAV parameters")
        object.__setattr__(self, "channels", channels)
        object.__setattr__(self, "sample_width", sample_width)
        object.__setattr__(self, "frame_rate", frame_rate)
        object.__setattr__(self, "frame_count", frame_count)
        object.__setattr__(self, "frame_bytes", bytes(frame_bytes))


def load_pcm_wav_from_path(path):
    if not isinstance(path, (str, bytes, PathLike)):
        raise TypeError("path must be a filesystem path")
    try:
        with wave.open(fspath(path), "rb") as wav_file:
            channels = wav_file.getnchannels()
            sample_width = wav_file.getsampwidth()
            frame_rate = wav_file.getframerate()
            frame_count = wav_file.getnframes()
            if wav_file.getcomptype() != "NONE":
                raise ValueError("WAV must use uncompressed PCM")
            if frame_count * channels * sample_width > MAX_WAV_FRAME_BYTES:
                raise ValueError("decoded WAV frame bytes exceed the version-1 limit")
            frame_bytes = wav_file.readframes(frame_count)
            return WavPcmData(channels, sample_width, frame_rate, frame_count, frame_bytes)
    except ValueError:
        raise
    except (OSError, EOFError, wave.Error, struct.error) as error:
        raise ValueError("invalid or unreadable uncompressed PCM WAV") from error


def wav_frame_bytes_to_carrier(frame_bytes):
    return np.frombuffer(_require_bytes(frame_bytes, "frame_bytes"), dtype=np.uint8).copy()


def carrier_to_wav_frame_bytes(carrier_units):
    return _validate_carrier_units(carrier_units).tobytes()


def encode_wav_media_context(wav_data, carrier_unit_count=None):
    if not isinstance(wav_data, WavPcmData):
        raise TypeError("wav_data must be a WavPcmData")
    if wav_data.channels > 0xFFFF or wav_data.sample_width > 0xFF or wav_data.frame_rate > 0xFFFFFFFF or wav_data.frame_count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("WAV values do not fit the media context")
    if carrier_unit_count is not None and carrier_unit_count != len(wav_data.frame_bytes):
        raise ValueError("carrier count does not match WAV frame bytes")
    return struct.pack(WAV_MEDIA_CONTEXT_FORMAT, wav_data.channels, wav_data.sample_width, wav_data.frame_rate, wav_data.frame_count)


def wav_data_with_carrier(wav_data, carrier_units):
    if not isinstance(wav_data, WavPcmData):
        raise TypeError("wav_data must be a WavPcmData")
    carrier_units = _validate_carrier_units(carrier_units)
    if carrier_units.size != len(wav_data.frame_bytes):
        raise ValueError("carrier length does not match WAV frame bytes")
    return WavPcmData(wav_data.channels, wav_data.sample_width, wav_data.frame_rate, wav_data.frame_count, carrier_units.tobytes())


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


def _embed_packet(carrier_units, layout, packet):
    packet = _require_bytes(packet, "packet")
    packet_bits = bytes_to_bit_sequence(packet)
    bits = np.zeros(layout.footprint * layout.lsb_count, dtype=np.uint8)
    bits[:packet_bits.size] = packet_bits
    result = carrier_units.copy()
    start = layout.start_unit
    end = start + layout.footprint
    result[start:end] = write_lsb_bits(result[start:end], bits, layout.lsb_count)
    return result


def encode_v1_carrier(carrier_units, media_code, media_context, private_key, start_unit, lsb_count, user_payload, metadata):
    carrier_units = _validate_carrier_units(carrier_units).copy()
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    private_key = validate_rsa_private_key(private_key)
    start_unit = _validate_uint64(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    user_payload = _require_bytes(user_payload, "user_payload")
    metadata = _require_bytes(metadata, "metadata")
    try:
        metadata.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("metadata must contain valid UTF-8 bytes") from error

    media_id = f"{MEDIA_PREFIXES[media_code]}-{secrets.token_hex(16)}"
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = secrets.token_bytes(V1_NONCE_SIZE)
    payload_length = 1 + len(media_id.encode("utf-8")) + 8 + 16 + 32 + 4 + len(user_payload) + 4 + len(metadata)
    layout = build_embedding_layout(carrier_units.size, start_unit, lsb_count, payload_length)
    media_hash = calculate_masked_media_hash(carrier_units, media_code, lsb_count, start_unit, layout.footprint)
    payload = V1PayloadRecord(media_id, timestamp, nonce, media_hash, user_payload, metadata)
    payload_bytes = serialize_v1_payload(payload)
    signing_input = encode_signing_input(media_code, media_context, layout, payload_bytes)
    signature = sign_v1_bytes(signing_input, private_key)
    packet = serialize_packet_header(lsb_count, media_code, len(payload_bytes)) + payload_bytes + signature
    return _embed_packet(carrier_units, layout, packet), layout, payload


class WrongStartLocationError(ValueError):
    pass


class SignatureVerificationError(ValueError):
    pass


class MediaHashMismatchError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedCandidate:
    candidate: StartMagicCandidate
    header: PacketHeader
    layout: EmbeddingLayout


def resolve_candidate(carrier_units, candidate, expected_media_code):
    carrier_units = _validate_carrier_units(carrier_units)
    if not isinstance(candidate, StartMagicCandidate):
        raise TypeError("candidate must be a StartMagicCandidate")
    expected_media_code = _validate_media_code(expected_media_code)
    header_units = ceil_unit_count(PACKET_HEADER_SIZE * 8, candidate.lsb_count)
    if candidate.start_unit + header_units > carrier_units.size:
        raise WrongStartLocationError("candidate header is out of range")
    header_bits = read_lsb_bits(carrier_units[candidate.start_unit:candidate.start_unit + header_units], PACKET_HEADER_SIZE * 8, candidate.lsb_count)
    header = parse_packet_header(bit_sequence_to_bytes(header_bits))
    if header.lsb_count != candidate.lsb_count:
        raise ValueError("header LSB count does not match scanned LSB count")
    if header.media_code != expected_media_code:
        raise ValueError("header media code does not match adapter media code")
    try:
        layout = build_embedding_layout(carrier_units.size, candidate.start_unit, candidate.lsb_count, header.payload_length)
    except ValueError as error:
        if "does not fit" in str(error):
            raise WrongStartLocationError("declared embedding footprint is out of range") from error
        raise
    return ResolvedCandidate(candidate, header, layout)


def verify_resolved_v1_candidate(carrier_units, media_code, media_context, public_key, resolved):
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    public_key = validate_rsa_public_key(public_key)
    if not isinstance(resolved, ResolvedCandidate):
        raise TypeError("resolved must be a ResolvedCandidate")
    layout = resolved.layout
    packet_bits_length = (PACKET_HEADER_SIZE + layout.payload_length + RSA_SIGNATURE_SIZE) * 8
    all_bits = read_lsb_bits(carrier_units[layout.start_unit:layout.start_unit + layout.footprint], layout.footprint * layout.lsb_count, layout.lsb_count)
    if np.any(all_bits[packet_bits_length:] != 0):
        raise ValueError("alignment padding must be zero")
    packet = bit_sequence_to_bytes(all_bits[:packet_bits_length])
    header = parse_packet_header(packet[:PACKET_HEADER_SIZE])
    if header != resolved.header:
        raise ValueError("packet header changed after candidate resolution")
    payload_start = PACKET_HEADER_SIZE
    payload_end = payload_start + header.payload_length
    payload_bytes = packet[payload_start:payload_end]
    payload = parse_v1_payload(payload_bytes)
    signature = packet[payload_end:]
    signing_input = encode_signing_input(media_code, media_context, layout, payload_bytes)
    if not verify_v1_signature(signing_input, signature, public_key):
        raise SignatureVerificationError("RSA-PSS signature verification failed")
    calculated_hash = calculate_masked_media_hash(carrier_units, media_code, layout.lsb_count, layout.start_unit, layout.footprint)
    if calculated_hash != payload.media_hash:
        raise MediaHashMismatchError("masked media hash mismatch")
    return payload


@dataclass(frozen=True)
class V1VerificationResult:
    valid: bool
    verdict: str
    detail: str
    payload: V1PayloadRecord | None
    key_fingerprint: str | None
    start_unit: int | None
    lsb_count: int | None
    preserved_bits: int | None
    preserved_ratio: float | None


def _failure_result(verdict, detail):
    return V1VerificationResult(False, verdict, detail, None, None, None, None, None, None)


def decode_v1_carrier(carrier_units, media_code, media_context, public_key):
    carrier_units = _validate_carrier_units(carrier_units)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    public_key = validate_rsa_public_key(public_key)
    try:
        candidates = scan_start_magic(carrier_units)
    except ValueError as error:
        return _failure_result("Cannot Verify", f"scanner failure: {error}")
    if not candidates:
        return _failure_result("Payload Missing", "no start-magic candidate was found")

    valid = []
    failures = []
    for candidate in candidates:
        try:
            resolved = resolve_candidate(carrier_units, candidate, media_code)
            payload = verify_resolved_v1_candidate(carrier_units, media_code, media_context, public_key, resolved)
            valid.append((payload, resolved.layout))
        except WrongStartLocationError as error:
            failures.append(("Wrong Start Location", candidate, str(error)))
        except SignatureVerificationError as error:
            failures.append(("Signature Invalid", candidate, str(error)))
        except MediaHashMismatchError as error:
            failures.append(("Tampered", candidate, str(error)))
        except ValueError as error:
            failures.append(("Cannot Verify", candidate, str(error)))
    if len(valid) > 1:
        return _failure_result("Cannot Verify", "ambiguous valid candidates were found")
    if len(valid) == 1:
        payload, layout = valid[0]
        preserved_bits = preserved_bit_count(layout.total_units, layout.footprint, layout.lsb_count)
        total_bits = layout.total_units * 8
        ratio = preserved_bits / total_bits if total_bits else 0.0
        return V1VerificationResult(
            True,
            "Authentic",
            "signature and masked media hash are valid under the supplied public key",
            payload,
            display_rsa_public_key_fingerprint(public_key),
            layout.start_unit,
            layout.lsb_count,
            preserved_bits,
            ratio,
        )
    priority = ("Wrong Start Location", "Signature Invalid", "Tampered", "Cannot Verify")
    verdict = next(item for item in priority if any(failure[0] == item for failure in failures))
    details = "; ".join(f"candidate {candidate.start_unit}/{candidate.lsb_count}: {detail}" for kind, candidate, detail in failures if kind == verdict)
    return _failure_result(verdict, details[:1000])


def _paths_resolve_same(first_path, second_path):
    for path in (first_path, second_path):
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
    return os.path.normcase(os.path.realpath(os.fsdecode(fspath(first_path)))) == os.path.normcase(os.path.realpath(os.fsdecode(fspath(second_path))))


def encode_png_v1(input_path, output_path, private_key, start_unit, lsb_count, user_payload, metadata):
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    image = load_png_from_path(input_path)
    carrier = rgb_array_to_carrier(image)
    context = encode_png_media_context(image.shape, carrier.size)
    encoded, layout, payload = encode_v1_carrier(carrier, IMAGE_MEDIA_CODE, context, private_key, start_unit, lsb_count, user_payload, metadata)
    save_rgb_png_to_path(carrier_to_rgb_array(encoded, image.shape), output_path)
    return layout, payload


def verify_png_v1(input_path, public_key):
    try:
        image = load_png_from_path(input_path)
        carrier = rgb_array_to_carrier(image)
        context = encode_png_media_context(image.shape, carrier.size)
    except (OSError, ValueError, UnSupportedFileType) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_v1_carrier(carrier, IMAGE_MEDIA_CODE, context, public_key)


def encode_wav_v1(input_path, output_path, private_key, start_unit, lsb_count, user_payload, metadata):
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    wav_data = load_pcm_wav_from_path(input_path)
    carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
    context = encode_wav_media_context(wav_data, carrier.size)
    encoded, layout, payload = encode_v1_carrier(carrier, AUDIO_MEDIA_CODE, context, private_key, start_unit, lsb_count, user_payload, metadata)
    save_pcm_wav_to_path(wav_data_with_carrier(wav_data, encoded), output_path)
    return layout, payload


def verify_wav_v1(input_path, public_key):
    try:
        wav_data = load_pcm_wav_from_path(input_path)
        carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
        context = encode_wav_media_context(wav_data, carrier.size)
    except (OSError, ValueError) as error:
        return _failure_result("Cannot Verify", str(error))
    return decode_v1_carrier(carrier, AUDIO_MEDIA_CODE, context, public_key)
