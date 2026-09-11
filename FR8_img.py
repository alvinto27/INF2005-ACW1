"""Image LSB steganography extraction (FR8).

Given a stego PNG's pixel array, a start channel, and an LSB count, reads
the hidden payload_protocol packet back out. Mirrors R2-R6.py's audio
extract_bytes()/extract_protocol_packet(). Does not sign, verify, or
derive/secure the start location (FR7) -- start_channel is a plain
parameter here. Does not modify FR1_FR5.py or payload_protocol.py.

Pixel order matches FR1_FR5.py's own convention: img_array.flatten() on an
(H, W, 3) uint8 array, i.e. row-major (row, col, channel) with channel
order R, G, B.
"""

import struct

import numpy as np


def _validate_lsb_count(lsb_count: int) -> None:
    if isinstance(lsb_count, bool) or not isinstance(lsb_count, int):
        raise TypeError("lsb_count must be an integer")
    if not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be from 1 through 8")


def _validate_start(img_array: np.ndarray, start_channel: int) -> None:
    if isinstance(start_channel, bool) or not isinstance(start_channel, int):
        raise TypeError("start_channel must be an integer")
    if not 0 <= start_channel <= img_array.size:
        raise ValueError("start_channel is outside the RGB channel sequence")


def image_capacity_bytes(img_array: np.ndarray, lsb_count: int, start_channel: int) -> int:
    """How many whole bytes can be embedded/extracted from start_channel
    onward, at the given lsb_count."""
    _validate_lsb_count(lsb_count)
    _validate_start(img_array, start_channel)
    available_channels = img_array.size - start_channel
    return (available_channels * lsb_count) // 8


def embed_lsb(img_array: np.ndarray, data: bytes, lsb_count: int, start_channel: int) -> np.ndarray:
    """Embed data starting at start_channel using lsb_count low bits per
    channel value. Returns a new array; img_array is left unmodified.

    Test-fixture helper only -- FR1_FR5.embed_image_payload is the real
    FR5 deliverable (currently fixed at 1 LSB / index 0). This exists so
    extract_bytes/extract_protocol_packet have something to be tested
    against at other lsb_count/start_channel values.
    """
    _validate_lsb_count(lsb_count)
    _validate_start(img_array, start_channel)
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    flat = img_array.flatten()
    required_channels = (len(data) * 8 + lsb_count - 1) // lsb_count
    if required_channels > flat.size - start_channel:
        raise ValueError("payload is too large for the image capacity")

    replace_mask = (1 << lsb_count) - 1
    clear_mask = 0xFF ^ replace_mask
    bit_pos = 0
    total_bits = len(data) * 8
    for offset in range(required_channels):
        symbol = 0
        for _ in range(lsb_count):
            symbol <<= 1
            if bit_pos < total_bits:
                byte_val = data[bit_pos // 8]
                symbol |= (byte_val >> (7 - bit_pos % 8)) & 1
            bit_pos += 1
        idx = start_channel + offset
        flat[idx] = (flat[idx] & clear_mask) | symbol

    return flat.reshape(img_array.shape)


def extract_bytes(img_array: np.ndarray, byte_count: int, lsb_count: int, start_channel: int) -> bytes:
    """The core FR8 mechanic: read byte_count bytes back out, lsb_count
    bits at a time, starting at start_channel. Mirrors R2-R6.py's
    extract_bytes() (audio) function-for-function.
    """
    _validate_lsb_count(lsb_count)
    _validate_start(img_array, start_channel)
    if byte_count < 0:
        raise ValueError("byte_count cannot be negative")

    flat = img_array.flatten()
    required_channels = (byte_count * 8 + lsb_count - 1) // lsb_count
    if required_channels > flat.size - start_channel:
        raise ValueError("Requested bytes exceed the available image capacity")

    symbol_mask = (1 << lsb_count) - 1
    accumulator = 0
    accumulated_bits = 0
    output = bytearray()
    for offset in range(required_channels):
        idx = start_channel + offset
        accumulator = (accumulator << lsb_count) | (int(flat[idx]) & symbol_mask)
        accumulated_bits += lsb_count
        while accumulated_bits >= 8 and len(output) < byte_count:
            accumulated_bits -= 8
            output.append((accumulator >> accumulated_bits) & 0xFF)
            accumulator &= (1 << accumulated_bits) - 1

    return bytes(output)


def extract_protocol_packet(img_array: np.ndarray, public_key, lsb_count: int, start_channel: int) -> bytes:
    """Read payload_protocol's 4-byte length header first, derive the RSA
    signature size from the public key, then pull the full packet in one
    call. Hand the result to payload_protocol.verify_verification_packet().
    """
    length_header = extract_bytes(img_array, 4, lsb_count, start_channel)
    payload_length = struct.unpack(">I", length_header)[0]
    signature_length = (public_key.key_size + 7) // 8
    packet_length = 4 + payload_length + signature_length
    return extract_bytes(img_array, packet_length, lsb_count, start_channel)
