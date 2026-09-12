"""Strict RGB PNG and uncompressed PCM WAV adapters."""

import struct
import wave
from dataclasses import dataclass
from os import PathLike, fspath

import numpy as np
from PIL import Image

from .bits import (
    _require_bytes,
    _validate_carrier_units,
    _validate_non_negative_integer,
    _validate_positive_integer,
)
from .constants import (
    MAX_WAV_FRAME_BYTES,
    PNG_CARRIER_MODE,
    PNG_MEDIA_CONTEXT_FORMAT,
    RGB_CHANNEL_COUNT,
    WAV_MEDIA_CONTEXT_FORMAT,
)


class UnSupportedFileType(Exception):
    """Marks an unsupported file type."""


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
