"""Read and write strict RGB/RGBA PNG and uncompressed PCM WAV carriers.

PNG images are decoded whole by Pillow, then exposed through bounded chunks by
``PngCarrier``. PCM WAV files are read in bounded chunks by ``WavCarrier``.
"""

import struct
import wave
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from os import PathLike, fspath

import numpy as np
from PIL import Image, UnidentifiedImageError

from .bits import (
    _validate_carrier_units,
    _validate_non_negative_integer,
    _validate_positive_integer,
)
from .carrier import (
    DEFAULT_CHUNK_BYTES,
    CarrierAccessError,
    CarrierSource,
    _validate_transformed_units,
    _validate_unit_range,
)
from .constants import (
    AUDIO_MEDIA_CODE,
    IMAGE_MEDIA_CODE,
    PNG_ALPHA_CARRIER_MODE,
    PNG_CARRIER_MODE,
    PNG_MEDIA_CONTEXT_FORMAT,
    RGB_CHANNEL_COUNT,
    RGBA_CHANNEL_COUNT,
    WAV_MEDIA_CONTEXT_FORMAT,
)


class UnSupportedFileType(Exception):
    """An error raised for a file type this package does not support."""


def _validate_png_array(image_array: np.ndarray) -> np.ndarray:
    """Check that image_array is a non-empty RGB or RGBA uint8 array."""
    if not isinstance(image_array, np.ndarray):
        raise TypeError("image_array must be a numpy array")
    if image_array.dtype != np.uint8:
        raise TypeError("image_array must have dtype uint8")
    if image_array.ndim != 3 or image_array.shape[2] not in (RGB_CHANNEL_COUNT, RGBA_CHANNEL_COUNT):
        raise ValueError("PNG must be RGB or RGBA; palette and grayscale images are not supported")
    if image_array.shape[0] < 1 or image_array.shape[1] < 1:
        raise ValueError("image dimensions must be greater than zero")
    return image_array


def _validate_rgb_png_header(
    image_path: str | bytes | PathLike[str],
) -> tuple[int, int]:
    """Check that a PNG file has the supported 8-bit RGB or RGBA format."""
    with open(image_path, "rb") as image_file:
        header = image_file.read(33)
    if len(header) != 33 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        raise ValueError("invalid PNG header")
    chunk_length = struct.unpack(">I", header[8:12])[0]
    if chunk_length != 13:
        raise ValueError("invalid PNG IHDR chunk")
    _, _, width, height, bit_depth, colour_type, compression, filter_method, _ = struct.unpack(
        ">I4sIIBBBBB", header[8:29]
    )
    if colour_type not in (2, 6):
        raise ValueError("PNG must be RGB or RGBA; palette and grayscale images are not supported")
    if bit_depth != 8:
        raise ValueError("PNG must use 8-bit RGB or RGBA samples")
    if compression != 0 or filter_method != 0:
        raise ValueError("unsupported PNG encoding")
    return width, height


def _load_png_buffer_from_path(
    image_path: str | bytes | PathLike[str],
) -> tuple[memoryview, tuple[int, int, int]]:
    """Load one checked PNG into a single decoded byte buffer."""
    if not isinstance(image_path, (str, bytes, PathLike)):
        raise TypeError("image_path must be a filesystem path")
    try:
        with Image.open(image_path) as image:
            if image.format != "PNG":
                raise UnSupportedFileType(f"unsupported file type: {image.format or 'unknown'}")
            if getattr(image, "is_animated", False) or getattr(image, "n_frames", 1) != 1:
                raise ValueError("animated PNG images are not supported")
            _validate_rgb_png_header(image_path)
            if image.mode not in (PNG_CARRIER_MODE, PNG_ALPHA_CARRIER_MODE):
                raise ValueError("PNG must be RGB or RGBA; palette and grayscale images are not supported")
            image.load()
            width, height = image.size
            channels = RGB_CHANNEL_COUNT if image.mode == PNG_CARRIER_MODE else RGBA_CHANNEL_COUNT
            if height < 1 or width < 1:
                raise ValueError("image dimensions must be greater than zero")
            # Copy public Pillow row bands into one full-image backing buffer.
            # The temporary tobytes() result is limited to an 8 MiB band.
            pixels = bytearray(height * width * channels)
            rows_per_band = max(1, (8 * 1024 * 1024) // (width * channels))
            offset = 0
            for row_start in range(0, height, rows_per_band):
                row_end = min(height, row_start + rows_per_band)
                with image.crop((0, row_start, width, row_end)) as band:
                    band_bytes = band.tobytes()
                    band_size = len(band_bytes)
                    pixels[offset:offset + band_size] = band_bytes
                offset += band_size
                del band_bytes
            if offset != len(pixels):
                raise ValueError("unreadable PNG image")
            pixel_buffer = memoryview(pixels).toreadonly()
            shape = (height, width, channels)
        return pixel_buffer, shape
    except Image.DecompressionBombError as error:
        max_image_pixels = Image.MAX_IMAGE_PIXELS
        if max_image_pixels is None:
            raise
        width, height = _validate_rgb_png_header(image_path)
        pixels = width * height
        limit = 2 * max_image_pixels
        raise ValueError(
            f"PNG image is too large: {pixels:,} pixels exceeds the limit of {limit:,}"
        ) from error
    except UnSupportedFileType:
        raise
    except ValueError:
        raise
    except UnidentifiedImageError as error:
        with open(image_path, "rb") as image_file:
            signature = image_file.read(8)
        if signature == b"\x89PNG\r\n\x1a\n":
            raise ValueError("unreadable PNG image") from error
        raise UnSupportedFileType("unsupported file type: unknown") from error
    except OSError as error:
        raise ValueError("unreadable PNG image") from error


def load_png_from_path(image_path: str | bytes | PathLike[str]) -> np.ndarray:
    """Load and check one single-frame 8-bit RGB or RGBA PNG from a file."""
    pixels, shape = _load_png_buffer_from_path(image_path)
    return np.frombuffer(pixels, dtype=np.uint8).reshape(shape).copy()


def rgb_array_to_carrier(image_array: np.ndarray) -> np.ndarray:
    """Flatten RGB channels from an RGB or RGBA image into carrier units."""
    image_array = _validate_png_array(image_array)
    return np.array(
        image_array[:, :, :RGB_CHANNEL_COUNT],
        dtype=np.uint8,
        order="C",
        copy=True,
    ).reshape(-1)


def encode_png_media_context(image_shape: tuple[int, int, int], carrier_unit_count: int | None = None) -> bytes:
    """Make the PNG context that binds width, height, and channel count."""
    try:
        height, width, channels = tuple(image_shape)
    except (TypeError, ValueError) as error:
        raise ValueError("image_shape must be (height, width, 3 or 4)") from error
    if channels not in (RGB_CHANNEL_COUNT, RGBA_CHANNEL_COUNT) or height < 1 or width < 1 or height > 0xFFFFFFFF or width > 0xFFFFFFFF:
        raise ValueError("image_shape must be bounded (height, width, 3 or 4)")
    if carrier_unit_count is not None and carrier_unit_count != height * width * RGB_CHANNEL_COUNT:
        raise ValueError("carrier count does not match PNG dimensions")
    return struct.pack(PNG_MEDIA_CONTEXT_FORMAT, width, height, channels)


def _save_png_array_to_path(image_array: np.ndarray, output_path: str | bytes | PathLike[str]) -> None:
    """Save a checked RGB or RGBA image array as a PNG file."""
    image_array = _validate_png_array(image_array)
    if not isinstance(output_path, (str, bytes, PathLike)):
        raise TypeError("output_path must be a filesystem path")
    mode = PNG_CARRIER_MODE if image_array.shape[2] == RGB_CHANNEL_COUNT else PNG_ALPHA_CARRIER_MODE
    try:
        Image.fromarray(image_array, mode=mode).save(output_path, format="PNG")
    except (OSError, ValueError) as error:
        raise ValueError("could not save PNG") from error


class PngCarrier(CarrierSource):
    """Read an RGB or RGBA PNG through bounded RGB carrier-unit chunks.

    The backend keeps one decoded byte buffer: about one image size (D) after
    loading. Rewriting allocates one output image as well, for about 2 x D
    image data. RGB values form the carrier. RGBA alpha is a read-only view and
    is never changed.
    """

    def __init__(self, path: str | bytes | PathLike[str], chunk_units: int = DEFAULT_CHUNK_BYTES) -> None:
        """Load one PNG into a single backing buffer, then choose the chunk size."""
        chunk_units = _validate_positive_integer(chunk_units, "chunk_units")
        self._path = path
        pixels, self._shape = _load_png_buffer_from_path(path)
        self._channel_count = self._shape[2]
        self._pixels = np.frombuffer(pixels, dtype=np.uint8).reshape(self._shape)
        self._pixels_by_channel = self._pixels.reshape((-1, self._channel_count))
        self._alpha = (
            self._pixels_by_channel[:, RGB_CHANNEL_COUNT]
            if self._channel_count == RGBA_CHANNEL_COUNT
            else None
        )
        self._total_units = self._shape[0] * self._shape[1] * RGB_CHANNEL_COUNT
        self._chunk_units = chunk_units
        self._pixels_per_chunk = max(1, chunk_units // RGB_CHANNEL_COUNT)
        self._media_context = encode_png_media_context(
            self._shape, self._total_units
        )

    @property
    def path(self) -> str | bytes | PathLike[str]:
        """Return the path used to load this PNG carrier."""
        return self._path

    @property
    def total_units(self) -> int:
        """Return the number of RGB channel values in the image."""
        return self._total_units

    @property
    def channel_count(self) -> int:
        """Return the input PNG's channel count, either three or four."""
        return self._channel_count

    @property
    def fixed_byte_count(self) -> int:
        """Return the number of alpha bytes paired with chunks, or zero for RGB."""
        return self._shape[0] * self._shape[1] if self._alpha is not None else 0

    @property
    def media_code(self) -> int:
        """Return the PNG protocol media code."""
        return IMAGE_MEDIA_CODE

    @property
    def media_context(self) -> bytes:
        """Return the PNG dimensions and channel count for protocol signing."""
        return self._media_context

    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        """Return a new writable array for the requested carrier-unit range."""
        start_unit, count = _validate_unit_range(start_unit, count, self.total_units)
        if count == 0:
            return np.empty(0, dtype=np.uint8)
        if self._channel_count == RGB_CHANNEL_COUNT:
            return self._pixels.reshape(-1)[start_unit:start_unit + count].copy()

        pixel_start = start_unit // RGB_CHANNEL_COUNT
        pixel_end = -(-(start_unit + count) // RGB_CHANNEL_COUNT)
        rgb_pixels = self._pixels_by_channel[
            pixel_start:pixel_end, :RGB_CHANNEL_COUNT
        ]
        rgb_units = np.array(rgb_pixels, dtype=np.uint8, order="C", copy=True).reshape(-1)
        unit_offset = start_unit - pixel_start * RGB_CHANNEL_COUNT
        return rgb_units[unit_offset:unit_offset + count]

    def iter_chunks(self) -> Iterator[np.ndarray]:
        """Yield every RGB carrier unit once in bounded unit-only chunks."""
        for start_unit in range(0, self.total_units, self._chunk_units):
            count = min(self._chunk_units, self.total_units - start_unit)
            yield self.read_units(start_unit, count)

    def iter_chunks_with_fixed_bytes(self) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield pixel-aligned RGB chunks and the matching alpha bytes."""
        pixel_count = self._shape[0] * self._shape[1]
        alpha_values = None if self._alpha is None else self._alpha.reshape(-1)
        for pixel_start in range(0, pixel_count, self._pixels_per_chunk):
            pixels = min(self._pixels_per_chunk, pixel_count - pixel_start)
            units = self.read_units(
                pixel_start * RGB_CHANNEL_COUNT, pixels * RGB_CHANNEL_COUNT
            )
            fixed_bytes = b"" if alpha_values is None else alpha_values[
                pixel_start:pixel_start + pixels
            ].tobytes()
            yield units, fixed_bytes

    def rewrite_to_path(
        self,
        output_path: str | bytes | PathLike[str],
        transform: Callable[[int, np.ndarray], np.ndarray],
        fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
    ) -> None:
        """Write transformed RGB units while preserving the source alpha bytes."""
        output_image = np.empty(self._shape, dtype=np.uint8)
        output_pixels = output_image.reshape((-1, self._channel_count))
        unit_offset = 0
        pixel_offset = 0
        for original, fixed_bytes in self.iter_chunks_with_fixed_bytes():
            if fixed_bytes_callback is not None:
                fixed_bytes_callback(unit_offset, original, fixed_bytes)
            replaced = _validate_transformed_units(
                transform(unit_offset, original), original.size
            )
            pixel_count = original.size // RGB_CHANNEL_COUNT
            output_pixels[
                pixel_offset:pixel_offset + pixel_count, :RGB_CHANNEL_COUNT
            ] = replaced.reshape((pixel_count, RGB_CHANNEL_COUNT))
            if self._channel_count == RGBA_CHANNEL_COUNT:
                output_pixels[
                    pixel_offset:pixel_offset + pixel_count, RGB_CHANNEL_COUNT
                ] = np.frombuffer(fixed_bytes, dtype=np.uint8)
            unit_offset += original.size
            pixel_offset += pixel_count
        _save_png_array_to_path(output_image, output_path)


def _validate_wav_format(channels: int, sample_width: int, frame_rate: int, frame_count: int) -> tuple[int, int, int, int]:
    """Check and normalise PCM WAV format values."""
    channels = _validate_positive_integer(channels, "channels")
    sample_width = _validate_positive_integer(sample_width, "sample_width")
    frame_rate = _validate_positive_integer(frame_rate, "frame_rate")
    frame_count = _validate_non_negative_integer(frame_count, "frame_count")
    if sample_width not in range(1, 5):
        raise ValueError("sample_width must be between 1 and 4 bytes")
    return channels, sample_width, frame_rate, frame_count


@dataclass(frozen=True)
class WavPcmInfo:
    """Keep checked PCM WAV format values without the frame bytes."""
    channels: int
    sample_width: int
    frame_rate: int
    frame_count: int

    def __post_init__(self) -> None:
        """Check and normalise the PCM WAV format values."""
        values = _validate_wav_format(self.channels, self.sample_width, self.frame_rate, self.frame_count)
        for name, value in zip(("channels", "sample_width", "frame_rate", "frame_count"), values):
            object.__setattr__(self, name, value)

    @property
    def bytes_per_frame(self) -> int:
        """Return the size of one PCM frame: one sample for every channel."""
        return self.channels * self.sample_width

    @property
    def sample_count(self) -> int:
        """Return the number of PCM samples, which is the number of carrier units."""
        return self.channels * self.frame_count


def encode_wav_media_context(wav_data: WavPcmInfo) -> bytes:
    """Make the WAV context that ties header format and frame settings to the signature."""
    if not isinstance(wav_data, WavPcmInfo):
        raise TypeError("wav_data must be a WavPcmInfo")
    if wav_data.channels > 0xFFFF or wav_data.sample_width > 0xFF or wav_data.frame_rate > 0xFFFFFFFF or wav_data.frame_count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("WAV values do not fit the media context")
    return struct.pack(WAV_MEDIA_CONTEXT_FORMAT, wav_data.channels, wav_data.sample_width, wav_data.frame_rate, wav_data.frame_count)


_WAV_READ_ERRORS = (OSError, EOFError, wave.Error, struct.error)


def _read_wav_info(wav_file: wave.Wave_read) -> WavPcmInfo:
    """Read and check the format values of an open WAV reader."""
    channels = wav_file.getnchannels()
    sample_width = wav_file.getsampwidth()
    frame_rate = wav_file.getframerate()
    frame_count = wav_file.getnframes()
    if wav_file.getcomptype() != "NONE":
        raise ValueError("WAV must use uncompressed PCM")
    return WavPcmInfo(channels, sample_width, frame_rate, frame_count)


def read_pcm_wav_info(path: str | bytes | PathLike[str]) -> WavPcmInfo:
    """Read and check a PCM WAV header without loading its frame bytes.

    The last declared frame is also read, so a file whose data is shorter than
    its header claims fails here, before any protocol work starts. No size cap
    applies, because nothing is allocated in proportion to the frame count.
    """
    if not isinstance(path, (str, bytes, PathLike)):
        raise TypeError("path must be a filesystem path")
    try:
        with wave.open(fspath(path), "rb") as wav_file:
            info = _read_wav_info(wav_file)
            if info.frame_count:
                wav_file.setpos(info.frame_count - 1)
                if len(wav_file.readframes(1)) != info.bytes_per_frame:
                    raise ValueError("WAV data is shorter than its declared frame count")
            return info
    except ValueError:
        raise
    except _WAV_READ_ERRORS as error:
        raise ValueError("invalid or unreadable uncompressed PCM WAV") from error


class WavCarrier(CarrierSource):
    """Read a PCM WAV file as carrier units in bounded chunks of whole PCM frames.

    One carrier unit is the least-significant byte of one little-endian PCM
    sample. Fixed bytes are every other byte of the same declared samples.
    """

    def __init__(self, path: str | bytes | PathLike[str], chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> None:
        """Check the WAV header and choose how many whole frames each chunk holds.

        ``chunk_bytes`` is the target raw PCM size of one chunk. A chunk always
        holds at least one frame and never splits a sample or a frame.
        """
        chunk_bytes = _validate_positive_integer(chunk_bytes, "chunk_bytes")
        self.info = read_pcm_wav_info(path)
        self._path = path
        self.frames_per_chunk = max(1, chunk_bytes // self.info.bytes_per_frame)

    @property
    def total_units(self) -> int:
        """Return the number of PCM samples in the file."""
        return self.info.sample_count

    @property
    def fixed_byte_count(self) -> int:
        """Return the non-LSB byte count in the declared PCM samples."""
        return self.info.sample_count * (self.info.sample_width - 1)

    @property
    def media_code(self) -> int:
        """Return the WAV protocol media code."""
        return AUDIO_MEDIA_CODE

    @property
    def media_context(self) -> bytes:
        """Return the WAV format and frame values encoded for the protocol."""
        return encode_wav_media_context(self.info)

    def _open(self) -> wave.Wave_read:
        """Open the WAV again and check that its header has not changed."""
        try:
            wav_file = wave.open(fspath(self._path), "rb")
        except _WAV_READ_ERRORS as error:
            raise CarrierAccessError("could not reopen the WAV carrier") from error
        try:
            info = _read_wav_info(wav_file)
        except (ValueError, *_WAV_READ_ERRORS) as error:
            wav_file.close()
            raise CarrierAccessError("could not reread the WAV carrier header") from error
        if info != self.info:
            wav_file.close()
            raise CarrierAccessError("WAV carrier header changed after it was opened")
        return wav_file

    def _read_frames(self, wav_file: wave.Wave_read, frame_count: int) -> bytes:
        """Read exactly frame_count frames, or raise CarrierAccessError."""
        try:
            raw = wav_file.readframes(frame_count)
        except _WAV_READ_ERRORS as error:
            raise CarrierAccessError("could not read WAV frame data") from error
        if len(raw) != frame_count * self.info.bytes_per_frame:
            raise CarrierAccessError("WAV data ended before its declared frame count")
        return raw

    def _units_and_fixed_from_frames(self, raw: bytes) -> tuple[np.ndarray, bytes]:
        """Split one frame chunk into sample LSB bytes and fixed sample bytes."""
        samples = np.frombuffer(raw, dtype=np.uint8).reshape((-1, self.info.sample_width))
        return samples[:, 0].copy(), samples[:, 1:].tobytes()

    def _units_from_frames(self, raw: bytes) -> np.ndarray:
        """Copy the least-significant byte of every sample in raw frame bytes."""
        return self._units_and_fixed_from_frames(raw)[0]

    def _iter_raw_chunks(self) -> Iterator[bytes]:
        """Yield the frame bytes in order, in chunks of whole frames."""
        wav_file = self._open()
        try:
            remaining = self.info.frame_count
            while remaining:
                frame_count = min(self.frames_per_chunk, remaining)
                yield self._read_frames(wav_file, frame_count)
                remaining -= frame_count
        finally:
            wav_file.close()

    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        """Return count units starting at start_unit, reading only the frames that hold them."""
        start_unit, count = _validate_unit_range(start_unit, count, self.total_units)
        if count == 0:
            return np.empty(0, dtype=np.uint8)
        channels = self.info.channels
        first_frame = start_unit // channels
        end_frame = -(-(start_unit + count) // channels)
        wav_file = self._open()
        try:
            try:
                wav_file.setpos(first_frame)
            except _WAV_READ_ERRORS as error:
                raise CarrierAccessError("could not seek in WAV frame data") from error
            raw = self._read_frames(wav_file, end_frame - first_frame)
        finally:
            wav_file.close()
        offset = start_unit - first_frame * channels
        return self._units_from_frames(raw)[offset:offset + count].copy()

    def iter_chunks(self) -> Iterator[np.ndarray]:
        """Yield every carrier unit once, in order, one chunk of whole frames at a time."""
        for raw in self._iter_raw_chunks():
            yield self._units_from_frames(raw)

    def iter_chunks_with_fixed_bytes(self) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield sample LSB bytes with the other bytes from those same frames."""
        for raw in self._iter_raw_chunks():
            yield self._units_and_fixed_from_frames(raw)

    def rewrite_to_path(
        self,
        output_path: str | bytes | PathLike[str],
        transform: Callable[[int, np.ndarray], np.ndarray],
        fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
    ) -> None:
        """Copy the WAV, transform units, and preserve high sample bytes exactly."""
        if not isinstance(output_path, (str, bytes, PathLike)):
            raise TypeError("output_path must be a filesystem path")
        sample_width = self.info.sample_width
        try:
            with wave.open(fspath(output_path), "wb") as wav_file:
                wav_file.setnchannels(self.info.channels)
                wav_file.setsampwidth(sample_width)
                wav_file.setframerate(self.info.frame_rate)
                wav_file.setnframes(self.info.frame_count)
                unit_offset = 0
                for raw in self._iter_raw_chunks():
                    original, fixed_bytes = self._units_and_fixed_from_frames(raw)
                    if fixed_bytes_callback is not None:
                        fixed_bytes_callback(unit_offset, original, fixed_bytes)
                    replaced = _validate_transformed_units(
                        transform(unit_offset, original), original.size
                    )
                    frame_bytes = bytearray(raw)
                    frame_bytes[0::sample_width] = replaced.tobytes()
                    wav_file.writeframesraw(frame_bytes)
                    unit_offset += original.size
        except _WAV_READ_ERRORS as error:
            raise CarrierAccessError("could not save uncompressed PCM WAV") from error
