"""Read and write strict RGB/RGBA PNG and uncompressed PCM WAV carriers.

PNG images are decoded whole by PyAV, then exposed through bounded chunks by
``PngCarrier``. PCM WAV files are read in bounded chunks by ``WavCarrier``.

Rewrites keep carrier metadata that is outside the masked media hash: PNG
ancillary chunks that a PNG editor may copy, and every WAV byte outside the
declared PCM samples.
"""

import io
import os
import struct
import tempfile
import wave
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike, fspath

import av
import numpy as np

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
) -> tuple[int, int, int, int]:
    """Check the PNG header and return width, height, channels, and bit depth."""
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
    if bit_depth not in (8, 16):
        raise ValueError("PNG must use 8-bit or 16-bit RGB or RGBA samples")
    if compression != 0 or filter_method != 0:
        raise ValueError("unsupported PNG encoding")
    return width, height, RGB_CHANNEL_COUNT if colour_type == 2 else RGBA_CHANNEL_COUNT, bit_depth


def _load_png_buffer_from_path(
    image_path: str | bytes | PathLike[str],
) -> tuple[memoryview, tuple[int, int, int], int]:
    """Load one checked PNG into a single decoded byte buffer."""
    if not isinstance(image_path, (str, bytes, PathLike)):
        raise TypeError("image_path must be a filesystem path")
    with open(image_path, "rb") as image_file:
        signature = image_file.read(8)
    if signature != _PNG_SIGNATURE:
        try:
            with av.open(os.fsdecode(image_path), mode="r") as non_png:
                file_type = non_png.format.name.split(",")[0].upper().replace("_PIPE", "")
        except (OSError, av.error.FFmpegError):
            file_type = "unknown"
        raise UnSupportedFileType(f"unsupported file type: {file_type}")
    width, height, channels, bit_depth = _validate_rgb_png_header(image_path)
    if width < 1 or height < 1:
        raise ValueError("image dimensions must be greater than zero")
    decoded_bytes = width * height * channels * (bit_depth // 8)
    if decoded_bytes > _PNG_MAX_DECODED_BYTES:
        raise ValueError(
            "PNG decoded size exceeds configured limit: "
            f"{decoded_bytes} bytes > {_PNG_MAX_DECODED_BYTES} bytes"
        )
    try:
        with open(image_path, "rb") as image_file:
            image_file.seek(8)
            while True:
                chunk_header = image_file.read(8)
                if len(chunk_header) != 8:
                    raise ValueError("unreadable PNG image")
                chunk_length, chunk_type = struct.unpack(">I4s", chunk_header)
                if chunk_type == b"acTL":
                    raise ValueError("animated PNG images are not supported")
                if chunk_type == b"IEND":
                    break
                image_file.seek(chunk_length + 4, os.SEEK_CUR)
        with av.open(os.fsdecode(image_path), mode="r") as container:
            if "png" not in container.format.name.lower():
                raise UnSupportedFileType(
                    f"unsupported file type: {container.format.name.split(',')[0].upper()}"
                )
            stream = container.streams.video[0]
            codec = stream.codec_context
            # FFmpeg rejects small max_pixels values for tiny padded images;
            # the IHDR byte check remains the exact limit for those cases.
            max_pixels = max(
                1_000_000,
                _PNG_MAX_DECODED_BYTES // (channels * (bit_depth // 8)) + 1,
            )
            codec.options = {**codec.options, "max_pixels": str(max_pixels)}
            if codec.width != width or codec.height != height:
                raise ValueError("unreadable PNG image")
            pixel_format = codec.format.name if codec.format is not None else ""
            allowed_formats = (
                {"rgb24", "rgba"}
                if bit_depth == 8
                else {"rgb48be", "rgba64be"}
            )
            if pixel_format not in allowed_formats:
                raise ValueError("PNG must be RGB or RGBA; palette and grayscale images are not supported")
            decoded: np.ndarray | None = None
            frame_count = 0
            for frame in container.decode(stream):
                frame_count += 1
                if frame_count > 1:
                    raise ValueError("animated PNG images are not supported")
                target_format = (
                    ("rgb24" if channels == RGB_CHANNEL_COUNT else "rgba")
                    if bit_depth == 8
                    else ("rgb48be" if channels == RGB_CHANNEL_COUNT else "rgba64be")
                )
                decoded = frame.to_ndarray(format=target_format)
            if decoded is None or decoded.shape != (height, width, channels):
                raise ValueError("unreadable PNG image")
            pixel_buffer = memoryview(decoded).cast("B").toreadonly()
            del decoded, frame
        return pixel_buffer, (height, width, channels), bit_depth
    except (UnSupportedFileType, ValueError):
        raise
    except (OSError, av.error.FFmpegError, IndexError) as error:
        with open(image_path, "rb") as image_file:
            signature = image_file.read(8)
        if signature != _PNG_SIGNATURE:
            raise UnSupportedFileType("unsupported file type: unknown") from error
        raise ValueError("unreadable PNG image") from error


def load_png_from_path(image_path: str | bytes | PathLike[str]) -> np.ndarray:
    """Load and check one single-frame 8-bit or 16-bit RGB/RGBA PNG."""
    pixels, shape, bit_depth = _load_png_buffer_from_path(image_path)
    dtype = np.uint8 if bit_depth == 8 else np.uint16
    return np.frombuffer(pixels, dtype=dtype).reshape(shape).copy()


def rgb_array_to_carrier(image_array: np.ndarray) -> np.ndarray:
    """Flatten RGB channels from an RGB or RGBA image into carrier units."""
    image_array = _validate_png_array(image_array)
    return np.array(
        image_array[:, :, :RGB_CHANNEL_COUNT],
        dtype=np.uint8,
        order="C",
        copy=True,
    ).reshape(-1)


def encode_png_media_context(
    image_shape: tuple[int, int, int],
    carrier_unit_count: int | None = None,
    bit_depth: int = 8,
) -> bytes:
    """Make the PNG context for dimensions, channels, and sample depth."""
    try:
        height, width, channels = tuple(image_shape)
    except (TypeError, ValueError) as error:
        raise ValueError("image_shape must be (height, width, 3 or 4)") from error
    if channels not in (RGB_CHANNEL_COUNT, RGBA_CHANNEL_COUNT) or height < 1 or width < 1 or height > 0xFFFFFFFF or width > 0xFFFFFFFF:
        raise ValueError("image_shape must be bounded (height, width, 3 or 4)")
    if bit_depth not in (8, 16):
        raise ValueError("PNG sample depth must be 8 or 16 bits")
    if carrier_unit_count is not None and carrier_unit_count != height * width * RGB_CHANNEL_COUNT:
        raise ValueError("carrier count does not match PNG dimensions")
    if bit_depth == 8:
        return struct.pack(PNG_MEDIA_CONTEXT_FORMAT, width, height, channels)
    return struct.pack(">IIBB", width, height, channels, bit_depth)


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_MAX_DECODED_BYTES = 715_827_880
_PNG_IMAGE_CHUNKS = frozenset((b"IHDR", b"IDAT", b"IEND"))
# Known chunks copied unchanged. They stay true after embedding because only
# low bits change. PLTE is only a suggested palette in truecolour PNGs.
_PNG_KNOWN_COPIED_CHUNKS = frozenset((
    b"PLTE", b"tEXt", b"zTXt", b"iTXt", b"iCCP", b"cICP", b"sRGB", b"gAMA", b"cHRM",
    b"mDCV", b"cLLI", b"pHYs", b"eXIf", b"bKGD", b"sPLT",
))
# sBIT would mark the embedded low bits as not significant, and hIST counts the
# old pixels, so both are dropped. tRNS is handled by colour type; tIME is
# replaced with the encode time.
_PNG_RGB_COLOUR_TYPE = 2
_PNG_RGB_TRNS_ERROR = "RGB PNG with a tRNS colour key is not supported; convert the image to RGBA"


def _utc_now() -> datetime:
    """Return the current UTC time. Tests patch this function."""
    return datetime.now(timezone.utc)


def _png_chunk_bytes(chunk_type: bytes, data: bytes) -> bytes:
    """Build one whole PNG chunk with a new CRC."""
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(chunk_type + data))


def _png_time_chunk() -> bytes:
    """Build a tIME chunk with the current UTC time."""
    now = _utc_now().astimezone(timezone.utc)
    return _png_chunk_bytes(
        b"tIME",
        struct.pack(">HBBBBB", now.year, now.month, now.day, now.hour, now.minute, now.second),
    )


def _copy_file_bytes(source_file: io.BufferedIOBase, output_file: io.BufferedIOBase, offset: int, count: int | None) -> None:
    """Copy count bytes, or all bytes to the end when count is None, in bounded blocks."""
    source_file.seek(offset)
    while count is None or count > 0:
        block = source_file.read(DEFAULT_CHUNK_BYTES if count is None else min(DEFAULT_CHUNK_BYTES, count))
        if not block:
            if count is None:
                return
            raise ValueError("file ended before the bytes to copy")
        output_file.write(block)
        if count is not None:
            count -= len(block)


def _png_copied_chunks(source_file: io.BufferedIOBase) -> tuple[list[tuple[int, int] | bytes], list[tuple[int, int] | bytes]]:
    """Return the chunks to write before and after IDAT.

    An item is a source (offset, size) range to copy, or new chunk bytes.
    Known chunks that stay true and unknown ancillary safe-to-copy chunks are
    copied. A tIME chunk is replaced with the encode time. sBIT, hIST, the
    tRNS of an RGBA PNG, and unknown unsafe-to-copy chunks are dropped. An RGB
    PNG with tRNS, more than one tIME, or an unknown critical chunk stops the
    encode, as the PNG specification requires of PNG editors.
    """
    file_size = os.fstat(source_file.fileno()).st_size
    source_file.seek(0)
    if source_file.read(8) != _PNG_SIGNATURE:
        raise ValueError("invalid PNG header")
    before: list[tuple[int, int] | bytes] = []
    after: list[tuple[int, int] | bytes] = []
    offset = 8
    seen_idat = False
    seen_time = False
    colour_type = None
    while True:
        source_file.seek(offset)
        header = source_file.read(8)
        if len(header) != 8:
            raise ValueError("PNG chunk list ends before IEND")
        length, chunk_type = struct.unpack(">I4s", header)
        size = length + 12
        if length > 0x7FFFFFFF or offset + size > file_size or not chunk_type.isalpha():
            raise ValueError("invalid PNG chunk structure")
        if chunk_type == b"IEND":
            return before, after
        if (chunk_type == b"IHDR") != (offset == 8):
            raise ValueError("invalid PNG chunk structure")
        if chunk_type == b"IHDR":
            colour_type = source_file.read(10)[9:10]
        elif chunk_type == b"IDAT":
            seen_idat = True
        elif chunk_type == b"tIME":
            if seen_time:
                raise ValueError("PNG has more than one tIME chunk")
            seen_time = True
            (after if seen_idat else before).append(_png_time_chunk())
        elif chunk_type == b"tRNS":
            if colour_type == bytes((_PNG_RGB_COLOUR_TYPE,)):
                raise ValueError(_PNG_RGB_TRNS_ERROR)
        elif chunk_type in _PNG_KNOWN_COPIED_CHUNKS or (
            chunk_type not in _PNG_IMAGE_CHUNKS and chunk_type[0:1].islower() and chunk_type[3:4].islower()
        ):
            (after if seen_idat else before).append((offset, size))
        elif chunk_type[0:1].isupper() and chunk_type not in _PNG_IMAGE_CHUNKS:
            raise ValueError(f"unknown critical PNG chunk: {chunk_type.decode('ascii')}")
        offset += size


class _PngChunkSplicer:
    """Pass encoded PNG bytes to a file and insert copied source chunks.

    The copied chunks go immediately before the first IDAT chunk and
    immediately before IEND. Only IHDR, IDAT, and IEND from PyAV are kept;
    all encoder ancillary chunks are dropped.
    """

    def __init__(self, output_file: io.BufferedIOBase, source_file: io.BufferedIOBase, before: list[tuple[int, int] | bytes], after: list[tuple[int, int] | bytes]) -> None:
        """Keep the output, the source, and the chunks to insert."""
        self._output = output_file
        self._source = source_file
        self._before = before
        self._after = after
        self._pending = bytearray()
        self._remaining = 0
        self._discarding = False
        self._signature_done = False
        self._types: list[bytes] = []
        self._written = 0

    def write(self, data: bytes) -> int:
        """Parse an encoded PNG stream in any write size and copy it through."""
        view = memoryview(data).cast("B")
        size = len(view)
        while view:
            if self._remaining:
                count = min(self._remaining, len(view))
                if not self._discarding:
                    self._output.write(view[:count])
                self._remaining -= count
                view = view[count:]
                continue
            count = min(8 - len(self._pending), len(view))
            self._pending += view[:count]
            view = view[count:]
            if len(self._pending) == 8:
                self._take_header(bytes(self._pending))
                self._pending.clear()
        self._written += size
        return size

    def _take_header(self, header: bytes) -> None:
        """Handle the PNG signature or one chunk header from PyAV."""
        if not self._signature_done:
            if header != _PNG_SIGNATURE:
                raise ValueError("the PNG encoder did not write a PNG signature")
            self._signature_done = True
            self._output.write(header)
            return
        length, chunk_type = struct.unpack(">I4s", header)
        if chunk_type not in _PNG_IMAGE_CHUNKS and not chunk_type[0:1].islower():
            raise ValueError(f"unexpected PNG chunk from the encoder: {chunk_type!r}")
        if chunk_type in _PNG_IMAGE_CHUNKS and (
            (chunk_type == b"IHDR") != (not self._types)
            or self._types[-1:] == [b"IEND"]
        ):
            raise ValueError(f"unexpected PNG chunk from the encoder: {chunk_type!r}")
        self._discarding = chunk_type not in _PNG_IMAGE_CHUNKS
        if chunk_type == b"IDAT" and b"IDAT" not in self._types:
            self._copy_chunks(self._before)
        elif chunk_type == b"IEND":
            self._copy_chunks(self._after)
        if not self._discarding:
            self._types.append(chunk_type)
            self._output.write(header)
        self._remaining = length + 4

    def _copy_chunks(self, chunks: list[tuple[int, int] | bytes]) -> None:
        """Write new chunk bytes, or copy whole source chunks with their original CRC."""
        for chunk in chunks:
            if isinstance(chunk, bytes):
                self._output.write(chunk)
            else:
                _copy_file_bytes(self._source, self._output, chunk[0], chunk[1])

    def flush(self) -> None:
        """Flush the output file."""
        self._output.flush()

    def tell(self) -> int:
        """Return the number of bytes received from the encoder."""
        return self._written

    def finish(self) -> None:
        """Check that the encoder wrote a whole PNG with IDAT and IEND."""
        if self._remaining or self._pending or self._types[-1:] != [b"IEND"] or b"IDAT" not in self._types:
            raise ValueError("the PNG encoder did not write a complete image")


def _save_png_frame_to_path(
    frame: av.VideoFrame,
    output_path: str | bytes | PathLike[str],
    chunk_source_path: str | bytes | PathLike[str] | None = None,
) -> None:
    """Encode a filled PyAV frame and copy safe source ancillary chunks."""
    if not isinstance(output_path, (str, bytes, PathLike)):
        raise TypeError("output_path must be a filesystem path")
    before: list[tuple[int, int] | bytes] = []
    after: list[tuple[int, int] | bytes] = []
    if chunk_source_path is not None:
        try:
            with open(chunk_source_path, "rb") as source_file:
                before, after = _png_copied_chunks(source_file)
        except OSError as error:
            raise ValueError("could not read the PNG carrier chunks") from error
    encoded_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temporary_file:
            encoded_path = temporary_file.name
        container = av.open(encoded_path, mode="w", format="image2pipe")
        try:
            stream = container.add_stream("png")
            stream.width = frame.width
            stream.height = frame.height
            stream.pix_fmt = frame.format.name
            stream.codec_context.options = {
                **stream.codec_context.options,
                "compression_level": "1",
                "pred": "up",
            }
            for packet in (*stream.encode(frame), *stream.encode(None)):
                container.mux(packet)
        finally:
            container.close()
        if chunk_source_path is None:
            source_file = open(encoded_path, "rb")
        else:
            try:
                source_file = open(chunk_source_path, "rb")
            except OSError as error:
                raise ValueError("could not reopen the PNG carrier") from error
        try:
            with open(output_path, "wb") as output_file, open(encoded_path, "rb") as encoded_file:
                splicer = _PngChunkSplicer(output_file, source_file, before, after)
                while block := encoded_file.read(DEFAULT_CHUNK_BYTES):
                    splicer.write(block)
                splicer.finish()
        finally:
            source_file.close()
    except (OSError, av.error.FFmpegError) as error:
        raise ValueError("could not save PNG") from error
    finally:
        if encoded_path is not None:
            try:
                os.unlink(encoded_path)
            except OSError:
                pass


def _save_png_array_to_path(image_array: np.ndarray, output_path: str | bytes | PathLike[str], chunk_source_path: str | bytes | PathLike[str] | None = None) -> None:
    """Save a checked RGB or RGBA array with the PyAV PNG encoder."""
    image_array = _validate_png_array(image_array)
    mode = PNG_CARRIER_MODE if image_array.shape[2] == RGB_CHANNEL_COUNT else PNG_ALPHA_CARRIER_MODE
    frame = av.VideoFrame.from_ndarray(
        image_array, format="rgb24" if mode == PNG_CARRIER_MODE else "rgba"
    )
    _save_png_frame_to_path(frame, output_path, chunk_source_path)


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
        pixels, self._shape, self._bit_depth = _load_png_buffer_from_path(path)
        self._channel_count = self._shape[2]
        self._pixels = np.frombuffer(
            pixels, dtype=np.uint8 if self._bit_depth == 8 else np.uint16
        ).reshape(self._shape)
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
            self._shape, self._total_units, self._bit_depth
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
        """Return all image bytes that are not RGB low-byte carrier units."""
        pixel_count = self._shape[0] * self._shape[1]
        if self._bit_depth == 8:
            return pixel_count if self._alpha is not None else 0
        return pixel_count * (3 + (2 if self._alpha is not None else 0))

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
        pixel_start = start_unit // RGB_CHANNEL_COUNT
        pixel_end = -(-(start_unit + count) // RGB_CHANNEL_COUNT)
        rgb_pixels = self._pixels_by_channel[
            pixel_start:pixel_end, :RGB_CHANNEL_COUNT
        ]
        if self._bit_depth == 8 and self._channel_count == RGB_CHANNEL_COUNT:
            return rgb_pixels.reshape(-1)[
                start_unit - pixel_start * RGB_CHANNEL_COUNT:
                start_unit - pixel_start * RGB_CHANNEL_COUNT + count
            ].copy()
        rgb_units = (rgb_pixels & 0xFF).astype(
            np.uint8, copy=self._bit_depth == 8
        ).reshape(-1)
        unit_offset = start_unit - pixel_start * RGB_CHANNEL_COUNT
        return rgb_units[unit_offset:unit_offset + count]

    def iter_chunks(self) -> Iterator[np.ndarray]:
        """Yield every RGB carrier unit once in bounded unit-only chunks."""
        for start_unit in range(0, self.total_units, self._chunk_units):
            count = min(self._chunk_units, self.total_units - start_unit)
            yield self.read_units(start_unit, count)

    def iter_chunks_with_fixed_bytes(self) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield RGB units and fixed bytes in their protocol-defined order."""
        pixel_count = self._shape[0] * self._shape[1]
        for pixel_start in range(0, pixel_count, self._pixels_per_chunk):
            pixels = min(self._pixels_per_chunk, pixel_count - pixel_start)
            units = self.read_units(
                pixel_start * RGB_CHANNEL_COUNT, pixels * RGB_CHANNEL_COUNT
            )
            if self._bit_depth == 8:
                fixed_bytes = b"" if self._alpha is None else self._alpha[
                    pixel_start:pixel_start + pixels
                ].tobytes()
                yield units, fixed_bytes
                continue
            rgb_values = self._pixels_by_channel[
                pixel_start:pixel_start + pixels, :RGB_CHANNEL_COUNT
            ]
            high_bytes = (rgb_values >> 8).astype(np.uint8).tobytes()
            yield units, high_bytes
        if self._bit_depth == 16 and self._alpha is not None:
            alpha_values = self._alpha.reshape(-1)
            for pixel_start in range(0, pixel_count, self._pixels_per_chunk):
                alpha_chunk = alpha_values[
                    pixel_start:pixel_start + self._pixels_per_chunk
                ]
                yield np.empty(0, dtype=np.uint8), alpha_chunk.astype("<u2", copy=False).tobytes()

    def rewrite_to_path(
        self,
        output_path: str | bytes | PathLike[str],
        transform: Callable[[int, np.ndarray], np.ndarray],
        fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
    ) -> None:
        """Write transformed RGB units into one PyAV frame, preserving fixed values."""
        height, width, _ = self._shape
        if self._bit_depth == 8:
            pixel_format = "rgb24" if self._channel_count == RGB_CHANNEL_COUNT else "rgba"
        else:
            pixel_format = "rgb48be" if self._channel_count == RGB_CHANNEL_COUNT else "rgba64be"
        frame = av.VideoFrame(width, height, format=pixel_format)
        plane = memoryview(frame.planes[0]).cast("B")
        row_stride = frame.planes[0].line_size
        bytes_per_sample = self._bit_depth // 8
        unit_offset = 0
        pixel_offset = 0
        for original, fixed_bytes in self.iter_chunks_with_fixed_bytes():
            if fixed_bytes_callback is not None:
                fixed_bytes_callback(unit_offset, original, fixed_bytes)
            if original.size == 0:
                continue
            replaced = _validate_transformed_units(
                transform(unit_offset, original), original.size
            )
            pixel_count = original.size // RGB_CHANNEL_COUNT
            source_pixels = self._pixels_by_channel[
                pixel_offset:pixel_offset + pixel_count
            ]
            if self._bit_depth == 8:
                if self._channel_count == RGBA_CHANNEL_COUNT:
                    output_pixels = np.empty((pixel_count, RGBA_CHANNEL_COUNT), dtype=np.uint8)
                    output_pixels[:, :RGB_CHANNEL_COUNT] = replaced.reshape(
                        (pixel_count, RGB_CHANNEL_COUNT)
                    )
                    output_pixels[:, RGB_CHANNEL_COUNT] = np.frombuffer(
                        fixed_bytes, dtype=np.uint8
                    )
                else:
                    output_pixels = replaced.reshape((pixel_count, RGB_CHANNEL_COUNT))
                output_bytes = memoryview(output_pixels).cast("B")
            else:
                output_pixels = source_pixels.copy()
                output_pixels[:, :RGB_CHANNEL_COUNT] = (
                    output_pixels[:, :RGB_CHANNEL_COUNT] & np.uint16(0xFF00)
                ) | replaced.reshape((pixel_count, RGB_CHANNEL_COUNT)).astype(np.uint16)
                output_bytes = memoryview(output_pixels.astype(">u2", copy=False)).cast("B")
            channel_bytes = self._channel_count * bytes_per_sample
            chunk_pixel_offset = 0
            while chunk_pixel_offset < pixel_count:
                row, column = divmod(pixel_offset + chunk_pixel_offset, width)
                row_pixels = min(pixel_count - chunk_pixel_offset, width - column)
                byte_count = row_pixels * channel_bytes
                destination = row * row_stride + column * channel_bytes
                source = chunk_pixel_offset * channel_bytes
                plane[destination:destination + byte_count] = output_bytes[
                    source:source + byte_count
                ]
                chunk_pixel_offset += row_pixels
            unit_offset += original.size
            pixel_offset += pixel_count
        _save_png_frame_to_path(frame, output_path, self._path)


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
    def path(self) -> str | bytes | PathLike[str]:
        """Return the path used to load this WAV carrier."""
        return self._path

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
        """Copy the WAV byte for byte and change only the declared sample LSBs.

        All chunks before and after the data chunk, the header, pad bytes, and
        data bytes after the last whole frame stay the same. The file is read
        and written in chunks of whole frames.
        """
        if not isinstance(output_path, (str, bytes, PathLike)):
            raise TypeError("output_path must be a filesystem path")
        sample_width = self.info.sample_width
        chunk_bytes = self.frames_per_chunk * self.info.bytes_per_frame
        sample_bytes = self.info.frame_count * self.info.bytes_per_frame
        try:
            with open(fspath(self._path), "rb") as source_file:
                data_offset = self._checked_data_offset(source_file)
                with open(fspath(output_path), "wb") as output_file:
                    _copy_file_bytes(source_file, output_file, 0, data_offset)
                    source_file.seek(data_offset)
                    unit_offset = 0
                    remaining = sample_bytes
                    while remaining:
                        read_size = min(chunk_bytes, remaining)
                        raw = source_file.read(read_size)
                        if len(raw) != read_size:
                            raise CarrierAccessError("WAV data ended before its declared frame count")
                        original, fixed_bytes = self._units_and_fixed_from_frames(raw)
                        if fixed_bytes_callback is not None:
                            fixed_bytes_callback(unit_offset, original, fixed_bytes)
                        replaced = _validate_transformed_units(
                            transform(unit_offset, original), original.size
                        )
                        frame_bytes = bytearray(raw)
                        frame_bytes[0::sample_width] = replaced.tobytes()
                        output_file.write(frame_bytes)
                        unit_offset += original.size
                        remaining -= read_size
                    _copy_file_bytes(source_file, output_file, data_offset + sample_bytes, None)
        except _WAV_READ_ERRORS as error:
            raise CarrierAccessError("could not save uncompressed PCM WAV") from error

    def _checked_data_offset(self, source_file: io.BufferedIOBase) -> int:
        """Find the data chunk and check it against the wave module.

        The wave reader stops just after the data chunk header, so its file
        position must equal the parsed data offset. The declared data size
        must give the same whole-frame count.
        """
        data_offset, data_size = _find_wav_data_chunk(source_file)
        source_file.seek(0)
        wav_file = wave.open(source_file, "rb")
        try:
            info = _read_wav_info(wav_file)
            wave_data_offset = source_file.tell()
        finally:
            wav_file.close()
        if info != self.info:
            raise CarrierAccessError("WAV carrier header changed after it was opened")
        if data_offset != wave_data_offset or data_size // info.bytes_per_frame != info.frame_count:
            raise ValueError("WAV data chunk location does not match the wave module")
        return data_offset


def _find_wav_data_chunk(source_file: io.BufferedIOBase) -> tuple[int, int]:
    """Return the offset and declared size of the first RIFF data chunk.

    RIFF chunk headers are an ID and a little-endian u32 size. A chunk with an
    odd size is followed by one pad byte.
    """
    source_file.seek(0)
    header = source_file.read(12)
    if len(header) != 12 or header[:4] != b"RIFF" or header[8:12] != b"WAVE":
        raise ValueError("WAV file does not start with a RIFF WAVE header")
    offset = 12
    while True:
        source_file.seek(offset)
        chunk_header = source_file.read(8)
        if len(chunk_header) != 8:
            raise ValueError("WAV file has no data chunk")
        chunk_id, chunk_size = struct.unpack("<4sI", chunk_header)
        if chunk_id == b"data":
            return offset + 8, chunk_size
        offset += 8 + chunk_size + (chunk_size & 1)
