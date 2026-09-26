"""Convert supported image and audio sources to strict PNG/WAV snapshots.

Strict PNG and PCM WAV carriers bypass conversion. Other supported inputs are
read once by PyAV and written to a private, temporary canonical carrier.
"""

import os
import re
import struct
import tempfile
import wave
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from os import PathLike, fspath
from pathlib import Path

import av
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa

from .core import (
    _paths_resolve_same,
    encode_png,
    encode_png_from_payload_path,
    encode_wav,
    encode_wav_from_payload_path,
)
from .layout import EmbeddingLayout
from .media import (
    _PNG_MAX_DECODED_BYTES,
    PngCarrier,
    UnSupportedFileType,
    WavCarrier,
)
from .packet import PayloadFileRecord, PayloadRecord
from .video import _audio_layout_identities


_MAX_RIFF_DATA_BYTES = 0xFFFFFFFF - 36
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_CORE_CHUNKS = frozenset((b"IHDR", b"IDAT", b"IEND"))
_PNG_COLOR_CHUNKS = frozenset((b"iCCP", b"cICP", b"sRGB", b"gAMA", b"cHRM", b"mDCV", b"cLLI"))
_PNG_DROP_CHUNKS = frozenset((b"pHYs", b"eXIf", b"tEXt", b"zTXt", b"iTXt", b"sBIT"))
_ACCEPTED_SOURCE_MESSAGE = (
    "unsupported or unreadable source; upload an image (PNG, JPEG, WebP, AVIF, "
    "BMP, TIFF, GIF) or audio (WAV, MP3, AAC/M4A, FLAC, ALAC, Ogg Vorbis/Opus) file"
)


def detect_source_family(path: str | bytes | PathLike[str]) -> tuple[str, str]:
    """Return the source family and detected format for a supported source."""
    source_path = Path(os.fsdecode(fspath(path)))
    with source_path.open("rb") as source:
        signature = source.read(16)
    if signature.startswith(_PNG_SIG):
        return "image", "png"
    if len(signature) == 16 and signature[:4] == b"RIFF" and signature[8:12] == b"WAVE":
        return "audio", "wav"
    if signature.startswith(b"\xff\xd8"):
        image_signature_format = "jpeg"
    elif signature.startswith((b"GIF87a", b"GIF89a")):
        image_signature_format = "gif"
    elif signature.startswith((b"II*\x00", b"MM\x00*")):
        image_signature_format = "tiff"
    elif signature.startswith(b"BM"):
        image_signature_format = "bmp"
    elif signature.startswith(b"\x76\x2f\x31\x01"):
        image_signature_format = "exr"
    elif signature[:4] == b"RIFF" and signature[8:12] == b"WEBP":
        image_signature_format = "webp"
    elif signature[4:8] == b"ftyp" and signature[8:12] in (b"avif", b"avis"):
        image_signature_format = "avif"
    else:
        image_signature_format = ""

    try:
        with av.open(str(source_path), mode="r") as container:
            video_streams = [stream for stream in container.streams if stream.type == "video"]
            audio_streams = [stream for stream in container.streams if stream.type == "audio"]
            real_video_streams = [
                stream for stream in video_streams
                if not (stream.disposition & av.stream.Disposition.attached_pic)
            ]
            if audio_streams and real_video_streams:
                raise ValueError("video covers are not supported in the web app")
            if audio_streams:
                codec_name = audio_streams[0].codec_context.name.lower()
                if codec_name.startswith("mp3"):
                    source_format = "mp3"
                elif codec_name == "flac":
                    source_format = "flac"
                elif codec_name == "alac":
                    source_format = "alac"
                elif codec_name == "vorbis":
                    source_format = "ogg-vorbis"
                elif codec_name == "opus":
                    source_format = "ogg-opus"
                elif codec_name == "aac":
                    source_format = "m4a" if signature[4:8] == b"ftyp" else "aac"
                else:
                    source_format = codec_name
                if signature.startswith(b"fLaC"):
                    source_format = "flac"
                elif signature.startswith(b"OggS"):
                    source_format = "ogg-vorbis" if codec_name == "vorbis" else "ogg-opus"
                return "audio", source_format
            if image_signature_format and video_streams:
                return "image", image_signature_format
            if real_video_streams:
                raise ValueError("video covers are not supported in the web app")
    except (OSError, TypeError, av.error.FFmpegError) as error:
        raise ValueError(_ACCEPTED_SOURCE_MESSAGE) from error
    except ValueError as error:
        if str(error) == "video covers are not supported in the web app":
            raise
        raise ValueError(_ACCEPTED_SOURCE_MESSAGE) from error
    if signature[:4] == b"RIFF" and signature[8:12] == b"WAVE":
        return "audio", "wav"
    raise ValueError(_ACCEPTED_SOURCE_MESSAGE)


def _reject_cmyk(is_cmyk: bool) -> None:
    """Refuse CMYK sources until a colour-managed conversion path is approved."""
    if is_cmyk:
        raise ValueError("CMYK images are not supported")


def _chunk_crc_is_valid(chunk_type: bytes, data: bytes, expected: int) -> bool:
    """Check one PNG chunk checksum."""
    return zlib.crc32(data, zlib.crc32(chunk_type)) & 0xFFFFFFFF == expected


def _read_png_header(path: Path) -> tuple[int, int, int, int] | None:
    """Return width, height, depth, colour type for a well-formed IHDR."""
    with path.open("rb") as source:
        header = source.read(33)
    if (
        len(header) != 33
        or header[:8] != _PNG_SIG
        or header[12:16] != b"IHDR"
        or struct.unpack_from(">I", header, 8)[0] != 13
        or not _chunk_crc_is_valid(b"IHDR", header[16:29], struct.unpack_from(">I", header, 29)[0])
    ):
        return None
    width, height, depth, colour_type, compression, filter_method, interlace = struct.unpack(
        ">IIBBBBB", header[16:29]
    )
    if width < 1 or height < 1 or compression != 0 or filter_method != 0 or interlace not in (0, 1):
        return None
    return width, height, depth, colour_type


def _png_chunk_data(path: Path, wanted: frozenset[bytes]) -> tuple[dict[bytes, bytes], bool]:
    """Validate PNG chunk framing and CRCs; return only selected small chunks."""
    selected: dict[bytes, bytes] = {}
    has_animation = False
    with path.open("rb") as source:
        if source.read(8) != _PNG_SIG:
            raise ValueError("invalid PNG header")
        found_end = False
        while not found_end:
            raw_header = source.read(8)
            if len(raw_header) != 8:
                raise ValueError("unreadable PNG image")
            length, chunk_type = struct.unpack(">I4s", raw_header)
            crc = zlib.crc32(chunk_type)
            keep = chunk_type in wanted or chunk_type == b"acTL"
            data = bytearray() if keep and length <= 16 * 1024 * 1024 else None
            remaining = length
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError("unreadable PNG image")
                crc = zlib.crc32(block, crc)
                if data is not None:
                    data.extend(block)
                remaining -= len(block)
            expected_bytes = source.read(4)
            if len(expected_bytes) != 4 or (crc & 0xFFFFFFFF) != struct.unpack(">I", expected_bytes)[0]:
                raise ValueError("unreadable PNG image")
            if chunk_type == b"acTL":
                has_animation = True
            elif keep and data is None:
                selected[chunk_type] = b""
            elif data is not None:
                selected[chunk_type] = bytes(data)
            if chunk_type == b"IEND":
                found_end = True
    return selected, has_animation


def _tiff_orientation(data: bytes) -> int | None:
    """Read TIFF IFD0 orientation from a bounded EXIF byte string."""
    if data.startswith(b"Exif\x00\x00"):
        data = data[6:]
    if len(data) < 8:
        return None
    endian = "<" if data[:2] == b"II" else ">" if data[:2] == b"MM" else None
    if endian is None or struct.unpack_from(endian + "H", data, 2)[0] != 42:
        return None
    ifd_offset = struct.unpack_from(endian + "I", data, 4)[0]
    if ifd_offset + 2 > len(data):
        return None
    entry_count = struct.unpack_from(endian + "H", data, ifd_offset)[0]
    if entry_count > 4096 or ifd_offset + 2 + entry_count * 12 > len(data):
        return None
    for index in range(entry_count):
        entry = ifd_offset + 2 + index * 12
        tag, field_type, count = struct.unpack_from(endian + "HHI", data, entry)
        if tag == 0x0112 and field_type == 3 and count == 1:
            orientation = struct.unpack_from(endian + "H", data, entry + 8)[0]
            return orientation if 1 <= orientation <= 8 else None
    return None


def _jpeg_metadata(path: Path) -> tuple[int | None, bool, int | None]:
    """Read JPEG EXIF orientation, ICC presence, and SOF component count."""
    orientation: int | None = None
    has_icc = False
    components: int | None = None
    with path.open("rb") as source:
        if source.read(2) != b"\xff\xd8":
            return None, False, None
        while True:
            byte = source.read(1)
            if not byte:
                break
            if byte != b"\xff":
                continue
            marker_byte = source.read(1)
            while marker_byte == b"\xff":
                marker_byte = source.read(1)
            if not marker_byte:
                break
            marker = marker_byte[0]
            if marker in (0xD9, 0xDA):
                break
            if 0xD0 <= marker <= 0xD7 or marker == 0x01:
                continue
            length_bytes = source.read(2)
            if len(length_bytes) != 2:
                break
            length = int.from_bytes(length_bytes, "big")
            if length < 2:
                break
            payload = source.read(length - 2)
            if len(payload) != length - 2:
                break
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                orientation = _tiff_orientation(payload)
            elif marker == 0xE2 and payload.startswith(b"ICC_PROFILE\x00"):
                has_icc = True
            elif marker in set(range(0xC0, 0xC4)) | set(range(0xC5, 0xC8)) | set(range(0xC9, 0xCC)) | set(range(0xCD, 0xD0)):
                if len(payload) >= 6:
                    components = payload[5]
    return orientation, has_icc, components


def _webp_metadata(path: Path) -> tuple[int | None, bool, bool, bool]:
    """Read WebP EXIF orientation, ICC, alpha, and animation flags."""
    orientation: int | None = None
    has_icc = False
    has_alpha = False
    animated = False
    with path.open("rb") as source:
        header = source.read(12)
        if len(header) != 12 or header[:4] != b"RIFF" or header[8:] != b"WEBP":
            return None, False, False, False
        while True:
            chunk_header = source.read(8)
            if len(chunk_header) != 8:
                break
            chunk_type = chunk_header[:4]
            length = int.from_bytes(chunk_header[4:], "little")
            if chunk_type in (b"ANIM", b"ANMF"):
                animated = True
            if chunk_type == b"ALPH":
                has_alpha = True
            if chunk_type == b"VP8X" and length:
                flags = source.read(1)
                if flags:
                    has_alpha = has_alpha or bool(flags[0] & 0x10)
                    has_icc = has_icc or bool(flags[0] & 0x20)
                source.seek(length - len(flags), os.SEEK_CUR)
            elif chunk_type == b"ICCP":
                has_icc = True
                source.seek(length, os.SEEK_CUR)
            elif chunk_type == b"EXIF" and length <= 16 * 1024 * 1024:
                orientation = _tiff_orientation(source.read(length))
            else:
                source.seek(length, os.SEEK_CUR)
            if length & 1:
                source.seek(1, os.SEEK_CUR)
    return orientation, has_icc, has_alpha, animated


def _gif_metadata(path: Path) -> tuple[bool, bool]:
    """Read GIF image-block count and transparency flags without LZW decode."""
    with path.open("rb") as source:
        header = source.read(13)
        if len(header) != 13 or header[:6] not in (b"GIF87a", b"GIF89a"):
            return False, False
        packed = header[10]
        if packed & 0x80:
            source.seek(3 * (1 << ((packed & 7) + 1)), os.SEEK_CUR)
        frame_count = 0
        transparent = False
        while True:
            introducer = source.read(1)
            if not introducer:
                break
            kind = introducer[0]
            if kind == 0x3B:
                break
            if kind == 0x21:
                label = source.read(1)
                if label == b"\xF9":
                    size = source.read(1)
                    control = source.read(4) if size == b"\x04" else b""
                    terminator = source.read(1)
                    if len(control) == 4 and terminator == b"\x00":
                        transparent = transparent or bool(control[0] & 1)
                    else:
                        return False, False
                else:
                    while True:
                        size = source.read(1)
                        if not size or size == b"\x00":
                            break
                        source.seek(size[0], os.SEEK_CUR)
                continue
            if kind == 0x2C:
                descriptor = source.read(9)
                if len(descriptor) != 9:
                    return False, False
                local_flags = descriptor[8]
                if local_flags & 0x80:
                    source.seek(3 * (1 << ((local_flags & 7) + 1)), os.SEEK_CUR)
                if not source.read(1):
                    return False, False
                frame_count += 1
                while True:
                    size = source.read(1)
                    if not size or size == b"\x00":
                        break
                    source.seek(size[0], os.SEEK_CUR)
                if frame_count > 1:
                    return True, transparent
                continue
            return False, False
    return frame_count > 1, transparent


def _read_tiff_orientation(path: Path) -> int | None:
    """Read TIFF IFD0 orientation without loading pixel strips or tiles."""
    with path.open("rb") as source:
        header = source.read(8)
        if len(header) != 8:
            return None
        endian = "<" if header[:2] == b"II" else ">" if header[:2] == b"MM" else None
        if endian is None or struct.unpack_from(endian + "H", header, 2)[0] != 42:
            return None
        ifd_offset = struct.unpack_from(endian + "I", header, 4)[0]
        source.seek(ifd_offset)
        raw_count = source.read(2)
        if len(raw_count) != 2:
            return None
        count = struct.unpack(endian + "H", raw_count)[0]
        if count > 4096:
            return None
        entries = source.read(count * 12)
        if len(entries) != count * 12:
            return None
        for index in range(count):
            entry = index * 12
            tag, field_type, value_count = struct.unpack_from(endian + "HHI", entries, entry)
            if tag == 0x0112 and field_type == 3 and value_count == 1:
                value = struct.unpack_from(endian + "H", entries, entry + 8)[0]
                return value if 1 <= value <= 8 else None
    return None


def _tiff_photometric(path: Path) -> int | None:
    """Read TIFF IFD0 photometric interpretation without reading pixel strips."""
    with path.open("rb") as source:
        header = source.read(8)
        if len(header) != 8:
            return None
        endian = "<" if header[:2] == b"II" else ">" if header[:2] == b"MM" else None
        if endian is None or struct.unpack_from(endian + "H", header, 2)[0] != 42:
            return None
        source.seek(struct.unpack_from(endian + "I", header, 4)[0])
        count_bytes = source.read(2)
        if len(count_bytes) != 2:
            return None
        count = struct.unpack(endian + "H", count_bytes)[0]
        if count > 4096:
            return None
        entries = source.read(count * 12)
        if len(entries) != count * 12:
            return None
        for index in range(count):
            entry = index * 12
            tag, field_type, value_count = struct.unpack_from(endian + "HHI", entries, entry)
            if tag == 262 and field_type == 3 and value_count == 1:
                return struct.unpack_from(endian + "H", entries, entry + 8)[0]
    return None


def _image_metadata(
    path: Path, png_chunks: dict[bytes, bytes] | None
) -> tuple[int | None, bool, bool, bool]:
    """Return orientation, ICC presence, CMYK, and alpha metadata from headers."""
    with path.open("rb") as source:
        signature = source.read(12)
    if png_chunks is not None:
        orientation = _tiff_orientation(png_chunks.get(b"eXIf", b""))
        return orientation, b"iCCP" in png_chunks, False, False
    if signature[:2] == b"\xff\xd8":
        orientation, has_icc, components = _jpeg_metadata(path)
        return orientation, has_icc, components == 4, False
    if signature[:4] == b"RIFF" and signature[8:12] == b"WEBP":
        orientation, has_icc, has_alpha, animated = _webp_metadata(path)
        if animated:
            raise ValueError("animated WebP images are not supported")
        return orientation, has_icc, False, has_alpha
    if signature[:6] in (b"GIF87a", b"GIF89a"):
        animated, has_alpha = _gif_metadata(path)
        if animated:
            raise ValueError("animated GIF images are not supported")
        return None, False, False, has_alpha
    if signature[:4] in (b"II*\x00", b"MM\x00*"):
        return _read_tiff_orientation(path), False, _tiff_photometric(path) == 5, False
    return None, False, False, False


def _orientation_filters(orientation: int | None) -> tuple[tuple[str, str | None], ...]:
    """Return verified FFmpeg transforms for EXIF orientation values 1–8."""
    return {
        None: (),
        1: (),
        2: (("hflip", None),),
        3: (("transpose", "dir=clock"), ("transpose", "dir=clock")),
        4: (("transpose", "dir=clock"), ("hflip", None), ("transpose", "dir=cclock")),
        5: (("transpose", "dir=clock"), ("hflip", None)),
        6: (("transpose", "dir=clock"),),
        7: (("transpose", "dir=cclock"), ("hflip", None)),
        8: (("transpose", "dir=cclock"),),
    }[orientation]


def _source_depth(pixel_format: av.VideoFormat | None) -> tuple[int, bool, bool]:
    """Return largest component depth, float flag, and format alpha flag."""
    if pixel_format is None:
        return 0, False, False
    component_depth = max((component.bits for component in pixel_format.components), default=0)
    name = pixel_format.name.lower()
    is_float = bool(re.search(r"(?:f16|f32|f64)(?:le|be|$)", name))
    has_alpha = any(component.is_alpha for component in pixel_format.components)
    return component_depth, is_float, has_alpha


def _pixel_cap(width: int, height: int, channels: int, depth: int) -> None:
    """Refuse a canonical image that exceeds the decoded-byte cap."""
    decoded_bytes = width * height * channels * (depth // 8)
    if decoded_bytes > _PNG_MAX_DECODED_BYTES:
        raise ValueError(
            "PNG decoded size exceeds configured limit: "
            f"{decoded_bytes} bytes > {_PNG_MAX_DECODED_BYTES} bytes"
        )


def _write_png_frame(
    frame: av.VideoFrame,
    path: Path,
    depth: int,
    channels: int,
    source_stream: av.video.stream.VideoStream,
    has_icc: bool,
) -> None:
    """Encode one PyAV frame as a PNG snapshot."""
    pixel_format = (
        ("rgb24" if channels == 3 else "rgba")
        if depth == 8
        else ("rgb48be" if channels == 3 else "rgba64be")
    )
    with av.open(str(path), mode="w", format="image2pipe") as output:
        stream = output.add_stream("png")
        stream.width = frame.width
        stream.height = frame.height
        stream.pix_fmt = pixel_format
        if not has_icc:
            stream.codec_context.color_range = 2
            stream.codec_context.colorspace = 0
            stream.codec_context.color_primaries = (
                source_stream.codec_context.color_primaries
                if source_stream.codec_context.color_primaries in (1, 4, 5, 6, 7, 9, 10, 11, 12, 22)
                else 1
            )
            stream.codec_context.color_trc = (
                source_stream.codec_context.color_trc
                if source_stream.codec_context.color_trc in (1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18)
                else 13
            )
        for packet in (*stream.encode(frame), *stream.encode(None)):
            output.mux(packet)


def _rewrite_png_snapshot(path: Path, destination: Path, source_color_chunks: dict[bytes, bytes]) -> None:
    """Keep only image data and selected colour chunks in a canonical PNG."""
    temporary = destination.with_suffix(".filtered.png")
    has_icc = False
    with path.open("rb") as source, temporary.open("wb") as output:
        if source.read(8) != _PNG_SIG:
            raise ValueError("PNG encoder produced an invalid snapshot")
        output.write(_PNG_SIG)
        chunks: list[tuple[bytes, int, int]] = []
        while True:
            position = source.tell()
            header = source.read(8)
            if len(header) != 8:
                raise ValueError("PNG encoder produced an incomplete snapshot")
            length, chunk_type = struct.unpack(">I4s", header)
            source.seek(length + 4, os.SEEK_CUR)
            chunks.append((chunk_type, position, length))
            if chunk_type == b"IEND":
                break
            if chunk_type == b"iCCP":
                has_icc = True
        wanted = set(_PNG_CORE_CHUNKS | _PNG_COLOR_CHUNKS)
        if has_icc:
            wanted.difference_update((b"sRGB", b"gAMA", b"cHRM"))
            if b"cICP" not in source_color_chunks:
                wanted.discard(b"cICP")
        present = {chunk_type for chunk_type, _, _ in chunks}
        add_chunks = {
            kind: data
            for kind, data in source_color_chunks.items()
            if kind in (b"cICP", b"mDCV", b"cLLI") and kind not in present
        }
        inserted = False
        rewritten_source_chunks: set[bytes] = set()
        for chunk_type, position, length in chunks:
            if chunk_type in source_color_chunks:
                if chunk_type not in rewritten_source_chunks:
                    output.write(_png_chunk(chunk_type, source_color_chunks[chunk_type]))
                    rewritten_source_chunks.add(chunk_type)
                continue
            if chunk_type == b"IDAT" and not inserted:
                for kind, data in add_chunks.items():
                    output.write(_png_chunk(kind, data))
                inserted = True
            if chunk_type not in wanted:
                continue
            source.seek(position)
            remaining = 12 + length
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError("PNG encoder produced a truncated chunk")
                output.write(block)
                remaining -= len(block)
    temporary.replace(destination)


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build one PNG chunk with a CRC."""
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(data, zlib.crc32(chunk_type)) & 0xFFFFFFFF)


def _set_color_parameters(
    graph: av.filter.Graph,
    previous: av.filter.context.FilterContext,
    stream: av.video.stream.VideoStream,
) -> av.filter.context.FilterContext:
    """Tag RGB output with FFmpeg's source primaries/transfer and RGB matrix."""
    primaries = {
        1: "bt709", 4: "bt470m", 5: "bt470bg", 6: "smpte170m", 7: "smpte240m",
        9: "bt2020", 10: "smpte428", 11: "smpte431", 12: "smpte432", 22: "jedec-p22",
    }.get(stream.codec_context.color_primaries, "bt709")
    transfer = {
        1: "bt709", 4: "bt470m", 5: "bt470bg", 6: "smpte170m", 7: "smpte240m",
        8: "linear", 9: "log100", 10: "log316", 11: "iec61966-2-4", 12: "bt1361e",
        13: "iec61966-2-1", 14: "bt2020-10", 15: "bt2020-12", 16: "smpte2084",
        17: "smpte428", 18: "arib-std-b67",
    }.get(stream.codec_context.color_trc, "iec61966-2-1")
    tagged = graph.add(
        "setparams",
        f"range=full:colorspace=gbr:color_primaries={primaries}:color_trc={transfer}",
    )
    previous.link_to(tagged)
    return tagged


def _apply_16bit_transparency_key(
    frame: av.VideoFrame, key: tuple[int, int, int]
) -> av.VideoFrame:
    """Add exact 16-bit alpha for a truecolour PNG transparency key."""
    rgb = frame.to_ndarray(format="rgb48be").astype(np.uint16)
    rgba = np.empty((frame.height, frame.width, 4), dtype=np.uint16)
    rgba[:, :, :3] = rgb
    rgba[:, :, 3] = np.where(
        np.all(rgb == np.asarray(key, dtype=np.uint16), axis=2), 0, 65535
    )
    result = av.VideoFrame.from_ndarray(rgba, format="rgba64be")
    result.pts = frame.pts
    result.time_base = frame.time_base
    return result


def _decoded_image_frames(
    container: av.container.InputContainer, stream: av.video.stream.VideoStream
) -> Iterator[av.VideoFrame]:
    """Decode the selected image stream once."""
    yield from container.decode(stream)


def _convert_image(path: Path, snapshot: Path) -> None:
    """Decode one supported image and write its single canonical PNG snapshot."""
    with path.open("rb") as source:
        signature = source.read(16)
    is_supported = (
        signature.startswith((
            _PNG_SIG, b"\xff\xd8", b"GIF87a", b"GIF89a", b"II*\x00",
            b"MM\x00*", b"BM", b"\x76\x2f\x31\x01",
        ))
        or (signature[:4] == b"RIFF" and signature[8:12] == b"WEBP")
        or (signature[4:8] == b"ftyp" and signature[8:12] in (b"avif", b"avis"))
    )
    if not is_supported:
        raise ValueError("unsupported image source format")
    png_header = _read_png_header(path)
    png_chunks: dict[bytes, bytes] | None = None
    with path.open("rb") as source:
        signature = source.read(12)
    is_png = signature[:8] == _PNG_SIG
    if is_png and png_header is None:
        try:
            PngCarrier(path)
        except (OSError, ValueError, UnSupportedFileType):
            raise
        raise ValueError("invalid PNG header")

    orientation: int | None = None
    has_icc = False
    alpha_from_header = False
    source_color_chunks: dict[bytes, bytes] = {}
    if png_header is not None:
        width, height, source_depth, colour_type = png_header
        png_chunks, animated = _png_chunk_data(
            path, frozenset((b"tRNS", b"eXIf", b"iCCP", b"cICP", b"mDCV", b"cLLI"))
        )
        if animated:
            raise ValueError("animated PNG images are not supported")
        orientation = _tiff_orientation(png_chunks.get(b"eXIf", b""))
        has_icc = b"iCCP" in png_chunks
        alpha_from_header = colour_type in (4, 6) or b"tRNS" in png_chunks
        source_color_chunks = {
            kind: png_chunks[kind]
            for kind in (b"cICP", b"mDCV", b"cLLI")
            if kind in png_chunks
        }
        if source_depth > 16:
            raise ValueError("image sample depth greater than 16 bits is not supported")
        depth = 8 if source_depth <= 8 else 16
        if orientation in (5, 6, 7, 8):
            width, height = height, width
        channels = 4 if alpha_from_header else 3
        _pixel_cap(width, height, channels, depth)
    else:
        orientation, has_icc, is_cmyk, alpha_from_header = _image_metadata(path, None)
        _reject_cmyk(is_cmyk)
        with path.open("rb") as source:
            signature = source.read(12)
        if signature[:6] in (b"GIF87a", b"GIF89a"):
            animated, alpha_from_header = _gif_metadata(path)
            if animated:
                raise ValueError("animated GIF images are not supported")
        if signature[:4] == b"RIFF" and signature[8:12] == b"WEBP":
            _, _, _, animated = _webp_metadata(path)
            if animated:
                raise ValueError("animated WebP images are not supported")

    with av.open(str(path), mode="r") as container:
        video_streams = [stream for stream in container.streams if stream.type == "video"]
        if not video_streams:
            raise ValueError("image source has no video stream")
        stream = video_streams[0]
        codec = stream.codec_context
        width = codec.width
        height = codec.height
        if orientation in (5, 6, 7, 8):
            width, height = height, width
        source_depth, is_float, format_alpha = _source_depth(codec.format)
        if width < 1 or height < 1:
            raise ValueError("image dimensions must be greater than zero")
        _reject_cmyk(
            codec.format is not None
            and codec.format.name == "gbrap"
            and not alpha_from_header
            and path.suffix.lower() in (".tif", ".tiff")
            and _tiff_photometric(path) == 5
        )
        if is_float or (source_depth > 16 and png_header is None):
            raise ValueError("image sample depth greater than 16 bits is not supported")
        if source_depth < 1:
            raise ValueError("could not determine image sample depth")
        if png_header is None:
            depth = 8 if source_depth <= 8 else 16
            channels = 4 if (alpha_from_header or format_alpha) else 3
            if signature[:6] in (b"GIF87a", b"GIF89a"):
                channels = 4 if alpha_from_header else 3
            _pixel_cap(width, height, channels, depth)
        try:
            codec.max_pixels = max(
                1_000_000,
                _PNG_MAX_DECODED_BYTES // (channels * (depth // 8)) + 1,
            )
        except (AttributeError, ValueError):
            pass
        if stream.frames > 1:
            raise ValueError("animated image sources are not supported")
        decoded_frames = 0
        for frame in _decoded_image_frames(container, stream):
            decoded_frames += 1
            if decoded_frames > 1:
                raise ValueError("animated image sources are not supported")
            transparency_key: tuple[int, int, int] | None = None
            if (
                png_header is not None
                and png_header[3] == 2
                and png_chunks is not None
                and b"tRNS" in png_chunks
            ):
                key = struct.unpack(">HHH", png_chunks[b"tRNS"])
                transparency_key = (
                    tuple(value & 0xFF for value in key)
                    if depth == 8
                    else key
                )
                if depth == 16:
                    frame = _apply_16bit_transparency_key(frame, transparency_key)
            decoded_format = frame.format
            frame_depth, frame_float, frame_alpha = _source_depth(decoded_format)
            if (
                frame_float
                or frame_depth > 16
                or (source_depth <= 8 and frame_depth > 8)
                or (source_depth > 8 and frame_depth != source_depth)
            ):
                raise ValueError("image sample depth greater than 16 bits is not supported")
            channels = 4 if (alpha_from_header or frame_alpha) else 3
            if signature[:6] in (b"GIF87a", b"GIF89a"):
                channels = 4 if alpha_from_header else 3
            graph = av.filter.Graph()
            buffer = graph.add_buffer(template=frame)
            previous = buffer
            for name, arguments in _orientation_filters(orientation):
                filtered = graph.add(name, arguments) if arguments is not None else graph.add(name)
                previous.link_to(filtered)
                previous = filtered
            target = (
                ("rgb24" if channels == 3 else "rgba")
                if depth == 8
                else ("rgb48be" if channels == 3 else "rgba64be")
            )
            format_filter = graph.add("format", target)
            previous.link_to(format_filter)
            previous = format_filter
            if transparency_key is not None and depth == 8:
                red, green, blue = transparency_key
                colour_key = graph.add(
                    "colorkey", f"0x{red:02x}{green:02x}{blue:02x}:0.001:0"
                )
                previous.link_to(colour_key)
                previous = colour_key
            if not has_icc:
                previous = _set_color_parameters(graph, previous, stream)
            sink = graph.add("buffersink")
            previous.link_to(sink)
            graph.configure()
            buffer.push(frame)
            buffer.push(None)
            canonical = graph.pull()
            if canonical.width != width or canonical.height != height:
                raise ValueError("image orientation produced unexpected dimensions")
            _write_png_frame(canonical, snapshot, depth, channels, stream, has_icc)
        if decoded_frames == 0:
            raise ValueError("image source contains no decoded frames")
    _rewrite_png_snapshot(snapshot, snapshot, source_color_chunks)


def _origin_matches(carrier: PngCarrier | WavCarrier, path: str | bytes | PathLike[str]) -> bool:
    """Check that a context-managed carrier came from the requested source."""
    origin = getattr(carrier, "_source_original_path", None)
    if origin is None:
        return _paths_resolve_same(carrier.path, path)
    return _paths_resolve_same(origin, path)


@contextmanager
def open_image_source(
    path: str | bytes | PathLike[str],
    staging_parent: str | bytes | PathLike[str],
) -> Iterator[PngCarrier]:
    """Yield a strict PNG carrier or a converted PNG snapshot carrier."""
    source_path = Path(os.fsdecode(fspath(path)))
    png_header = _read_png_header(source_path)
    if png_header is not None:
        _, _, depth, colour_type = png_header
        if colour_type in (2, 6) and depth in (8, 16):
            # Keep the strict adapter's existing cap, decode, animation, and error order.
            with open(source_path, "rb") as source:
                source.seek(8)
                transparency = False
                while True:
                    header = source.read(8)
                    if len(header) != 8:
                        break
                    length, kind = struct.unpack(">I4s", header)
                    if kind == b"tRNS":
                        transparency = True
                    if kind == b"IEND":
                        break
                    source.seek(length + 4, os.SEEK_CUR)
            if not (colour_type == 2 and transparency):
                carrier = PngCarrier(path)
                carrier._source_original_path = Path(os.path.realpath(source_path))
                yield carrier
                return
        # A valid but unsupported PNG mode/depth, or RGB+tRNS, is format refusal.
        try:
            _png_chunk_data(source_path, frozenset((b"tRNS", b"eXIf", b"iCCP", b"cICP", b"mDCV", b"cLLI")))
        except ValueError:
            # Preserve the strict adapter's error rather than converting corrupt input.
            PngCarrier(path)
            raise
    elif source_path.suffix.lower() == ".png":
        # A PNG-looking name with a damaged header must retain today's strict error.
        try:
            PngCarrier(path)
        except (OSError, ValueError, UnSupportedFileType):
            raise

    with tempfile.TemporaryDirectory(prefix=".stego-source-", dir=staging_parent) as directory:
        snapshot = Path(directory) / "source.png"
        try:
            _convert_image(source_path, snapshot)
        except av.error.FFmpegError as error:
            raise ValueError(_ACCEPTED_SOURCE_MESSAGE) from error
        carrier = PngCarrier(snapshot)
        carrier._source_original_path = Path(os.path.realpath(source_path))
        yield carrier


def _wav_format_code(path: Path) -> int | None:
    """Read the WAVE fmt tag without decoding audio data."""
    with path.open("rb") as source:
        header = source.read(12)
        if len(header) != 12 or header[:4] != b"RIFF" or header[8:] != b"WAVE":
            return None
        while True:
            chunk_header = source.read(8)
            if len(chunk_header) != 8:
                return None
            kind = chunk_header[:4]
            length = struct.unpack_from("<I", chunk_header, 4)[0]
            if kind == b"fmt ":
                data = source.read(min(length, 64))
                if len(data) < 16:
                    return -1
                tag = struct.unpack_from("<H", data)[0]
                if tag == 0xFFFE and len(data) >= 40:
                    return struct.unpack_from("<H", data, 24)[0]
                return tag
            source.seek(length + (length & 1), os.SEEK_CUR)


def _audio_integer_width(stream: av.audio.stream.AudioStream) -> int | None:
    """Return lossless integer source depth from codec name or codec extradata."""
    codec = stream.codec_context
    name = codec.name.lower()
    if name.startswith("pcm_"):
        match = re.search(r"(?:s|u)(8|16|24|32)(?:be|le|_planar|$)", name)
        return int(match.group(1)) if match else None
    extradata = bytes(codec.extradata or b"")
    if name == "flac":
        streaminfo_offset = 0
        if extradata.startswith(b"fLaC"):
            offset = 4
            while offset + 4 <= len(extradata):
                block_header = extradata[offset]
                block_size = int.from_bytes(extradata[offset + 1:offset + 4], "big")
                offset += 4
                if offset + block_size > len(extradata):
                    return None
                if block_header & 0x7F == 0 and block_size == 34:
                    streaminfo_offset = offset
                    break
                offset += block_size
            else:
                return None
        if len(extradata) >= streaminfo_offset + 18:
            packed_info = int.from_bytes(extradata[streaminfo_offset + 10:streaminfo_offset + 18], "big")
            return ((packed_info >> 36) & 0x1F) + 1
        return None
    if name == "alac":
        if len(extradata) >= 18 and extradata[4:8] == b"alac":
            return extradata[17]
        return None
    return None


def _interleaved_pcm(frame: av.AudioFrame, channels: int, width: int) -> bytes:
    """Pack one decoded integer frame into little-endian PCM at its source width."""
    values = frame.to_ndarray()
    if frame.format.is_planar:
        values = values.reshape((channels, frame.samples)).T.reshape(-1)
    else:
        values = values.reshape(-1)
    if width == 8:
        if values.dtype == np.uint8:
            return values.tobytes()
        signed = (values.astype(np.int16) >> 8).astype(np.int16)
        return (signed + np.int16(128)).astype(np.uint8).tobytes()
    if width == 16:
        return values.astype("<i2", copy=False).tobytes()
    signed = values.astype(np.int32, copy=False)
    if width == 24:
        signed = signed >> 8
        packed = signed.astype("<i4", copy=False).view(np.uint8).reshape(-1, 4)
        return packed[:, :3].tobytes()
    if width == 32:
        return signed.astype("<i4", copy=False).tobytes()
    raise ValueError(f"unsupported lossless integer sample width: {width}")


def _decoded_audio_frames(
    container: av.container.InputContainer, stream: av.audio.stream.AudioStream
) -> Iterator[av.AudioFrame]:
    """Decode the selected audio stream once."""
    yield from container.decode(stream)


def _convert_audio(path: Path, snapshot: Path) -> None:
    """Decode one audio stream and write canonical integer PCM incrementally."""
    with av.open(str(path), mode="r") as container:
        streams = [stream for stream in container.streams if stream.type == "audio"]
        if len(streams) != 1:
            raise ValueError("audio source must contain exactly one audio stream")
        stream = streams[0]
        codec = stream.codec_context
        rate = codec.sample_rate
        if rate is None or rate < 1:
            raise ValueError("invalid audio sample rate")
        identities = _audio_layout_identities(codec.layout)
        channels = len(identities)
        width = _audio_integer_width(stream)
        if width not in (8, 16, 24, 32):
            width = 16
        sample_width = width // 8
        layout = "mono" if channels == 1 else "stereo"
        resampler = None if _audio_integer_width(stream) in (8, 16, 24, 32) else av.AudioResampler(
            format="s16", layout=layout, rate=rate
        )
        bytes_written = 0
        with wave.open(str(snapshot), "wb") as output:
            output.setnchannels(channels)
            output.setsampwidth(sample_width)
            output.setframerate(rate)

            def write_frame(frame: av.AudioFrame) -> None:
                nonlocal bytes_written
                if frame.sample_rate != rate:
                    raise ValueError("audio sample rate changed during decode")
                if len(frame.layout.channels) != channels:
                    raise ValueError("audio channel layout changed during decode")
                raw = (
                    _interleaved_pcm(frame, channels, width)
                    if resampler is None
                    else frame.to_ndarray().astype("<i2", copy=False).tobytes()
                )
                if bytes_written + len(raw) > _MAX_RIFF_DATA_BYTES:
                    raise ValueError("canonical PCM data exceeds the RIFF 4 GiB limit")
                output.writeframesraw(raw)
                bytes_written += len(raw)

            for frame in _decoded_audio_frames(container, stream):
                if frame.sample_rate != rate:
                    raise ValueError("audio sample rate changed during decode")
                if _audio_layout_identities(frame.layout) != identities:
                    raise ValueError("audio channel layout changed during decode")
                if resampler is None:
                    write_frame(frame)
                else:
                    for converted in resampler.resample(frame):
                        write_frame(converted)
            if resampler is not None:
                for converted in resampler.resample(None):
                    write_frame(converted)
        if bytes_written % (channels * sample_width):
            raise ValueError("decoded PCM ended with a partial sample frame")


@contextmanager
def open_audio_source(
    path: str | bytes | PathLike[str],
    staging_parent: str | bytes | PathLike[str],
) -> Iterator[WavCarrier]:
    """Yield a strict PCM WAV carrier or a converted PCM WAV snapshot."""
    source_path = Path(os.fsdecode(fspath(path)))
    format_code = _wav_format_code(source_path)
    if format_code == 1:
        carrier = WavCarrier(path)
        carrier._source_original_path = Path(os.path.realpath(source_path))
        yield carrier
        return
    if format_code == -1:
        WavCarrier(path)
        return
    with source_path.open("rb") as source:
        wave_signature = source.read(12)
    is_wave = len(wave_signature) == 12 and wave_signature[:4] == b"RIFF" and wave_signature[8:] == b"WAVE"
    if is_wave and format_code is None:
        # A malformed WAV name retains the strict reader's error.
        try:
            WavCarrier(path)
        except (OSError, ValueError):
            raise
    with tempfile.TemporaryDirectory(prefix=".stego-source-", dir=staging_parent) as directory:
        snapshot = Path(directory) / "source.wav"
        try:
            _convert_audio(source_path, snapshot)
        except av.error.FFmpegError as error:
            raise ValueError(_ACCEPTED_SOURCE_MESSAGE) from error
        carrier = WavCarrier(snapshot)
        carrier._source_original_path = Path(os.path.realpath(source_path))
        yield carrier


def encode_image(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    user_payload: bytes,
    metadata: bytes,
    *,
    carrier_source: PngCarrier | None = None,
) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode an image source via a strict PNG carrier or temporary snapshot."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    if carrier_source is not None:
        if not _origin_matches(carrier_source, input_path):
            raise ValueError("carrier_source must be opened from input_path")
        return encode_png(
            carrier_source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, user_payload, metadata, carrier_source=carrier_source,
        )
    with open_image_source(input_path, Path(os.fsdecode(fspath(output_path))).parent) as source:
        return encode_png(
            source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, user_payload, metadata, carrier_source=source,
        )


def encode_image_from_payload_path(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
    *,
    carrier_source: PngCarrier | None = None,
) -> tuple[EmbeddingLayout, PayloadFileRecord]:
    """Stream a payload file into an image source's canonical PNG carrier."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    if carrier_source is not None:
        if not _origin_matches(carrier_source, input_path):
            raise ValueError("carrier_source must be opened from input_path")
        return encode_png_from_payload_path(
            carrier_source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, payload_path, metadata, carrier_source=carrier_source,
        )
    with open_image_source(input_path, Path(os.fsdecode(fspath(output_path))).parent) as source:
        return encode_png_from_payload_path(
            source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, payload_path, metadata, carrier_source=source,
        )


def encode_audio(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    user_payload: bytes,
    metadata: bytes,
    *,
    carrier_source: WavCarrier | None = None,
) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode an audio source via a strict WAV carrier or temporary snapshot."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    if carrier_source is not None:
        if not _origin_matches(carrier_source, input_path):
            raise ValueError("carrier_source must be opened from input_path")
        return encode_wav(
            carrier_source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, user_payload, metadata, carrier_source=carrier_source,
        )
    with open_audio_source(input_path, Path(os.fsdecode(fspath(output_path))).parent) as source:
        return encode_wav(
            source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, user_payload, metadata, carrier_source=source,
        )


def encode_audio_from_payload_path(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
    *,
    carrier_source: WavCarrier | None = None,
) -> tuple[EmbeddingLayout, PayloadFileRecord]:
    """Stream a payload file into an audio source's canonical WAV carrier."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    if carrier_source is not None:
        if not _origin_matches(carrier_source, input_path):
            raise ValueError("carrier_source must be opened from input_path")
        return encode_wav_from_payload_path(
            carrier_source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, payload_path, metadata, carrier_source=carrier_source,
        )
    with open_audio_source(input_path, Path(os.fsdecode(fspath(output_path))).parent) as source:
        return encode_wav_from_payload_path(
            source.path, output_path, signing_private_key, receiver_public_key,
            start_unit, lsb_count, payload_path, metadata, carrier_source=source,
        )
