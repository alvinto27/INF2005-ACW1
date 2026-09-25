"""Protocol-level video carrier tests, with PyAV-backed tests optional."""

import importlib.util
import os
import subprocess
import struct
import sys
import unittest
from unittest.mock import patch
from collections.abc import Callable, Iterator
from fractions import Fraction
from os import PathLike
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import numpy as np

from stego import (
    VIDEO_MEDIA_CODE,
    bootstrap_span,
    encode_video,
    encode_video_from_payload_path,
    decode_carrier_source,
    generate_rsa_keypair,
    prepare_carrier_encoding,
)
from stego.carrier import ArrayCarrier, CarrierSource
from stego.core import (
    CarrierEncoding,
    _encode_file_from_payload_path,
    _rewrite_checked,
)
from stego.video import (
    VideoCarrier,
    _audio_layout_identities,
    _audio_position_matches,
    _check_video_conversion,
    _configure_decoder,
    _frame_ticks,
    _round_fraction,
    _video_format_info,
    verify_video,
)
from stego.constants import IMAGE_MEDIA_CODE


VIDEO_CONTEXT = b"in-memory video context"
UNITS = np.arange(20_000, dtype=np.uint8)
SIGNING_PRIVATE_KEY, SIGNING_PUBLIC_KEY = generate_rsa_keypair()
RECEIVER_PRIVATE_KEY, RECEIVER_PUBLIC_KEY = generate_rsa_keypair()


class MemoryVideoCarrier(CarrierSource):
    """Expose adjustable in-memory units and fixed bytes as a video carrier."""

    def __init__(
        self,
        units: np.ndarray,
        *,
        context: bytes = VIDEO_CONTEXT,
        fixed: bytes = b"sidecar",
        reported_units: int | None = None,
        check_requested: bool = True,
        chunk_units: int = 317,
        corrupt_output: bool = False,
    ) -> None:
        self.units = units
        self.context = context
        self.fixed = fixed
        self.reported_units = reported_units
        self.check_requested = check_requested
        self.chunk_units = chunk_units
        self.corrupt_output = corrupt_output
        self.output_closed = False
        self.opened_output: MemoryVideoCarrier | None = None

    @property
    def total_units(self) -> int:
        return self.units.size if self.reported_units is None else self.reported_units

    @property
    def fixed_byte_count(self) -> int:
        return len(self.fixed)

    @property
    def media_code(self) -> int:
        return VIDEO_MEDIA_CODE

    @property
    def media_context(self) -> bytes:
        return self.context

    @property
    def requires_output_check(self) -> bool:
        return self.check_requested

    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        return self.units[start_unit:start_unit + count].copy()

    def iter_chunks(self) -> Iterator[np.ndarray]:
        for offset in range(0, self.units.size, self.chunk_units):
            yield self.units[offset:offset + self.chunk_units].copy()

    def iter_chunks_with_fixed_bytes(self) -> Iterator[tuple[np.ndarray, bytes]]:
        first = True
        for chunk in self.iter_chunks():
            yield chunk, self.fixed if first else b""
            first = False

    def rewrite_to_path(
        self,
        path: str | bytes | PathLike[str],
        transform: Callable[[int, np.ndarray], np.ndarray],
        fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
    ) -> None:
        output = np.empty(self.units.size, dtype=np.uint8)
        offset = 0
        for units, fixed_bytes in self.iter_chunks_with_fixed_bytes():
            if fixed_bytes_callback is not None:
                fixed_bytes_callback(offset, units, fixed_bytes)
            output[offset:offset + units.size] = transform(offset, units)
            offset += units.size
        Path(path).write_bytes(output.tobytes())

    def open_rewritten_output(
        self, path: str | bytes | PathLike[str]
    ) -> CarrierSource:
        output = np.frombuffer(Path(path).read_bytes(), dtype=np.uint8).copy()
        if self.corrupt_output:
            output[-1] ^= np.uint8(0x80)
        self.opened_output = MemoryVideoCarrier(
            output, context=self.context, fixed=self.fixed, check_requested=False
        )
        return self.opened_output

    def close(self) -> None:
        self.output_closed = True


def prepare_test_encoding(source: MemoryVideoCarrier) -> CarrierEncoding:
    """Prepare a small v3 packet in the test video carrier."""
    return prepare_carrier_encoding(
        source,
        VIDEO_MEDIA_CODE,
        VIDEO_CONTEXT,
        SIGNING_PRIVATE_KEY,
        RECEIVER_PUBLIC_KEY,
        bootstrap_span(RECEIVER_PUBLIC_KEY),
        3,
        b"video test payload",
        b"{}",
    )


def make_encoding(
    source: MemoryVideoCarrier | None = None,
) -> tuple[CarrierEncoding, MemoryVideoCarrier, np.ndarray]:
    """Prepare and embed a small packet for output-validation tests."""
    carrier = source or MemoryVideoCarrier(UNITS.copy())
    encoding = prepare_test_encoding(carrier)
    output_chunks = []
    offset = 0
    for units, fixed_bytes in carrier.iter_chunks_with_fixed_bytes():
        encoding.update_fixed_bytes(offset, units, fixed_bytes)
        output_chunks.append(encoding.embed_chunk(offset, units))
        offset += units.size
    output_units = np.concatenate(output_chunks)
    return encoding, carrier, output_units


def make_h264_aac(
    path: Path,
    *,
    width: int = 64,
    height: int = 32,
    frame_count: int = 3,
    audio_frames: int = 48_000,
) -> None:
    """Write a deterministic H.264/AAC MP4 with stereo source audio."""
    import av

    output = av.open(str(path), mode="w", format="mp4")
    video = output.add_stream("libx264", rate=30)
    video.width = width
    video.height = height
    video.pix_fmt = "yuv420p"
    video.time_base = Fraction(1, 30)
    video.codec_context.time_base = Fraction(1, 30)
    video.codec_context.options = {"preset": "ultrafast", "crf": "28"}
    audio = output.add_stream("aac", rate=48_000)
    audio.layout = "stereo"
    audio.time_base = Fraction(1, 48_000)
    output.metadata["title"] = "source title must not be copied"

    y_grid, x_grid = np.indices((height, width), dtype=np.uint16)
    for index in range(frame_count):
        rgb = np.empty((height, width, 3), dtype=np.uint8)
        rgb[:, :, 0] = (x_grid + index * 7) % 256
        rgb[:, :, 1] = (y_grid * 3 + index * 11) % 256
        rgb[:, :, 2] = (x_grid + y_grid + index * 13) % 256
        frame = av.VideoFrame.from_ndarray(rgb, format="rgb24")
        frame.pts = index
        frame.time_base = Fraction(1, 30)
        for packet in video.encode(frame):
            output.mux(packet)

    sample_positions = np.arange(audio_frames, dtype=np.float64)
    left = (np.sin(sample_positions * (2 * np.pi * 440 / 48_000)) * 12_000).astype(np.int16)
    right = (np.sin(sample_positions * (2 * np.pi * 660 / 48_000)) * 9_000).astype(np.int16)
    interleaved = np.empty(audio_frames * 2, dtype=np.int16)
    interleaved[0::2] = left
    interleaved[1::2] = right
    for sample_start in range(0, audio_frames, 1024):
        values = interleaved[sample_start * 2:(sample_start + 1024) * 2]
        if values.size == 0:
            continue
        frame = av.AudioFrame.from_ndarray(
            values.reshape(1, -1), format="s16", layout="stereo"
        )
        frame.sample_rate = 48_000
        frame.pts = sample_start
        frame.time_base = Fraction(1, 48_000)
        for packet in audio.encode(frame):
            output.mux(packet)
    for stream in (video, audio):
        for packet in stream.encode():
            output.mux(packet)
    output.close()


def make_tiny_clip(path: Path, frame_count: int = 8) -> None:
    """Make a small deterministic H.264/AAC clip with decoded stereo audio."""
    make_h264_aac(
        path,
        width=32,
        height=24,
        frame_count=frame_count,
        audio_frames=48_000,
    )


def remux_packets(source_path: Path, output_path: Path) -> None:
    """Copy compressed packets into a fresh Matroska container without transcoding."""
    import av

    with av.open(str(source_path)) as source, av.open(
        str(output_path), mode="w", format="matroska"
    ) as output:
        outputs = {
            stream.index: output.add_stream_from_template(stream)
            for stream in source.streams
        }
        for packet in source.demux():
            if packet.dts is None:
                continue
            packet.stream = outputs[packet.stream.index]
            output.mux(packet)


def remux_with_subtitle(source_path: Path, output_path: Path) -> None:
    """Use FFmpeg to packet-copy the carrier and add a small SRT subtitle."""
    import shutil

    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise unittest.SkipTest("ffmpeg CLI is not installed for subtitle fixture creation")
    subtitle_path = output_path.with_suffix(".srt")
    subtitle_path.write_text(
        "1\n00:00:00,000 --> 00:00:01,000\nsubtitle test\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            ffmpeg, "-v", "error", "-y", "-i", str(source_path), "-i",
            str(subtitle_path), "-map", "0", "-map", "1", "-c", "copy",
            "-c:s", "srt", str(output_path),
        ],
        check=True,
        capture_output=True,
    )


def reencode_lossy(source_path: Path, output_path: Path) -> None:
    """Transcode video to lossy H.264 while packet-copying the PCM audio."""
    import av

    with av.open(str(source_path)) as source, av.open(
        str(output_path), mode="w", format="matroska"
    ) as output:
        input_video, input_audio = source.streams.video[0], source.streams.audio[0]
        video = output.add_stream("libx264", rate=25)
        video.width = input_video.codec_context.width
        video.height = input_video.codec_context.height
        video.pix_fmt = "yuv420p"
        video.time_base = Fraction(1, 1_000)
        video.codec_context.time_base = Fraction(1, 1_000)
        video.codec_context.options = {"preset": "ultrafast", "crf": "28"}
        audio = output.add_stream_from_template(input_audio)
        for frame in source.decode(video=0):
            encoded = av.VideoFrame.from_ndarray(
                frame.to_ndarray(format="rgb24"), format="rgb24"
            )
            encoded.pts = frame.pts
            encoded.time_base = frame.time_base
            for packet in video.encode(encoded):
                output.mux(packet)
        for packet in video.encode():
            output.mux(packet)
        source.seek(0)
        for packet in source.demux(input_audio):
            if packet.dts is None:
                continue
            packet.stream = audio
            output.mux(packet)


def rewrite_matroska(
    source_path: Path,
    output_path: Path,
    *,
    video_lsb: bool = False,
    audio_low: bool = False,
    audio_high: bool = False,
    timestamp: bool = False,
    title: str | None = None,
) -> None:
    """Decode and losslessly rewrite a carrier, with one optional controlled change."""
    import av

    with av.open(str(source_path)) as source:
        video_in = source.streams.video[0]
        audio_in = source.streams.audio[0]
        with av.open(str(output_path), mode="w", format="matroska") as output:
            video_out = output.add_stream("ffv1", rate=25)
            video_out.width = video_in.codec_context.width
            video_out.height = video_in.codec_context.height
            video_out.pix_fmt = "bgr0"
            video_out.time_base = Fraction(1, 1000)
            video_out.codec_context.time_base = Fraction(1, 1000)
            audio_out = output.add_stream(
                "pcm_s16le", rate=audio_in.codec_context.sample_rate
            )
            audio_layout = audio_in.codec_context.layout.name
            audio_out.layout = audio_layout
            if title is not None:
                output.metadata["title"] = title

            for index, frame in enumerate(source.decode(video=0)):
                rgb = frame.to_ndarray(format="rgb24")
                if video_lsb and index == 5:
                    rgb[0, 0, 0] ^= np.uint8(1)
                rewritten = av.VideoFrame.from_ndarray(rgb, format="rgb24")
                rewritten.pts = frame.pts + (1 if timestamp and index == 3 else 0)
                rewritten.time_base = frame.time_base or video_in.time_base
                for packet in video_out.encode(rewritten):
                    output.mux(packet)

            source.seek(0)
            for frame in source.decode(audio=0):
                values = frame.to_ndarray().copy()
                if values.dtype != np.int16:
                    raise AssertionError(f"expected decoded PCM s16, got {values.dtype}")
                if values.size:
                    if audio_low:
                        values.reshape(-1)[-1] ^= np.int16(1)
                    if audio_high:
                        values.reshape(-1)[-1] ^= np.int16(0x0100)
                rewritten_audio = av.AudioFrame.from_ndarray(
                    values, format="s16", layout=audio_layout
                )
                rewritten_audio.sample_rate = frame.sample_rate
                rewritten_audio.pts = frame.pts
                rewritten_audio.time_base = frame.time_base
                for packet in audio_out.encode(rewritten_audio):
                    output.mux(packet)

            for stream in (video_out, audio_out):
                for packet in stream.encode():
                    output.mux(packet)


def make_matroska(
    path: Path,
    *,
    ticks: tuple[int, ...] = (0, 40, 80),
    audio_samples: np.ndarray | None = None,
    audio_rate: int = 48_000,
    audio_channels: int = 2,
    audio_start: int = 0,
    audio_gap_samples: int = 0,
    width: int = 16,
    height: int = 8,
    audio_layout: str | None = None,
    extra_audio: bool = False,
) -> None:
    """Write a small deterministic FFV1/PCM Matroska fixture."""
    import av

    output = av.open(str(path), mode="w", format="matroska")
    video = output.add_stream("ffv1", rate=25)
    video.width = width
    video.height = height
    video.pix_fmt = "bgr0"
    video.time_base = Fraction(1, 1000)
    video.codec_context.time_base = Fraction(1, 1000)
    audio = None
    extra = None
    if extra_audio:
        extra = output.add_stream("pcm_s16le", rate=audio_rate)
        extra.layout = "mono"
    if audio_samples is not None:
        layout = audio_layout or {1: "mono", 2: "stereo", 6: "5.1"}[audio_channels]
        audio = output.add_stream("pcm_s16le", rate=audio_rate)
        audio.layout = layout
        if audio_rate:
            audio.time_base = Fraction(1, audio_rate)
    for index, tick in enumerate(ticks):
        pixels = np.empty((height, width, 3), dtype=np.uint8)
        pixels[:] = (index * 17 % 256, index * 31 % 256, index * 47 % 256)
        frame = av.VideoFrame.from_ndarray(pixels, format="rgb24")
        frame.pts = tick
        frame.time_base = Fraction(1, 1000)
        for packet in video.encode(frame):
            output.mux(packet)
    if audio is not None and audio_samples is not None:
        if audio_gap_samples:
            midpoint = audio_samples.size // 2
            sample_frames = (
                (audio_samples[:midpoint], audio_start),
                (audio_samples[midpoint:], audio_start + midpoint // audio_channels + audio_gap_samples),
            )
        else:
            sample_frames = ((audio_samples, audio_start),)
        for sample_values, pts in sample_frames:
            frame = av.AudioFrame.from_ndarray(
                sample_values.reshape(1, -1), format="s16", layout=layout
            )
            frame.sample_rate = audio_rate
            frame.pts = pts
            frame.time_base = Fraction(1, audio_rate)
            for packet in audio.encode(frame):
                output.mux(packet)
    for stream in (video, audio):
        if stream is not None:
            for packet in stream.encode():
                output.mux(packet)
    output.close()


def make_pixel_format_clip(
    path: Path,
    pixel_format: str,
    *,
    ticks: tuple[int, ...] = (0, 40, 80),
    width: int = 8,
    height: int = 6,
    canonical_pixels: np.ndarray | None = None,
    codec: str = "ffv1",
) -> None:
    """Write a tiny FFV1 source at a selected native pixel format."""
    import av

    video_format = av.VideoFormat(pixel_format)
    depth = max(component.bits for component in video_format.components)
    has_alpha = any(component.is_alpha for component in video_format.components)
    mask = (1 << depth) - 1
    if canonical_pixels is None and pixel_format != "yuva444p9le":
        base = np.linspace(0, mask, width * height, dtype=np.uint32).reshape(
            height, width
        )
        channels = [
            base,
            (base * 3 + 19) & mask,
            (base * 5 + 37) & mask,
        ]
        if has_alpha:
            channels.append((base * 7 + 71) & mask)
        dtype = np.uint8 if depth <= 8 else np.uint16
        canonical_pixels = np.stack(channels, axis=-1).astype(dtype)

    output = av.open(str(path), mode="w", format="matroska")
    video = output.add_stream(codec, rate=25)
    video.width = width
    video.height = height
    video.pix_fmt = pixel_format
    video.time_base = Fraction(1, 1000)
    video.codec_context.time_base = Fraction(1, 1000)
    for tick in ticks:
        if pixel_format == "yuva444p9le":
            frame = av.VideoFrame(width, height, format=pixel_format)
            component_values = (170, 400, 300, 420)
            for plane, value in zip(frame.planes, component_values):
                rows = np.zeros(
                    (plane.height, plane.line_size // 2), dtype=np.uint16
                )
                rows[:, :plane.width] = value
                plane.update(rows.tobytes())
        elif pixel_format in {"rgba", "bgra"}:
            if canonical_pixels is None:
                raise AssertionError("an alpha pixel array is required")
            frame = av.VideoFrame.from_ndarray(
                canonical_pixels, format="rgba"
            ).reformat(format=pixel_format)
        else:
            if canonical_pixels is None:
                raise AssertionError("a canonical pixel array is required")
            frame = av.VideoFrame(width, height, format=pixel_format)
            component_values = [
                canonical_pixels[:, :, 1],
                canonical_pixels[:, :, 2],
                canonical_pixels[:, :, 0],
            ]
            if has_alpha:
                component_values.append(canonical_pixels[:, :, 3])
            dtype = np.uint8 if depth <= 8 else np.uint16
            for plane, values in zip(frame.planes, component_values):
                row_width = plane.line_size // np.dtype(dtype).itemsize
                rows = np.zeros((plane.height, row_width), dtype=dtype)
                rows[:, :width] = values
                plane.update(rows.tobytes())
        frame.pts = tick
        frame.time_base = Fraction(1, 1000)
        for packet in video.encode(frame):
            output.mux(packet)
    for packet in video.encode():
        output.mux(packet)
    output.close()


def rewrite_native_pixel(
    source_path: Path,
    output_path: Path,
    pixel_format: str,
    channel: int,
    xor_value: int,
) -> None:
    """Rewrite one canonical pixel component and preserve the video timestamps."""
    import av

    with av.open(str(source_path)) as source, av.open(
        str(output_path), mode="w", format="matroska"
    ) as output:
        source_stream = source.streams.video[0]
        output_stream = output.add_stream("ffv1", rate=25)
        output_stream.width = source_stream.codec_context.width
        output_stream.height = source_stream.codec_context.height
        output_stream.pix_fmt = pixel_format
        output_stream.time_base = Fraction(1, 1000)
        output_stream.codec_context.time_base = Fraction(1, 1000)
        for frame in source.decode(video=0):
            pixels = frame.to_ndarray(format=pixel_format)
            pixels[-1, -1, channel] ^= np.array(xor_value, dtype=pixels.dtype)
            rewritten = av.VideoFrame.from_ndarray(pixels, format=pixel_format)
            rewritten.pts = frame.pts
            rewritten.time_base = frame.time_base or source_stream.time_base
            for packet in output_stream.encode(rewritten):
                output.mux(packet)
        for packet in output_stream.encode():
            output.mux(packet)


def make_avi_audio_layout(path: Path, layout_name: str) -> None:
    """Write FFV1/PCM in AVI to test layouts that Matroska does not preserve."""
    import av

    with av.open(str(path), mode="w", format="avi") as output:
        video = output.add_stream("ffv1", rate=25)
        video.width = 64
        video.height = 32
        video.pix_fmt = "bgr0"
        audio = output.add_stream("pcm_s16le", rate=48_000)
        audio.layout = layout_name
        frame = av.VideoFrame.from_ndarray(
            np.zeros((32, 64, 3), dtype=np.uint8), format="rgb24"
        )
        frame.pts = 0
        frame.time_base = Fraction(1, 25)
        for packet in video.encode(frame):
            output.mux(packet)
        audio_frame = av.AudioFrame.from_ndarray(
            np.zeros((1, 960), dtype=np.int16), format="s16", layout=layout_name
        )
        audio_frame.sample_rate = 48_000
        audio_frame.pts = 0
        audio_frame.time_base = Fraction(1, 48_000)
        for packet in audio.encode(audio_frame):
            output.mux(packet)
        for stream in (video, audio):
            for packet in stream.encode():
                output.mux(packet)


class DecoderConfigurationTests(unittest.TestCase):
    def test_decoder_uses_automatic_threads(self) -> None:
        stream = SimpleNamespace(thread_count=1, thread_type="SLICE")
        _configure_decoder(stream)
        self.assertEqual(stream.thread_count, 0)
        self.assertEqual(stream.thread_type, "AUTO")


class VideoMediaCodeTests(unittest.TestCase):
    def test_code_three_packet_round_trip(self) -> None:
        encoding, _, output = make_encoding()
        try:
            result = decode_carrier_source(
                MemoryVideoCarrier(output, check_requested=False),
                VIDEO_MEDIA_CODE,
                VIDEO_CONTEXT,
                SIGNING_PUBLIC_KEY,
                RECEIVER_PRIVATE_KEY,
            )
            self.assertEqual(result.verdict, "Authentic", result.detail)
            self.assertEqual(result.payload.user_payload, b"video test payload")
            self.assertTrue(encoding.payload.media_id.startswith("VID-"))
        finally:
            encoding.close()

    def test_code_three_with_code_one_context_follows_verdict_rules(self) -> None:
        encoding, _, output = make_encoding()
        try:
            result = decode_carrier_source(
                MemoryVideoCarrier(output, check_requested=False),
                IMAGE_MEDIA_CODE,
                VIDEO_CONTEXT,
                SIGNING_PUBLIC_KEY,
                RECEIVER_PRIVATE_KEY,
            )
            self.assertEqual(result.verdict, "Signature Invalid")
        finally:
            encoding.close()


class CarrierOutputCheckTests(unittest.TestCase):
    def test_correct_output_is_accepted_before_finish(self) -> None:
        encoding, _, output = make_encoding()
        encoding.check_output(MemoryVideoCarrier(output))
        encoding.finish()

    def test_embedded_lsb_flip_is_rejected(self) -> None:
        encoding, _, output = make_encoding()
        output[encoding.layout.start_unit] ^= np.uint8(1)
        with self.assertRaisesRegex(ValueError, "embedded transforms"):
            encoding.check_output(MemoryVideoCarrier(output))
        encoding.close()

    def test_preserved_bit_flip_is_rejected_by_masked_hash(self) -> None:
        encoding, _, output = make_encoding()
        output[-1] ^= np.uint8(0x80)
        with self.assertRaisesRegex(ValueError, "masked media hash"):
            encoding.check_output(MemoryVideoCarrier(output))
        encoding.close()

    def test_changed_fixed_byte_is_rejected_by_masked_hash(self) -> None:
        encoding, _, output = make_encoding()
        with self.assertRaisesRegex(ValueError, "masked media hash"):
            encoding.check_output(MemoryVideoCarrier(output, fixed=b"changed"))
        encoding.close()

    def test_wrong_context_is_rejected(self) -> None:
        encoding, _, output = make_encoding()
        with self.assertRaisesRegex(ValueError, "media context"):
            encoding.check_output(MemoryVideoCarrier(output, context=b"wrong"))
        encoding.close()

    def test_short_output_stream_is_rejected(self) -> None:
        encoding, _, output = make_encoding()
        with self.assertRaisesRegex(ValueError, "units; expected"):
            encoding.check_output(
                MemoryVideoCarrier(output[:-1], reported_units=output.size)
            )
        encoding.close()

    def test_long_output_stream_is_rejected(self) -> None:
        encoding, _, output = make_encoding()
        with self.assertRaisesRegex(ValueError, "more units"):
            encoding.check_output(
                MemoryVideoCarrier(
                    np.append(output, np.uint8(0)), reported_units=output.size
                )
            )
        encoding.close()

    def test_requested_check_must_precede_finish(self) -> None:
        encoding, _, _ = make_encoding()
        with self.assertRaisesRegex(ValueError, "requires an output check"):
            encoding.finish()

    def test_sources_default_to_no_output_check(self) -> None:
        source = MemoryVideoCarrier(UNITS.copy(), check_requested=False)
        self.assertFalse(source.requires_output_check)

    def test_default_rewritten_output_hook_is_unsupported(self) -> None:
        with self.assertRaisesRegex(
            NotImplementedError, "this carrier does not support output checks"
        ):
            ArrayCarrier(UNITS.copy()).open_rewritten_output("unused")

    def test_shared_rewrite_checks_output_and_closes_reader(self) -> None:
        source = MemoryVideoCarrier(UNITS.copy())
        encoding = prepare_test_encoding(source)
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "carrier.bin"
            _rewrite_checked(source, encoding, output_path)
            self.assertTrue(output_path.is_file())
            self.assertIsNotNone(source.opened_output)
            self.assertTrue(source.opened_output.output_closed)

    def test_corrupt_checked_output_is_removed(self) -> None:
        source = MemoryVideoCarrier(UNITS.copy(), corrupt_output=True)
        encoding = prepare_test_encoding(source)
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "carrier.bin"
            with self.assertRaisesRegex(ValueError, "masked media hash"):
                _rewrite_checked(source, encoding, output_path)
            self.assertFalse(output_path.exists())
            self.assertTrue(source.opened_output.output_closed)
        encoding.close()

    def test_corrupt_payload_path_output_leaves_no_staging_or_destination(self) -> None:
        source = MemoryVideoCarrier(UNITS.copy(), corrupt_output=True)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload_path = root / "payload.bin"
            output_path = root / "encoded.mkv"
            payload_path.write_bytes(b"file payload")
            with self.assertRaisesRegex(ValueError, "masked media hash"):
                _encode_file_from_payload_path(
                    source,
                    output_path,
                    SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    bootstrap_span(RECEIVER_PUBLIC_KEY),
                    3,
                    payload_path,
                    b"{}",
                )
            self.assertFalse(output_path.exists())
            self.assertEqual(list(root.iterdir()), [payload_path])
            self.assertTrue(source.opened_output.output_closed)


@unittest.skipUnless(importlib.util.find_spec("av"), "PyAV is not installed")
class PyAVLazyImportTests(unittest.TestCase):
    def test_importing_stego_does_not_import_pyav(self) -> None:
        script = (
            "import importlib.abc, sys; "
            "sys.meta_path.insert(0, type('BlockAv', (), {"
            "'find_spec': lambda self, fullname, *args: "
            "(_ for _ in ()).throw(ModuleNotFoundError('av unavailable')) "
            "if fullname == 'av' else None})()); "
            "import stego; assert 'av' not in sys.modules"
        )
        subprocess.run([sys.executable, "-c", script], check=True)


@unittest.skipUnless(importlib.util.find_spec("av"), "PyAV is not installed")
class PyAVAvailabilityTests(unittest.TestCase):
    def test_pyav_is_available_for_video_backend_tests(self) -> None:
        self.assertIsNotNone(importlib.util.find_spec("av"))


@unittest.skipUnless(importlib.util.find_spec("av"), "PyAV is not installed")
class VideoCarrierReadTests(unittest.TestCase):
    def test_rgb_video_units_context_and_frame_timing_are_exact(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vfr.mkv"
            make_matroska(path, ticks=(0, 33, 70))
            source = VideoCarrier(path, chunk_units=17)
            try:
                chunks = list(source.iter_chunks_with_fixed_bytes())
                units = np.concatenate([part for part, _ in chunks])
                fixed = b"".join(data for _, data in chunks)
                expected = np.concatenate(
                    [
                        np.tile(
                            np.array(
                                (index * 17 % 256, index * 31 % 256, index * 47 % 256),
                                dtype=np.uint8,
                            ),
                            16 * 8,
                        )
                        for index in range(3)
                    ]
                )
                self.assertTrue(np.array_equal(units, expected))
                self.assertEqual(
                    fixed,
                    b"".join(struct.pack(">q", tick) for tick in (0, 33, 70)),
                )
                self.assertEqual(
                    source.media_context,
                    struct.pack(">IIQBBIHQ", 16, 8, 3, 8, 3, 0, 0, 0),
                )
                self.assertEqual(source.fixed_byte_count, 24)
            finally:
                source.close()

    def test_native_depth_video_round_trips_with_exact_payload(self) -> None:
        cases = (
            ("rgba8", "bgra", 8, True),
            ("rgb9", "gbrp9le", 9, False),
            ("rgb10", "gbrp10le", 10, False),
            ("rgb12", "gbrp12le", 12, False),
            ("rgb14", "gbrp14le", 14, False),
            ("rgb16", "gbrp16le", 16, False),
            ("rgba10", "gbrap10le", 10, True),
            ("rgba16", "gbrap16le", 16, True),
            ("rgba9-source", "yuva444p9le", 10, True),
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for label, source_format, depth, has_alpha in cases:
                with self.subTest(case=label):
                    source_path = root / f"{label}-source.mkv"
                    output_path = root / f"{label}-encoded.mkv"
                    payload = f"exact payload for {label}".encode()
                    make_pixel_format_clip(
                        source_path,
                        source_format,
                        ticks=(0, 40, 80),
                        width=64,
                        height=48,
                    )
                    with patch("stego.video._MIN_FREE_BYTES", 0):
                        encode_video(
                            source_path,
                            output_path,
                            SIGNING_PRIVATE_KEY,
                            RECEIVER_PUBLIC_KEY,
                            bootstrap_span(RECEIVER_PUBLIC_KEY),
                            3,
                            payload,
                            b"{}",
                        )
                    result = verify_video(
                        output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
                    )
                    self.assertEqual(result.verdict, "Authentic", result.detail)
                    self.assertEqual(result.payload.user_payload, payload)
                    output_carrier = VideoCarrier(output_path)
                    try:
                        fields = struct.unpack(
                            ">IIQBBIHQ", output_carrier.media_context
                        )
                        self.assertEqual(fields[3], depth)
                        self.assertEqual(fields[4], 4 if has_alpha else 3)
                    finally:
                        output_carrier.close()

    def test_rgba_and_gbrap_unit_and_fixed_byte_order(self) -> None:
        import av

        with TemporaryDirectory() as directory:
            root = Path(directory)
            rgba_values = np.array([[[0x12, 0x34, 0x56, 0x78]]], dtype=np.uint8)
            for source_format in ("bgra", "rgba"):
                with self.subTest(source_format=source_format):
                    rgba_path = root / f"{source_format}.mkv"
                    make_pixel_format_clip(
                        rgba_path,
                        source_format,
                        ticks=(0,),
                        width=1,
                        height=1,
                        canonical_pixels=rgba_values,
                        codec="rawvideo" if source_format == "rgba" else "ffv1",
                    )
                    with av.open(str(rgba_path)) as container:
                        decoded = next(container.decode(video=0)).to_ndarray(
                            format="rgba"
                        )
                    self.assertEqual(decoded.shape, (1, 1, 4))
                    self.assertEqual(decoded[0, 0].tolist(), [0x12, 0x34, 0x56, 0x78])
                    rgba_source = VideoCarrier(rgba_path, chunk_units=3)
                    try:
                        rgba_chunks = list(rgba_source.iter_chunks_with_fixed_bytes())
                        self.assertEqual(
                            rgba_source.read_units(0, 3).tolist(), [0x12, 0x34, 0x56]
                        )
                        self.assertEqual(rgba_chunks[0][1], struct.pack(">q", 0))
                        self.assertEqual(rgba_chunks[1][0].size, 0)
                        self.assertEqual(rgba_chunks[1][1], b"\x78")
                        self.assertEqual(rgba_source.fixed_byte_count, 9)
                    finally:
                        rgba_source.close()

            gbrap_path = root / "gbrap10.mkv"
            gbrap_values = np.array(
                [[[0x123, 0x256, 0x3A7, 0x2BC]]], dtype=np.uint16
            )
            make_pixel_format_clip(
                gbrap_path,
                "gbrap10le",
                ticks=(0,),
                width=1,
                height=1,
                canonical_pixels=gbrap_values,
            )
            with av.open(str(gbrap_path)) as container:
                decoded = next(container.decode(video=0)).to_ndarray(
                    format="gbrap10le"
                )
            self.assertEqual(decoded.shape, (1, 1, 4))
            self.assertEqual(decoded[0, 0].tolist(), [0x123, 0x256, 0x3A7, 0x2BC])
            gbrap_source = VideoCarrier(gbrap_path, chunk_units=3)
            try:
                gbrap_chunks = list(gbrap_source.iter_chunks_with_fixed_bytes())
                self.assertEqual(
                    gbrap_source.read_units(0, 3).tolist(), [0x23, 0x56, 0xA7]
                )
                self.assertEqual(
                    gbrap_chunks[0][1], struct.pack(">q", 0) + b"\x01\x02\x03"
                )
                self.assertEqual(gbrap_chunks[1][0].size, 0)
                self.assertEqual(gbrap_chunks[1][1], b"\xBC\x02")
                self.assertEqual(
                    gbrap_source.media_context,
                    struct.pack(">IIQBBIHQ", 1, 1, 1, 10, 4, 0, 0, 0),
                )
                self.assertEqual(gbrap_source.fixed_byte_count, 13)
            finally:
                gbrap_source.close()

    def test_video_fixed_byte_count_matches_independent_formula(self) -> None:
        cases = (
            ("rgb8", "bgr0", 8, False, 16, 8, 8),
            ("rgb10", "gbrp10le", 10, False, 8, 6, 8 + 3 * 8 * 6),
            (
                "rgba10",
                "gbrap10le",
                10,
                True,
                8,
                6,
                8 + 3 * 8 * 6 + 2 * 8 * 6,
            ),
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for label, pixel_format, depth, alpha, width, height, per_frame in cases:
                with self.subTest(case=label):
                    path = root / f"{label}.mkv"
                    if pixel_format == "bgr0":
                        make_matroska(path, ticks=(0, 40, 80), width=width, height=height)
                    else:
                        make_pixel_format_clip(
                            path,
                            pixel_format,
                            ticks=(0, 40, 80),
                            width=width,
                            height=height,
                        )
                    source = VideoCarrier(path)
                    try:
                        self.assertEqual(source.fixed_byte_count, per_frame * 3)
                        fields = struct.unpack(">IIQBBIHQ", source.media_context)
                        self.assertEqual(fields[3], depth)
                        self.assertEqual(fields[4], 4 if alpha else 3)
                    finally:
                        source.close()

    def test_eight_bit_no_alpha_output_remains_bgr0(self) -> None:
        import av

        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.mp4"
            output_path = root / "output.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path,
                    output_path,
                    SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    bootstrap_span(RECEIVER_PUBLIC_KEY),
                    3,
                    b"8-bit bgr0",
                    b"{}",
                )
            with av.open(str(output_path)) as container:
                self.assertEqual(
                    container.streams.video[0].codec_context.format.name, "bgr0"
                )

    def test_native_depth_tampering_is_detected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "gbrap10-source.mkv"
            encoded_path = root / "gbrap10-encoded.mkv"
            make_pixel_format_clip(
                source_path, "gbrap10le", ticks=(0, 40, 80), width=64, height=48
            )
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path,
                    encoded_path,
                    SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    bootstrap_span(RECEIVER_PUBLIC_KEY),
                    3,
                    b"tamper native depth",
                    b"{}",
                )
            cases = (("low", 0, 1), ("high", 0, 0x100), ("alpha", 3, 1))
            for label, channel, xor_value in cases:
                with self.subTest(component=label):
                    changed_path = root / f"{label}-changed.mkv"
                    rewrite_native_pixel(
                        encoded_path, changed_path, "gbrap10le", channel, xor_value
                    )
                    result = verify_video(
                        changed_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
                    )
                    self.assertEqual(result.verdict, "Tampered", result.detail)

    def test_float_and_over_16_bit_formats_are_refused(self) -> None:
        import av

        with self.assertRaisesRegex(ValueError, "unsupported video pixel format"):
            _video_format_info(av.VideoFormat("gbrpf32le"))
        over_depth = SimpleNamespace(
            name="gbrp17le",
            components=tuple(
                SimpleNamespace(bits=17, is_alpha=False) for _ in range(3)
            ),
        )
        with self.assertRaisesRegex(ValueError, "unsupported video pixel format"):
            _video_format_info(over_depth)

    def test_canonical_conversion_probe_runs_once_per_scan(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "canonical-conversion-probe.mkv"
            make_pixel_format_clip(path, "gbrp10le", ticks=(0, 40, 80))
            with patch(
                "stego.video._check_video_conversion",
                wraps=_check_video_conversion,
            ) as conversion_check:
                source = VideoCarrier(path)
            try:
                self.assertEqual(conversion_check.call_count, 1)
            finally:
                source.close()

    def test_pixel_format_change_during_decode_is_refused(self) -> None:
        import av

        with TemporaryDirectory() as directory:
            path = Path(directory) / "changing-pixel-format.mkv"
            make_pixel_format_clip(path, "gbrp9le", ticks=(0, 40))
            original_frame_ticks = _frame_ticks

            def changed_formats(
                frames: Iterator[object],
                stream: object,
                first_time: Fraction | None = None,
            ) -> Iterator[tuple[object, int, Fraction]]:
                for index, (frame, tick, exact_time) in enumerate(
                    original_frame_ticks(frames, stream, first_time)
                ):
                    if index == 1:
                        frame = SimpleNamespace(
                            width=frame.width,
                            height=frame.height,
                            format=av.VideoFormat("gbrp10le"),
                        )
                    yield frame, tick, exact_time

            with patch("stego.video._frame_ticks", side_effect=changed_formats):
                with self.assertRaisesRegex(
                    ValueError, "video pixel format changed during decode"
                ):
                    VideoCarrier(path)

    def test_audio_samples_follow_video_and_high_bytes_are_fixed(self) -> None:
        samples = np.arange(960, dtype=np.int16)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "av.mkv"
            make_matroska(path, audio_samples=samples, audio_channels=2)
            source = VideoCarrier(path, chunk_units=19)
            try:
                chunks = list(source.iter_chunks_with_fixed_bytes())
                units = np.concatenate([part for part, _ in chunks])
                fixed = b"".join(data for _, data in chunks)
                video_units = 3 * 16 * 8 * 3
                pcm = samples.astype("<i2").tobytes()
                expected_audio = np.frombuffer(pcm, dtype=np.uint8)[0::2]
                self.assertTrue(np.array_equal(units[video_units:], expected_audio))
                self.assertEqual(
                    fixed[:24], b"".join(struct.pack(">q", tick) for tick in (0, 40, 80))
                )
                self.assertEqual(fixed[24:32], struct.pack(">q", 0))
                self.assertEqual(fixed[32:], np.frombuffer(pcm, dtype=np.uint8)[1::2].tobytes())
                self.assertEqual(source.audio_frames_per_channel, 480)
                self.assertEqual(source.total_units, video_units + samples.size)
            finally:
                source.close()

    def test_range_read_crosses_video_audio_boundary_and_resets(self) -> None:
        samples = np.arange(960, dtype=np.int16)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "av.mkv"
            make_matroska(path, audio_samples=samples)
            source = VideoCarrier(path, chunk_units=23)
            try:
                boundary = 3 * 16 * 8 * 3
                expected_audio = np.frombuffer(samples.astype("<i2").tobytes(), dtype=np.uint8)[0::2]
                result = source.read_units(boundary - 3, 6)
                self.assertEqual(result[-3:].tolist(), expected_audio[:3].tolist())
                self.assertEqual(source.read_units(0, 4).tolist(), [0, 0, 0, 0])
            finally:
                source.close()

    def test_large_frame_is_yielded_as_bounded_chunks(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "large.mkv"
            make_matroska(path, ticks=(0,), width=700, height=600)
            source = VideoCarrier(path, chunk_units=100_000)
            try:
                chunks = list(source.iter_chunks_with_fixed_bytes())
                self.assertGreater(len(chunks), 1)
                self.assertLessEqual(max(units.size for units, _ in chunks), 100_000)
                self.assertEqual(sum(len(fixed) for _, fixed in chunks), 8)
                self.assertEqual(sum(len(units) for units, _ in chunks), 700 * 600 * 3)
            finally:
                source.close()

    def test_audio_before_video_keeps_negative_millisecond_offset(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "negative-audio.mkv"
            make_matroska(
                path,
                ticks=(0, 40, 80),
                audio_samples=np.arange(960, dtype=np.int16),
                audio_start=-480,
            )
            source = VideoCarrier(path)
            try:
                fixed = b"".join(data for _, data in source.iter_chunks_with_fixed_bytes())
                self.assertEqual(struct.unpack(">q", fixed[24:32])[0], -10)
            finally:
                source.close()

    def test_real_encodes_use_the_output_video_origin(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ticks = tuple(5_000 + index * 40 for index in range(90))
            audio = np.arange(9_600, dtype=np.int16)
            cases = (
                ("no-audio", None, 0),
                ("audio-after", audio, 240_960),
                ("audio-before", audio, 238_080),
            )
            with patch("stego.video._MIN_FREE_BYTES", 0):
                for name, samples, audio_start in cases:
                    with self.subTest(case=name):
                        source_path = root / f"{name}-source.mkv"
                        output_path = root / f"{name}-encoded.mkv"
                        make_matroska(
                            source_path,
                            ticks=ticks,
                            audio_samples=samples,
                            audio_rate=48_000,
                            audio_start=audio_start,
                            width=64,
                            height=32,
                        )
                        encode_video(
                            source_path, output_path, SIGNING_PRIVATE_KEY,
                            RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY),
                            3, b"non-zero video origin", b"{}",
                        )
                        result = verify_video(
                            output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
                        )
                        self.assertEqual(result.verdict, "Authentic", result.detail)
                        self.assertEqual(
                            result.payload.user_payload, b"non-zero video origin"
                        )
                        if name == "audio-before":
                            rewritten = VideoCarrier(output_path)
                            try:
                                self.assertGreater(rewritten._first_video_time, 0)
                                self.assertEqual(rewritten._audio_start_tick, -40)
                            finally:
                                rewritten.close()

    def test_audio_gap_at_tolerance_is_accepted(self) -> None:
        sample_rate = 48_000
        tolerance = (sample_rate + 1_999) // 2_000
        self.assertEqual(tolerance, 24)
        self.assertTrue(_audio_position_matches(tolerance, 0, sample_rate))
        self.assertFalse(_audio_position_matches(tolerance + 1, 0, sample_rate))

    def test_audio_overlap_at_tolerance_is_accepted(self) -> None:
        sample_rate = 48_000
        tolerance = (sample_rate + 1_999) // 2_000
        self.assertEqual(tolerance, 24)
        self.assertTrue(_audio_position_matches(-tolerance, 0, sample_rate))
        self.assertFalse(_audio_position_matches(-tolerance - 1, 0, sample_rate))

    def test_audio_gap_is_refused(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audio-gap.mkv"
            make_matroska(
                path,
                ticks=(0,),
                audio_samples=np.arange(960, dtype=np.int16),
                audio_gap_samples=480,
            )
            with self.assertRaisesRegex(ValueError, "gap or overlap"):
                VideoCarrier(path)

    def test_six_channel_audio_is_refused(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "surround.mkv"
            make_matroska(
                path,
                ticks=(0,),
                audio_samples=np.zeros(6 * 128, dtype=np.int16),
                audio_channels=6,
            )
            with self.assertRaisesRegex(ValueError, "unsupported audio channel count"):
                VideoCarrier(path)

    def test_canonical_and_unspecified_audio_layouts_are_accepted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name, channels in (
                ("stereo", 2),
                ("2 channels", 2),
                ("mono", 1),
                ("1 channels", 1),
            ):
                with self.subTest(layout=name):
                    path = root / f"{channels}-{name.replace(' ', '-')}.mkv"
                    make_matroska(
                        path,
                        ticks=(0, 40),
                        audio_samples=np.zeros(channels * 480, dtype=np.int16),
                        audio_channels=channels,
                        audio_layout=name,
                    )
                    carrier = VideoCarrier(path)
                    try:
                        self.assertEqual(carrier._audio_channels, channels)
                    finally:
                        carrier.close()

    def test_channel_identity_helper_refuses_noncanonical_orders(self) -> None:
        import av

        for name in ("FL+LFE", "FR+FL", "DL+DR", "FC+LFE"):
            with self.subTest(layout=name):
                with self.assertRaisesRegex(ValueError, "unsupported audio channel layout"):
                    _audio_layout_identities(av.AudioLayout(name))

    def test_noncanonical_two_channel_layout_is_refused(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "front-and-lfe.avi"
            make_avi_audio_layout(path, "FL+LFE")
            with self.assertRaisesRegex(ValueError, "unsupported audio channel layout"):
                VideoCarrier(path)

    def test_swapped_stereo_layout_is_refused_when_pyav_can_write_it(self) -> None:
        import av

        with TemporaryDirectory() as directory:
            path = Path(directory) / "swapped-stereo.avi"
            make_avi_audio_layout(path, "FR+FL")
            with av.open(str(path)) as container:
                identities = tuple(
                    channel.name for channel in container.streams.audio[0].codec_context.layout.channels
                )
            if identities != ("FR", "FL"):
                self.skipTest(
                    "PyAV 15.1 AVI writer normalizes FR+FL to NONE/NONE; "
                    "the order cannot be tested from a decoded media header"
                )
            with self.assertRaisesRegex(ValueError, "unsupported audio channel layout"):
                VideoCarrier(path)

    def test_multiple_audio_streams_are_refused(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "extra.mkv"
            make_matroska(
                path,
                ticks=(0,),
                audio_samples=np.zeros(96, dtype=np.int16),
                extra_audio=True,
            )
            with self.assertRaisesRegex(ValueError, "unsupported additional stream"):
                VideoCarrier(path)

    def test_rounding_is_exact_and_ties_away_from_zero(self) -> None:
        self.assertEqual(_round_fraction(Fraction(1, 2)), 1)
        self.assertEqual(_round_fraction(Fraction(-1, 2)), -1)
        self.assertEqual(_round_fraction(Fraction(1, 3)), 0)

    def test_missing_non_increasing_and_colliding_video_ticks_are_refused(self) -> None:
        time_base = Fraction(1, 10_000)
        stream = SimpleNamespace(time_base=time_base)
        missing = [SimpleNamespace(pts=None, time_base=time_base)]
        with self.assertRaisesRegex(ValueError, "missing media timestamp"):
            list(_frame_ticks(iter(missing), stream))
        non_increasing = [
            SimpleNamespace(pts=1, time_base=time_base),
            SimpleNamespace(pts=1, time_base=time_base),
        ]
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            list(_frame_ticks(iter(non_increasing), stream))
        colliding = [
            SimpleNamespace(pts=0, time_base=time_base),
            SimpleNamespace(pts=4, time_base=time_base),
        ]
        with self.assertRaisesRegex(ValueError, "collide at millisecond"):
            list(_frame_ticks(iter(colliding), stream))

    def test_invalid_media_returns_cannot_verify(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "not-video.mkv"
            path.write_bytes(b"not media")
            result = verify_video(
                path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
            )
            self.assertEqual(result.verdict, "Cannot Verify")

    def test_pixel_limit_is_checked_on_stream_header_before_decode(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "too-many-header-pixels.mkv"
            make_matroska(path, ticks=(0,), width=4, height=3)
            original_open = VideoCarrier._open
            open_count = 0

            def counted_open(carrier: VideoCarrier) -> object:
                nonlocal open_count
                open_count += 1
                return original_open(carrier)

            with patch("stego.video._MAX_FRAME_PIXELS", 11), patch.object(
                VideoCarrier, "_open", counted_open
            ):
                with self.assertRaisesRegex(ValueError, "configured pixel limit"):
                    VideoCarrier(path)
            self.assertEqual(open_count, 1)

    def test_pixel_limit_is_checked_on_decoded_frames(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "too-many-frame-pixels.mkv"
            make_matroska(path, ticks=(0,), width=4, height=2)
            original_frame_ticks = _frame_ticks

            def oversized_frame_ticks(
                frames: Iterator[object],
                stream: object,
                first_time: Fraction | None = None,
            ) -> Iterator[tuple[object, int, Fraction]]:
                for frame, tick, exact_time in original_frame_ticks(
                    frames, stream, first_time
                ):
                    yield (
                        SimpleNamespace(width=4, height=3, format=frame.format),
                        tick,
                        exact_time,
                    )

            with patch("stego.video._MAX_FRAME_PIXELS", 10), patch(
                "stego.video._frame_ticks", side_effect=oversized_frame_ticks
            ):
                with self.assertRaisesRegex(ValueError, "configured pixel limit"):
                    VideoCarrier(path)

    def test_decoded_size_limit_stops_counting_video_frames_early(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "many-frames.mkv"
            make_matroska(
                path,
                ticks=tuple(index * 40 for index in range(10)),
                width=16,
                height=8,
            )
            original_frame_ticks = _frame_ticks
            decoded_count = 0

            def counted_frame_ticks(
                frames: Iterator[object],
                stream: object,
                first_time: Fraction | None = None,
            ) -> Iterator[tuple[object, int, Fraction]]:
                nonlocal decoded_count
                for item in original_frame_ticks(frames, stream, first_time):
                    decoded_count += 1
                    yield item

            with patch("stego.video._MAX_CARRIER_UNITS", 2 * 16 * 8 * 3), patch(
                "stego.video._frame_ticks", side_effect=counted_frame_ticks
            ):
                with self.assertRaisesRegex(
                    ValueError, "video carrier exceeds configured decoded-size limit"
                ):
                    VideoCarrier(path)
            self.assertEqual(decoded_count, 3)

    def test_decoded_size_limit_counts_audio_sample_units(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audio-units.mkv"
            make_matroska(
                path,
                ticks=(0,),
                audio_samples=np.arange(960, dtype=np.int16),
                audio_channels=1,
                width=16,
                height=8,
            )
            with patch("stego.video._MAX_CARRIER_UNITS", 500):
                with self.assertRaisesRegex(
                    ValueError, "video carrier exceeds configured decoded-size limit"
                ):
                    VideoCarrier(path)

    def test_video_beyond_previous_frame_and_duration_limits_round_trips(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "long-source.mkv"
            output_path = root / "long-encoded.mkv"
            make_matroska(
                source_path,
                ticks=tuple(index * 40 for index in range(451)),
                width=64,
                height=32,
            )
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path,
                    output_path,
                    SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    bootstrap_span(RECEIVER_PUBLIC_KEY),
                    3,
                    b"beyond old limits",
                    b"{}",
                )
            result = verify_video(
                output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
            )
            self.assertEqual(result.verdict, "Authentic", result.detail)
            self.assertEqual(result.payload.user_payload, b"beyond old limits")

    def test_minimum_free_space_failure_does_not_create_output_or_stage(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.mp4"
            output_path = root / "insufficient-space.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 1 << 80):
                with self.assertRaisesRegex(
                    ValueError, "insufficient free disk space"
                ):
                    encode_video(
                        source_path,
                        output_path,
                        SIGNING_PRIVATE_KEY,
                        RECEIVER_PUBLIC_KEY,
                        bootstrap_span(RECEIVER_PUBLIC_KEY),
                        3,
                        b"cap test",
                        b"{}",
                    )
            self.assertFalse(output_path.exists())
            self.assertFalse(list(root.glob(".stego-staging-*")))

    def test_output_cap_failure_removes_staging_and_does_not_publish(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.mp4"
            output_path = root / "must-not-publish.mkv"
            make_h264_aac(source_path, width=64, height=32, frame_count=30)
            with patch("stego.video._MIN_FREE_BYTES", 0), patch(
                "stego.video._MAX_OUTPUT_BYTES", 1
            ):
                with self.assertRaisesRegex(ValueError, "output exceeds"):
                    encode_video(
                        source_path,
                        output_path,
                        SIGNING_PRIVATE_KEY,
                        RECEIVER_PUBLIC_KEY,
                        bootstrap_span(RECEIVER_PUBLIC_KEY),
                        3,
                        b"small payload",
                        b"{}",
                    )
            self.assertFalse(output_path.exists())
            self.assertFalse(list(root.glob(".stego-staging-*")))

    def test_automatic_and_single_thread_decodes_are_identical(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "thread-source.mp4"
            output_path = root / "thread-output.mkv"
            make_tiny_clip(source_path)
            source = VideoCarrier(source_path)
            try:
                source.rewrite_to_path(output_path, lambda _offset, units: units)
            finally:
                source.close()

            def read_with_threads(
                path: Path, count: int, thread_type: str
            ) -> tuple[bytes, int, int, bytes, bytes]:
                def configure(stream: object) -> None:
                    stream.thread_count = count
                    stream.thread_type = thread_type

                with patch("stego.video._configure_decoder", configure):
                    carrier = VideoCarrier(path)
                    try:
                        unit_chunks: list[np.ndarray] = []
                        fixed_chunks: list[bytes] = []
                        for units, fixed in carrier.iter_chunks_with_fixed_bytes():
                            unit_chunks.append(units)
                            fixed_chunks.append(fixed)
                        return (
                            carrier.media_context,
                            carrier.total_units,
                            carrier.fixed_byte_count,
                            np.concatenate(unit_chunks).tobytes(),
                            b"".join(fixed_chunks),
                        )
                    finally:
                        carrier.close()

            for path in (source_path, output_path):
                with self.subTest(path=path.name):
                    single = read_with_threads(path, 1, "SLICE")
                    automatic = read_with_threads(path, 0, "AUTO")
                    self.assertEqual(automatic, single)

    def test_real_encode_round_trip_for_every_lsb_count_with_audio(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.mp4"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                for lsb_count in range(1, 9):
                    with self.subTest(lsb_count=lsb_count):
                        output_path = root / f"encoded-{lsb_count}.mkv"
                        layout, _ = encode_video(
                            source_path,
                            output_path,
                            SIGNING_PRIVATE_KEY,
                            RECEIVER_PUBLIC_KEY,
                            bootstrap_span(RECEIVER_PUBLIC_KEY),
                            lsb_count,
                            b"tiny carrier round trip",
                            b"{}",
                        )
                        self.assertEqual(layout.lsb_count, lsb_count)
                        result = verify_video(
                            output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
                        )
                        self.assertEqual(result.verdict, "Authentic", result.detail)
                        self.assertEqual(result.payload.user_payload, b"tiny carrier round trip")

    def test_packet_can_cross_track_boundary_or_live_wholly_in_audio(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.mp4"
            make_tiny_clip(source_path, frame_count=10)
            video_units = 32 * 24 * 10 * 3
            for label, start_unit in (
                ("crosses", video_units - 1_000),
                ("audio-only", video_units + 100),
            ):
                with self.subTest(location=label):
                    output_path = root / f"{label}.mkv"
                    with patch("stego.video._MIN_FREE_BYTES", 0):
                        encode_video(
                            source_path,
                            output_path,
                            SIGNING_PRIVATE_KEY,
                            RECEIVER_PUBLIC_KEY,
                            start_unit,
                            1,
                            b"boundary packet",
                            b"{}",
                        )
                    result = verify_video(
                        output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
                    )
                    self.assertEqual(result.verdict, "Authentic", result.detail)

    def test_wrong_receiver_key_reports_payload_missing(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, output_path = root / "source.mp4", root / "encoded.mkv"
            make_tiny_clip(source_path)
            wrong_receiver, _ = generate_rsa_keypair()
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, output_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 3,
                    b"secret", b"{}",
                )
            result = verify_video(output_path, SIGNING_PUBLIC_KEY, wrong_receiver)
            self.assertEqual(result.verdict, "Payload Missing")

    def test_capacity_refusal_does_not_publish_output(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, output_path = root / "source.mp4", root / "encoded.mkv"
            make_tiny_clip(source_path, frame_count=2)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                with self.assertRaisesRegex(ValueError, "capacity"):
                    encode_video(
                        source_path, output_path, SIGNING_PRIVATE_KEY,
                        RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY),
                        1, b"x" * 100_000, b"{}",
                    )
            self.assertFalse(output_path.exists())
            self.assertFalse(list(root.glob(".stego-staging-*")))

    def test_real_carrier_mutations_are_tampered(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, encoded_path = root / "source.mp4", root / "encoded.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, encoded_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 8,
                    b"tamper me", b"{}",
                )
            for name, options in (
                ("pixel-lsb", {"video_lsb": True}),
                ("audio-low", {"audio_low": True}),
                ("audio-high", {"audio_high": True}),
                ("frame-time", {"timestamp": True}),
            ):
                with self.subTest(change=name):
                    altered = root / f"{name}.mkv"
                    rewrite_matroska(encoded_path, altered, **options)
                    result = verify_video(
                        altered, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
                    )
                    self.assertEqual(result.verdict, "Tampered", result.detail)

    def test_lossless_packet_copy_remux_remains_authentic(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, encoded_path = root / "source.mp4", root / "encoded.mkv"
            remuxed = root / "remuxed.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, encoded_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 3,
                    b"remux test", b"{}",
                )
            remux_packets(encoded_path, remuxed)
            result = verify_video(remuxed, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Authentic", result.detail)

    def test_lossy_reencode_does_not_remain_authentic(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, encoded_path = root / "source.mp4", root / "encoded.mkv"
            lossy_path = root / "lossy.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, encoded_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 3,
                    b"lossy test", b"{}",
                )
            reencode_lossy(encoded_path, lossy_path)
            result = verify_video(lossy_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertNotEqual(result.verdict, "Authentic", result.detail)

    def test_extra_subtitle_stream_is_refused(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, encoded_path = root / "source.mp4", root / "encoded.mkv"
            with_subtitle = root / "with-subtitle.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, encoded_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 3,
                    b"subtitle test", b"{}",
                )
            remux_with_subtitle(encoded_path, with_subtitle)
            with self.assertRaisesRegex(ValueError, "unsupported additional stream"):
                VideoCarrier(with_subtitle)

    def test_source_change_after_pass_one_cleans_staging(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, output_path = root / "source.mp4", root / "encoded.mkv"
            make_tiny_clip(source_path)
            original = VideoCarrier.rewrite_to_path

            def change_source(
                carrier: VideoCarrier,
                path: str | bytes | PathLike[str],
                transform: Callable[[int, np.ndarray], np.ndarray],
                fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
            ) -> None:
                Path(carrier._path).write_bytes(b"source changed after pass one")
                original(carrier, path, transform, fixed_bytes_callback)

            with patch("stego.video._MIN_FREE_BYTES", 0), patch.object(
                VideoCarrier, "rewrite_to_path", change_source
            ):
                with self.assertRaises(Exception):
                    encode_video(
                        source_path, output_path, SIGNING_PRIVATE_KEY,
                        RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY),
                        3, b"change test", b"{}",
                    )
            self.assertFalse(output_path.exists())
            self.assertFalse(list(root.glob(".stego-staging-*")))

    def test_real_pass_three_corruption_is_not_published(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, output_path = root / "source.mp4", root / "encoded.mkv"
            make_tiny_clip(source_path)
            original = VideoCarrier.rewrite_to_path

            def corrupt_after_mux(
                carrier: VideoCarrier,
                path: str | bytes | PathLike[str],
                transform: Callable[[int, np.ndarray], np.ndarray],
                fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
            ) -> None:
                original(carrier, path, transform, fixed_bytes_callback)
                temporary_corrupt = root / "corrupt.mkv"
                rewrite_matroska(Path(path), temporary_corrupt, video_lsb=True)
                os.replace(temporary_corrupt, path)

            with patch("stego.video._MIN_FREE_BYTES", 0), patch.object(
                VideoCarrier, "rewrite_to_path", corrupt_after_mux
            ):
                with self.assertRaisesRegex(ValueError, "masked media hash"):
                    encode_video(
                        source_path, output_path, SIGNING_PRIVATE_KEY,
                        RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY),
                        3, b"corruption test", b"{}",
                    )
            self.assertFalse(output_path.exists())
            self.assertFalse(list(root.glob(".stego-staging-*")))

    def test_title_tag_change_remains_authentic(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, encoded_path = root / "source.mp4", root / "encoded.mkv"
            changed = root / "title.mkv"
            make_tiny_clip(source_path)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, encoded_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 3,
                    b"title test", b"{}",
                )
            rewrite_matroska(encoded_path, changed, title="metadata is not signed")
            result = verify_video(changed, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Authentic", result.detail)

    def test_rotation_change_is_skipped_with_pyav_limitation(self) -> None:
        self.skipTest(
            "PyAV 15.1 has no supported Matroska display-matrix writer API; "
            "rotation remains outside the v1 authenticity boundary"
        )

    def test_last_frame_duration_change_is_skipped_with_pyav_limitation(self) -> None:
        self.skipTest(
            "PyAV 15.1 exposes container/stream duration as read-only, and its "
            "FFV1 encoder does not preserve an assigned VideoFrame.duration; "
            "there is no supported writer path to change duration alone"
        )

    def test_payload_path_encode_is_staged_and_verifies(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.mp4"
            output_path = root / "encoded.mkv"
            payload_path = root / "payload.bin"
            payload_path.write_bytes(b"video payload from a file")
            make_h264_aac(source_path, width=64, height=32, frame_count=30)
            with patch("stego.video._MIN_FREE_BYTES", 0):
                layout, payload = encode_video_from_payload_path(
                    source_path,
                    output_path,
                    SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    bootstrap_span(RECEIVER_PUBLIC_KEY),
                    3,
                    payload_path,
                    b"{}",
                )
            self.assertEqual(layout.lsb_count, 3)
            self.assertEqual(payload.user_payload_size, payload_path.stat().st_size)
            self.assertFalse(list(root.glob(".stego-staging-*")))
            result = verify_video(
                output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY
            )
            self.assertEqual(result.verdict, "Authentic", result.detail)
            self.assertEqual(result.payload.user_payload, payload_path.read_bytes())

    @unittest.skipUnless(
        os.environ.get("STEGO_LARGE_VIDEO_TEST") == "1",
        "set STEGO_LARGE_VIDEO_TEST=1 to run the 15-second video RSS test",
    )
    def test_long_synthetic_video_rss_stays_bounded(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)

            def run_measured(source: Path, output: Path) -> int:
                code = (
                    "import resource,sys; from pathlib import Path; "
                    "from stego import bootstrap_span,encode_video,verify_video,generate_rsa_keypair; "
                    "src,dst=Path(sys.argv[1]),Path(sys.argv[2]); "
                    "sign_priv,sign_pub=generate_rsa_keypair(); recv_priv,recv_pub=generate_rsa_keypair(); "
                    "encode_video(src,dst,sign_priv,recv_pub,bootstrap_span(recv_pub),3,b'rss',b'{}'); "
                    "result=verify_video(dst,sign_pub,recv_priv); "
                    "assert result.verdict=='Authentic',result.detail; "
                    "print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)"
                )
                completed = subprocess.run(
                    [sys.executable, "-c", code, str(source), str(output)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return int(completed.stdout.strip().splitlines()[-1])

            peaks: list[int] = []
            for duration, frames in ((5, 150), (15, 450)):
                source_path = root / f"source-{duration}s.mp4"
                output_path = root / f"encoded-{duration}s.mkv"
                make_h264_aac(
                    source_path, width=640, height=360, frame_count=frames,
                    audio_frames=48_000 * duration,
                )
                peaks.append(run_measured(source_path, output_path))
            print(f"Peak RSS (5 s video/audio, 15 s video/audio): {peaks} KiB")
            self.assertLess(max(peaks), 1_500 * 1024)
            self.assertLessEqual(abs(peaks[1] - peaks[0]), 64 * 1024)

    def test_stereo_s16_is_preserved_for_source_and_rewritten_input(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "named-stereo-input.mp4"
            rewritten_path = root / "rewritten-stereo.mkv"
            make_h264_aac(source_path, frame_count=3, audio_frames=48_000)
            source = VideoCarrier(source_path)
            try:
                source.rewrite_to_path(rewritten_path, lambda _offset, units: units)
            finally:
                source.close()

            def audio_s16(path: Path) -> np.ndarray:
                carrier = VideoCarrier(path)
                try:
                    chunks: list[np.ndarray] = []
                    first = True
                    for units, fixed in carrier._iter_audio(True):
                        high = np.frombuffer(fixed[8:] if first else fixed, dtype=np.uint8)
                        first = False
                        self.assertEqual(high.size, units.size)
                        packed = units.astype(np.uint16) | (high.astype(np.uint16) << 8)
                        chunks.append(packed.astype("<i2", copy=False))
                    return np.concatenate(chunks)
                finally:
                    carrier.close()

            source_samples = audio_s16(source_path)
            self.assertEqual(source_samples.size % 2, 0)
            self.assertTrue(np.array_equal(source_samples, audio_s16(rewritten_path)))
            # Matroska PCM may report an unspecified two-channel identity on read-back.
            second_rewrite = root / "rewritten-again.mkv"
            carrier = VideoCarrier(rewritten_path)
            try:
                carrier.rewrite_to_path(second_rewrite, lambda _offset, units: units)
            finally:
                carrier.close()
            self.assertTrue(np.array_equal(source_samples, audio_s16(second_rewrite)))

    def test_mono_encode_verifies_and_preserves_s16_values(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "mono-source.mkv"
            output_path = root / "mono-encoded.mkv"
            mono_samples = np.arange(4_800, dtype=np.int16) * 3 - 7_000
            make_matroska(
                source_path,
                ticks=tuple(index * 40 for index in range(90)),
                audio_samples=mono_samples,
                audio_rate=48_000,
                audio_channels=1,
                audio_layout="mono",
                width=64,
                height=32,
            )
            with patch("stego.video._MIN_FREE_BYTES", 0):
                encode_video(
                    source_path, output_path, SIGNING_PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY),
                    3, b"mono video carrier", b"{}",
                )
            result = verify_video(output_path, SIGNING_PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Authentic", result.detail)
            self.assertEqual(result.payload.user_payload, b"mono video carrier")

            def samples_from(path: Path) -> np.ndarray:
                carrier = VideoCarrier(path)
                try:
                    low_parts: list[np.ndarray] = []
                    high_parts: list[np.ndarray] = []
                    first_chunk = True
                    for units, fixed in carrier._iter_audio(True):
                        high_bytes = fixed[8:] if first_chunk else fixed
                        first_chunk = False
                        low_parts.append(units)
                        high_parts.append(np.frombuffer(high_bytes, dtype=np.uint8))
                    low = np.concatenate(low_parts).astype(np.uint16)
                    high = np.concatenate(high_parts).astype(np.uint16)
                    return (low | (high << 8)).astype("<i2")
                finally:
                    carrier.close()

            np.testing.assert_array_equal(samples_from(source_path), mono_samples)
            np.testing.assert_array_equal(samples_from(output_path), mono_samples)


if __name__ == "__main__":

    unittest.main()
