"""Read a bounded, canonical video-plus-audio carrier with PyAV."""

import os
import shutil
import struct
import tempfile
from collections.abc import Callable, Iterator
from fractions import Fraction
from os import PathLike, fspath
from pathlib import Path

import av
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa

from .bits import _validate_positive_integer
from .carrier import (
    DEFAULT_CHUNK_BYTES,
    CarrierAccessError,
    CarrierSource,
    _validate_transformed_units,
    _validate_unit_range,
)
from .constants import VIDEO_MEDIA_CODE
from .core import (
    CarrierEncoding,
    VerificationResult,
    _context_for_sender_key,
    _encode_file_from_payload_path,
    _failure_result,
    _paths_resolve_same,
    _remove_incomplete_output,
    _rewrite_checked,
    decode_carrier_source,
    decode_carrier_source_to_payload_path,
    prepare_carrier_encoding,
)
from .layout import EmbeddingLayout
from .packet import PayloadFileRecord, PayloadRecord

_MAX_CARRIER_UNITS = 4 * 1024**3
_MAX_FRAME_BYTES = 256 * 1024**2
_MAX_OUTPUT_BYTES = 2 * 1024**3
_MIN_FREE_BYTES = 3 * 1024 * 1024 * 1024
_AUDIO_CHANNEL_COUNTS = frozenset((1, 2))
_VIDEO_CONTEXT_FORMAT = ">IIQBBIHQ"
_VIDEO_DEPTHS = (8, 9, 10, 12, 14, 16)
_VIDEO_ALPHA_DEPTHS = (8, 10, 12, 14, 16)


def _check_video_output_resources(
    path: str | bytes | PathLike[str], additional_required_bytes: int = 0
) -> Path:
    """Check destination free space and return its normalized path."""
    if additional_required_bytes < 0:
        raise ValueError("additional_required_bytes must be non-negative")
    destination = Path(os.fsdecode(fspath(path)))
    parent = destination.parent
    if shutil.disk_usage(parent).free < _MIN_FREE_BYTES + additional_required_bytes:
        raise ValueError("insufficient free disk space for video output")
    return destination


def _check_video_frame_bytes(
    width: int, height: int, depth: int, channel_count: int
) -> None:
    """Refuse a canonical decoded frame above the configured byte limit."""
    bytes_per_sample = 1 if depth == 8 else 2
    if width * height * channel_count * bytes_per_sample > _MAX_FRAME_BYTES:
        raise ValueError("video frame exceeds configured frame-byte limit")


def _new_video_stage(destination: Path) -> Path:
    """Create an output staging file in the destination directory."""
    descriptor, stage_name = tempfile.mkstemp(
        prefix=".stego-staging-", suffix=".mkv", dir=destination.parent
    )
    os.close(descriptor)
    return Path(stage_name)


def _check_video_file_size(path: str | bytes | PathLike[str]) -> None:
    """Enforce the single configured Matroska output byte limit."""
    try:
        output_size = os.path.getsize(path)
    except OSError:
        output_size = 0
    if output_size > _MAX_OUTPUT_BYTES:
        raise ValueError("video output exceeds configured byte limit")


def _video_format_info(video_format: object) -> tuple[int, bool, int, str, str]:
    """Return source depth, alpha flag, canonical depth, decode, and output formats."""
    name = getattr(video_format, "name", None)
    components = getattr(video_format, "components", None)
    if not isinstance(name, str) or components is None:
        raise ValueError("unsupported video pixel format")
    lowered_name = name.lower()
    if any(marker in lowered_name for marker in ("f16", "f32", "f64")):
        raise ValueError("unsupported video pixel format")
    try:
        component_bits = tuple(int(component.bits) for component in components)
        has_alpha = any(bool(component.is_alpha) for component in components)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("unsupported video pixel format") from error
    if not component_bits or min(component_bits) < 1:
        raise ValueError("unsupported video pixel format")
    source_depth = max(component_bits)
    if source_depth > 16:
        raise ValueError("unsupported video pixel format")
    depth_table = _VIDEO_ALPHA_DEPTHS if has_alpha else _VIDEO_DEPTHS
    canonical_depth = next(
        (depth for depth in depth_table if depth >= source_depth), None
    )
    if canonical_depth is None:
        raise ValueError("unsupported video pixel format")
    channels = "ap" if has_alpha else "p"
    if canonical_depth == 8:
        decode_format = "rgba" if has_alpha else "rgb24"
        output_format = "bgra" if has_alpha else "bgr0"
    else:
        decode_format = f"gbr{channels}{canonical_depth}le"
        output_format = decode_format
    return source_depth, has_alpha, canonical_depth, decode_format, output_format


def _check_video_conversion(frame: object, pixel_format: str) -> None:
    """Confirm that the decoded frame converts to its canonical pixel format."""
    try:
        converted = frame.reformat(format=pixel_format)
    except Exception as error:
        raise ValueError("unsupported video pixel format") from error
    if converted.format.name != pixel_format:
        raise ValueError("unsupported video pixel format")


def _canonical_frame_array(
    frame: object,
    pixel_format: str,
    width: int,
    height: int,
    depth: int,
    channel_count: int,
) -> np.ndarray:
    """Return canonical RGB(A) pixels at their native component depth."""
    try:
        pixels = frame.to_ndarray(format=pixel_format)
    except Exception as error:
        raise CarrierAccessError("unsupported video pixel format") from error
    dtype = np.uint8 if depth == 8 else np.uint16
    if pixels.shape != (height, width, channel_count) or pixels.dtype != dtype:
        raise CarrierAccessError("unsupported video pixel format")
    # The canonical pixel format defines the sample range. Avoid a full-frame
    # maximum scan on every pass; encode read-back checks exact decoded values.
    return pixels


def _high_bytes_little_endian(values: np.ndarray) -> bytes:
    """Return each uint16 sample's high byte without shift/cast temporaries."""
    little_endian = values.astype("<u2", copy=False)
    return little_endian.view(np.uint8)[1::2].tobytes()


def _pack_video_context(
    width: int,
    height: int,
    frame_count: int,
    depth: int,
    video_channels: int,
    audio_rate: int,
    audio_channels: int,
    audio_frames: int,
) -> bytes:
    """Build the fixed 32-byte media-code-3 context."""
    return struct.pack(
        _VIDEO_CONTEXT_FORMAT,
        width,
        height,
        frame_count,
        depth,
        video_channels,
        audio_rate,
        audio_channels,
        audio_frames,
    )


def _round_fraction(value: Fraction) -> int:
    """Round an exact rational to the nearest integer, with ties away from zero."""
    numerator = value.numerator
    denominator = value.denominator
    sign = -1 if numerator < 0 else 1
    quotient, remainder = divmod(abs(numerator), denominator)
    if remainder * 2 >= denominator:
        quotient += 1
    return sign * quotient


def _audio_position_matches(actual: int, expected: int, sample_rate: int) -> bool:
    """Allow only the rounding error of a millisecond media time base."""
    return abs(actual - expected) <= (sample_rate + 1_999) // 2_000


def _audio_layout_identities(layout: object) -> tuple[str, ...]:
    """Accept canonical mono/stereo identities or wholly unspecified layouts."""
    channels = getattr(layout, "channels", None)
    if channels is None:
        raise ValueError("unsupported audio channel layout")
    identities = tuple(getattr(channel, "name", "NONE") for channel in channels)
    if len(identities) not in _AUDIO_CHANNEL_COUNTS:
        raise ValueError("unsupported audio channel count")
    if identities not in {
        ("FC",),
        ("NONE",),
        ("FL", "FR"),
        ("NONE", "NONE"),
    }:
        raise ValueError("unsupported audio channel layout")
    return identities


def _pack_tick(tick: int) -> bytes:
    """Encode a signed canonical millisecond tick as a checked i64."""
    if tick < -(1 << 63) or tick >= 1 << 63:
        raise ValueError("media timestamp does not fit the signed 64-bit context")
    return struct.pack(">q", tick)


def _frame_time(frame: object, stream: object) -> Fraction:
    """Return a frame timestamp in seconds without converting it to float."""
    pts = getattr(frame, "pts", None)
    time_base = getattr(frame, "time_base", None) or getattr(stream, "time_base", None)
    if pts is None or time_base is None:
        raise ValueError("missing media timestamp")
    return Fraction(pts) * Fraction(time_base)


def _frame_ticks(
    frames: Iterator[object], stream: object, first_time: Fraction | None = None
) -> Iterator[tuple[object, int, Fraction]]:
    """Yield decoded frames with canonical millisecond ticks and exact time."""
    previous: Fraction | None = None
    previous_tick: int | None = None
    origin = first_time
    for frame in frames:
        exact_time = _frame_time(frame, stream)
        if previous is not None and exact_time <= previous:
            raise ValueError("video timestamps must be strictly increasing")
        if origin is None:
            origin = exact_time
        tick = _round_fraction((exact_time - origin) * 1000)
        if previous is not None and tick <= (previous_tick if previous_tick is not None else -1):
            raise ValueError("distinct video timestamps collide at millisecond precision")
        previous = exact_time
        previous_tick = tick
        yield frame, tick, exact_time


def _pcm_bytes(frame: object) -> bytes:
    """Return packed little-endian signed 16-bit samples from a resampled frame."""
    samples = np.asarray(frame.to_ndarray())
    if samples.dtype != np.int16:
        raise ValueError("audio conversion did not produce signed 16-bit samples")
    return np.ascontiguousarray(samples).reshape(-1).astype("<i2", copy=False).tobytes()


def _configure_decoder(stream: object) -> None:
    """Use FFmpeg automatic threading on every decoder open."""
    stream.thread_count = 0
    stream.thread_type = "AUTO"


def _audio_chunks(
    converted: object,
    chunk_units: int,
    channels: int,
    with_fixed_bytes: bool,
    first_chunk: bool,
    audio_start_tick: int,
) -> Iterator[tuple[np.ndarray, bytes, bytes]]:
    """Yield aligned s16 carrier chunks, high bytes, and timing/fixed bytes."""
    pcm = _pcm_bytes(converted)
    raw = np.frombuffer(pcm, dtype=np.uint8)
    if raw.size % 2:
        raise ValueError("decoded audio sample bytes are incomplete")
    low = raw[0::2]
    high = raw[1::2]
    if low.size % channels:
        raise ValueError("decoded audio does not contain whole channel frames")
    chunk_limit = max(channels, chunk_units // channels * channels)
    for offset in range(0, low.size, chunk_limit):
        end = min(low.size, offset + chunk_limit)
        units = low[offset:end].copy()
        high_bytes = high[offset:end].tobytes()
        fixed = high_bytes if with_fixed_bytes else b""
        if with_fixed_bytes and first_chunk and offset == 0:
            fixed = _pack_tick(audio_start_tick) + fixed
        yield units, high_bytes, fixed


def _audio_resampler(av_module: object, stream: object) -> object:
    """Convert decoded samples to s16 without changing rate or channel order."""
    codec = stream.codec_context
    layout = codec.layout
    _audio_layout_identities(layout)
    sample_rate = codec.sample_rate
    if sample_rate is None or sample_rate < 1:
        raise ValueError("invalid audio sample rate")
    return av_module.AudioResampler(
        format="s16", layout=layout, rate=sample_rate
    )


class VideoCarrier(CarrierSource):
    """Expose decoded RGB frames followed by interleaved PCM audio samples.

    The constructor makes a bounded validation/counting pass. Later reads
    reopen and decode the input; frame and sample arrays are not retained.
    """

    def __init__(
        self,
        path: str | bytes | PathLike[str],
        chunk_units: int = DEFAULT_CHUNK_BYTES,
    ) -> None:
        """Validate and count a video file using bounded decode passes."""
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
        chunk_units = min(
            _validate_positive_integer(chunk_units, "chunk_units"), DEFAULT_CHUNK_BYTES
        )
        self._path = path
        self._chunk_units = chunk_units
        self._read_iterator: Iterator[np.ndarray] | None = None
        self._read_position = 0
        self._read_chunk: np.ndarray | None = None
        self._read_chunk_offset = 0
        self._closed = False
        self._current_video_origin: Fraction | None = None
        self._output_reader = False
        self._scan()

    @property
    def path(self) -> str | bytes | PathLike[str]:
        """Return the file path used to open this carrier."""
        return self._path

    @property
    def total_units(self) -> int:
        """Return three low-byte RGB units per pixel plus audio sample units."""
        return self._total_units

    @property
    def fixed_byte_count(self) -> int:
        """Return frame timing, RGB high bytes, alpha bytes, and audio fixed bytes."""
        return self._fixed_byte_count

    @property
    def media_code(self) -> int:
        """Return the protocol video media code."""
        return VIDEO_MEDIA_CODE

    @property
    def media_context(self) -> bytes:
        """Return the fixed 32-byte video/audio context."""
        return self._media_context

    @property
    def requires_output_check(self) -> bool:
        """Video encodes require a decoded read-back check."""
        return True

    @property
    def frame_count(self) -> int:
        """Return the decoded video-frame count."""
        return self._frame_count

    @property
    def audio_frames_per_channel(self) -> int:
        """Return the decoded audio sample count per channel."""
        return self._audio_frames_per_channel

    def _open(self) -> object:
        """Open an input container with PyAV."""
        return av.open(fspath(self._path), mode="r")

    @staticmethod
    def _select_streams(container: object) -> tuple[object, object | None]:
        """Require exactly one video, at most one audio, and no other streams."""
        streams = list(container.streams)
        videos = [stream for stream in streams if stream.type == "video"]
        audios = [stream for stream in streams if stream.type == "audio"]
        if len(videos) > 1 or len(audios) > 1 or len(videos) + len(audios) != len(streams):
            raise ValueError("unsupported additional stream")
        if len(videos) != 1:
            raise ValueError("video file must contain exactly one video stream")
        _configure_decoder(videos[0])
        if audios:
            _configure_decoder(audios[0])
        return videos[0], audios[0] if audios else None

    def _scan(self) -> None:
        """Count frames and samples, validate timing, and build signed context."""
        with self._open() as container:
            video_stream, audio_stream = self._select_streams(container)
            width = video_stream.codec_context.width
            height = video_stream.codec_context.height
            if not width or not height:
                raise ValueError("invalid video dimensions")
            header_format = video_stream.codec_context.format
            header_info = (
                _video_format_info(header_format) if header_format is not None else None
            )
            if header_info is not None:
                _check_video_frame_bytes(
                    width, height, header_info[2], 4 if header_info[1] else 3
                )

        first_video_time: Fraction | None = None
        frame_count = 0
        total_units = 0
        source_depth: int | None = None
        has_alpha: bool | None = None
        canonical_depth = 0
        decode_pixel_format = ""
        output_pixel_format = ""
        with self._open() as container:
            video_stream, _ = self._select_streams(container)
            decoder = container.decode(video=0)
            for frame, _tick, exact_time in _frame_ticks(decoder, video_stream):
                frame_info = _video_format_info(frame.format)
                frame_depth, frame_alpha, frame_canonical_depth, frame_decode_format, frame_output_format = frame_info
                _check_video_frame_bytes(
                    frame.width, frame.height, frame_canonical_depth,
                    4 if frame_alpha else 3,
                )
                if frame.width != width or frame.height != height:
                    raise ValueError("video dimensions changed during decode")
                if source_depth is None:
                    if header_info is not None and frame_info[:2] != header_info[:2]:
                        raise ValueError("video pixel format changed during decode")
                    source_depth = frame_depth
                    has_alpha = frame_alpha
                    canonical_depth = frame_canonical_depth
                    decode_pixel_format = frame_decode_format
                    output_pixel_format = frame_output_format
                    _check_video_conversion(frame, decode_pixel_format)
                elif (frame_depth, frame_alpha) != (source_depth, has_alpha):
                    raise ValueError("video pixel format changed during decode")
                total_units += frame.width * frame.height * 3
                if total_units > _MAX_CARRIER_UNITS:
                    raise ValueError(
                        "video carrier exceeds configured carrier-unit limit"
                    )
                if first_video_time is None:
                    first_video_time = exact_time
                frame_count += 1
        if not frame_count or first_video_time is None:
            raise ValueError("video stream contains no decoded frames")

        audio_rate = 0
        audio_channels = 0
        audio_layout_identities: tuple[str, ...] = ()
        audio_frames = 0
        audio_start_tick = 0
        if audio_stream is not None:
            audio_rate = audio_stream.codec_context.sample_rate or 0
            layout = audio_stream.codec_context.layout
            audio_layout_identities = _audio_layout_identities(layout)
            audio_channels = len(audio_layout_identities)
            if audio_rate < 1:
                raise ValueError("invalid audio sample rate")
            audio_first_time: Fraction | None = None
            with self._open() as container:
                _, selected_audio = self._select_streams(container)
                if selected_audio is None:
                    raise ValueError("audio stream disappeared during decode")
                for frame in container.decode(audio=0):
                    exact_time = _frame_time(frame, selected_audio)
                    if frame.sample_rate != audio_rate:
                        raise ValueError("audio sample rate changed during decode")
                    if _audio_layout_identities(frame.layout) != audio_layout_identities:
                        raise ValueError("unsupported audio channel layout")
                    total_units += frame.samples * audio_channels
                    if total_units > _MAX_CARRIER_UNITS:
                        raise ValueError(
                            "video carrier exceeds configured carrier-unit limit"
                        )
                    if audio_first_time is None:
                        audio_first_time = exact_time
                        audio_start_tick = _round_fraction(
                            (exact_time - first_video_time) * 1000
                        )
                    actual_position = _round_fraction(
                        (exact_time - audio_first_time) * audio_rate
                    )
                    if not _audio_position_matches(actual_position, audio_frames, audio_rate):
                        raise ValueError("audio contains a gap or overlap")
                    audio_frames += frame.samples
            if audio_frames == 0 or audio_first_time is None:
                raise ValueError("audio stream contains no decoded samples")

        self._width = width
        self._height = height
        self._frame_count = frame_count
        self._first_video_time = first_video_time
        self._audio_rate = audio_rate
        self._audio_channels = audio_channels
        self._audio_frames_per_channel = audio_frames
        self._audio_start_tick = audio_start_tick
        self._source_depth = source_depth
        self._depth = canonical_depth
        self._has_alpha = bool(has_alpha)
        self._video_channels = 4 if self._has_alpha else 3
        self._decode_pixel_format = decode_pixel_format
        self._output_pixel_format = output_pixel_format
        self._video_units = frame_count * width * height * 3
        audio_units = audio_frames * audio_channels
        self._total_units = total_units
        pixels_per_frame = width * height
        frame_fixed_bytes = 8
        if self._depth > 8:
            frame_fixed_bytes += 3 * pixels_per_frame
        if self._has_alpha:
            frame_fixed_bytes += pixels_per_frame * (1 if self._depth == 8 else 2)
        self._fixed_byte_count = frame_count * frame_fixed_bytes + (
            8 + audio_units if audio_units else 0
        )
        self._media_context = _pack_video_context(
            width,
            height,
            frame_count,
            self._depth,
            self._video_channels,
            audio_rate,
            audio_channels,
            audio_frames,
        )

    def _iter_video(
        self, with_fixed_bytes: bool
    ) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield bounded low-byte RGB units and ordered frame fixed bytes."""
        frame_count = 0
        first_time = self._first_video_time
        self._current_video_origin = None
        with self._open() as container:
            stream, audio_stream = self._select_streams(container)
            if (audio_stream is None) != (self._audio_channels == 0):
                raise CarrierAccessError("audio stream presence changed after validation")
            header_format = stream.codec_context.format
            if header_format is not None:
                header_info = _video_format_info(header_format)
                expected_depth = self._depth if self._output_reader else self._source_depth
                if (header_info[0], header_info[1]) != (
                    expected_depth,
                    self._has_alpha,
                ):
                    raise CarrierAccessError("video pixel format changed during decode")
                if self._output_reader and header_info[2] != self._depth:
                    raise CarrierAccessError(
                        "output video pixel format does not match signed context"
                    )
            for frame, tick, exact_time in _frame_ticks(
                container.decode(video=0), stream, first_time
            ):
                if self._current_video_origin is None:
                    self._current_video_origin = exact_time
                if frame.width != self._width or frame.height != self._height:
                    raise CarrierAccessError("video dimensions changed after validation")
                frame_info = _video_format_info(frame.format)
                expected_depth = self._depth if self._output_reader else self._source_depth
                if (frame_info[0], frame_info[1]) != (
                    expected_depth,
                    self._has_alpha,
                ):
                    raise CarrierAccessError("video pixel format changed during decode")
                if self._output_reader and frame_info[2] != self._depth:
                    raise CarrierAccessError(
                        "output video pixel format does not match signed context"
                    )
                pixels = _canonical_frame_array(
                    frame,
                    self._decode_pixel_format,
                    self._width,
                    self._height,
                    self._depth,
                    self._video_channels,
                )
                pixel_values = pixels.reshape(-1, self._video_channels)
                chunk_limit = min(self._chunk_units, DEFAULT_CHUNK_BYTES)
                pixels_per_chunk = max(1, chunk_limit // 3)
                first_chunk = True
                pixel_count = self._width * self._height
                for pixel_offset in range(0, pixel_count, pixels_per_chunk):
                    pixel_end = min(pixel_count, pixel_offset + pixels_per_chunk)
                    values = pixel_values[pixel_offset:pixel_end, :3].reshape(-1)
                    units = values.astype(np.uint8, copy=False)
                    fixed = _pack_tick(tick) if with_fixed_bytes and first_chunk else b""
                    if with_fixed_bytes and self._depth > 8:
                        fixed += _high_bytes_little_endian(values)
                    yield units, fixed
                    first_chunk = False
                if with_fixed_bytes and self._has_alpha:
                    alpha_bytes = 1 if self._depth == 8 else 2
                    alpha_limit = max(1, chunk_limit // alpha_bytes)
                    alpha = pixel_values[:, 3]
                    for offset in range(0, alpha.size, alpha_limit):
                        values = alpha[offset:offset + alpha_limit]
                        fixed = (
                            values.astype(np.uint8, copy=False).tobytes()
                            if alpha_bytes == 1
                            else values.astype("<u2", copy=False).tobytes()
                        )
                        yield np.empty(0, dtype=np.uint8), fixed
                frame_count += 1
        if frame_count != self._frame_count:
            raise CarrierAccessError("video frame count changed after validation")

    def _iter_audio(
        self, with_fixed_bytes: bool
    ) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield s16 low bytes with timing and high bytes in the fixed stream."""
        if self._audio_channels == 0:
            return
        import av

        emitted_samples = 0
        input_samples = 0
        first_audio_time: Fraction | None = None
        with self._open() as container:
            _, stream = self._select_streams(container)
            if stream is None:
                raise CarrierAccessError("audio stream disappeared after validation")
            if stream.codec_context.sample_rate != self._audio_rate:
                raise CarrierAccessError("audio sample rate changed after validation")
            if self._current_video_origin is None and self._first_video_time is not None:
                self._current_video_origin = self._first_video_time
            header_layout = _audio_layout_identities(stream.codec_context.layout)
            if len(header_layout) != self._audio_channels:
                raise CarrierAccessError("unsupported audio channel layout")
            resampler = _audio_resampler(av, stream)
            first_chunk = True
            for frame in container.decode(audio=0):
                if frame.sample_rate != self._audio_rate:
                    raise CarrierAccessError("audio sample rate changed after validation")
                if _audio_layout_identities(frame.layout) != header_layout:
                    raise CarrierAccessError("unsupported audio channel layout")
                exact_time = _frame_time(frame, stream)
                if first_audio_time is None:
                    first_audio_time = exact_time
                    if self._current_video_origin is None:
                        raise CarrierAccessError("video origin is missing during audio decode")
                    actual_tick = _round_fraction(
                        (exact_time - self._current_video_origin) * 1000
                    )
                    if actual_tick != self._audio_start_tick:
                        raise CarrierAccessError("audio start time changed after validation")
                actual_position = _round_fraction(
                    (exact_time - first_audio_time) * self._audio_rate
                )
                if not _audio_position_matches(actual_position, input_samples, self._audio_rate):
                    raise CarrierAccessError("audio contains a gap or overlap")
                input_samples += frame.samples
                for converted in resampler.resample(frame):
                    for units, _, fixed in _audio_chunks(
                        converted,
                        self._chunk_units,
                        self._audio_channels,
                        with_fixed_bytes,
                        first_chunk,
                        self._audio_start_tick,
                    ):
                        yield units, fixed
                        emitted_samples += units.size
                        first_chunk = False
            for converted in resampler.resample(None):
                for units, _, fixed in _audio_chunks(
                    converted,
                    self._chunk_units,
                    self._audio_channels,
                    with_fixed_bytes,
                    first_chunk,
                    self._audio_start_tick,
                ):
                    yield units, fixed
                    emitted_samples += units.size
                    first_chunk = False
        if input_samples != self._audio_frames_per_channel:
            raise CarrierAccessError("audio sample count changed after validation")
        if emitted_samples != self._audio_frames_per_channel * self._audio_channels:
            raise CarrierAccessError("audio sample count changed after validation")

    def rewrite_to_path(
        self,
        path: str | bytes | PathLike[str],
        transform: Callable[[int, np.ndarray], np.ndarray],
        fixed_bytes_callback: Callable[[int, np.ndarray, bytes], None] | None = None,
    ) -> None:
        """Write selected native-depth RGB(A)/s16 tracks to tag-free Matroska."""
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
        import av

        output = av.open(fspath(path), mode="w", format="matroska")
        # The stream rate is a nominal codec setting; explicit millisecond PTS
        # and time bases below carry the actual (including VFR) frame timing.
        video_output = output.add_stream("ffv1", rate=25)
        video_output.width = self._width
        video_output.height = self._height
        video_output.pix_fmt = self._output_pixel_format
        video_output.time_base = Fraction(1, 1000)
        video_codec = video_output.codec_context
        video_codec.time_base = Fraction(1, 1000)
        video_codec.gop_size = 1
        video_codec.thread_count = 0
        video_codec.options = {"level": "3", "slices": "16", "threads": "auto"}

        audio_output = None
        audio_layout = "mono" if self._audio_channels == 1 else "stereo"
        if self._audio_channels:
            audio_output = output.add_stream("pcm_s16le", rate=self._audio_rate)
            audio_output.layout = audio_layout
            audio_output.time_base = Fraction(1, self._audio_rate)

        def mux_packets(stream: object, frame: object | None = None) -> None:
            packets = stream.encode() if frame is None else stream.encode(frame)
            for packet in packets:
                output.mux(packet)
                _check_video_file_size(path)

        try:
            video_units = 0
            frame_count = 0
            with self._open() as source_container:
                source_video, _ = self._select_streams(source_container)
                for frame, tick, exact_time in _frame_ticks(
                    source_container.decode(video=0),
                    source_video,
                    self._first_video_time,
                ):
                    if frame_count == 0:
                        self._current_video_origin = exact_time
                    frame_info = _video_format_info(frame.format)
                    if (frame_info[0], frame_info[1]) != (
                        self._source_depth,
                        self._has_alpha,
                    ):
                        raise CarrierAccessError(
                            "video pixel format changed during decode"
                        )
                    pixels = _canonical_frame_array(
                        frame,
                        self._decode_pixel_format,
                        self._width,
                        self._height,
                        self._depth,
                        self._video_channels,
                    )
                    pixel_values = pixels.reshape(-1, self._video_channels)
                    chunk_limit = min(self._chunk_units, DEFAULT_CHUNK_BYTES)
                    pixels_per_chunk = max(1, chunk_limit // 3)
                    first_chunk = True
                    pixel_count = self._width * self._height
                    for pixel_offset in range(0, pixel_count, pixels_per_chunk):
                        pixel_end = min(pixel_count, pixel_offset + pixels_per_chunk)
                        rgb_values = pixel_values[pixel_offset:pixel_end, :3].reshape(-1)
                        original = rgb_values.astype(np.uint8, copy=False)
                        fixed = _pack_tick(tick) if first_chunk else b""
                        if self._depth > 8:
                            fixed += _high_bytes_little_endian(rgb_values)
                        if fixed_bytes_callback is not None:
                            fixed_bytes_callback(video_units, original, fixed)
                        changed = _validate_transformed_units(
                            transform(video_units, original), original.size
                        )
                        if self._depth == 8:
                            rgb_values[:] = changed
                        else:
                            rgb_values[:] = (rgb_values & np.uint16(0xFF00)) | changed
                        pixel_values[pixel_offset:pixel_end, :3] = rgb_values.reshape(
                            -1, 3
                        )
                        video_units += original.size
                        first_chunk = False
                    if self._has_alpha and fixed_bytes_callback is not None:
                        alpha_bytes = 1 if self._depth == 8 else 2
                        alpha_limit = max(1, chunk_limit // alpha_bytes)
                        alpha = pixel_values[:, 3]
                        for offset in range(0, alpha.size, alpha_limit):
                            values = alpha[offset:offset + alpha_limit]
                            fixed = (
                                values.astype(np.uint8, copy=False).tobytes()
                                if alpha_bytes == 1
                                else values.astype("<u2", copy=False).tobytes()
                            )
                            fixed_bytes_callback(
                                video_units, np.empty(0, dtype=np.uint8), fixed
                            )
                    encoded_frame = av.VideoFrame.from_ndarray(
                        pixels,
                        format=self._decode_pixel_format,
                    )
                    encoded_frame.pts = tick
                    encoded_frame.time_base = Fraction(1, 1000)
                    mux_packets(video_output, encoded_frame)
                    frame_count += 1
            if frame_count != self._frame_count or video_units != self._video_units:
                raise CarrierAccessError("video carrier changed after validation")

            if audio_output is not None:
                audio_sample_position = _round_fraction(
                    Fraction(self._audio_start_tick * self._audio_rate, 1000)
                )
                audio_unit_offset = 0
                first_audio_chunk = True
                for units, fixed in self._iter_audio(True):
                    high_bytes = fixed[8:] if first_audio_chunk else fixed
                    if fixed_bytes_callback is not None:
                        fixed_bytes_callback(
                            self._video_units + audio_unit_offset, units, fixed
                        )
                    changed = _validate_transformed_units(
                        transform(self._video_units + audio_unit_offset, units),
                        units.size,
                    )
                    high = np.frombuffer(high_bytes, dtype=np.uint8)
                    if high.size != changed.size:
                        raise CarrierAccessError("audio fixed-byte chunk has the wrong size")
                    pcm = np.empty(changed.size * 2, dtype=np.uint8)
                    pcm[0::2] = changed
                    pcm[1::2] = high
                    samples = np.frombuffer(pcm.tobytes(), dtype="<i2")
                    audio_frame = av.AudioFrame.from_ndarray(
                        samples.reshape(1, -1),
                        format="s16",
                        layout=audio_layout,
                    )
                    audio_frame.sample_rate = self._audio_rate
                    audio_frame.pts = audio_sample_position
                    audio_frame.time_base = Fraction(1, self._audio_rate)
                    mux_packets(audio_output, audio_frame)
                    sample_count = changed.size // self._audio_channels
                    audio_sample_position += sample_count
                    audio_unit_offset += changed.size
                    first_audio_chunk = False
                if audio_unit_offset != self._audio_frames_per_channel * self._audio_channels:
                    raise CarrierAccessError("audio carrier changed after validation")

            mux_packets(video_output)
            if audio_output is not None:
                mux_packets(audio_output)
        finally:
            output.close()
        _check_video_file_size(path)

    def open_rewritten_output(
        self, path: str | bytes | PathLike[str]
    ) -> VideoCarrier:
        """Open a read-back iterator that validates during its single full pass.

        The expected context is copied as a comparison target. The output pass
        independently checks stream selection, dimensions, timing, rates,
        channel layout, and exact decoded unit/fixed-byte counts, so an extra
        counting decode is not needed before ``CarrierEncoding.check_output``.
        """
        output = object.__new__(VideoCarrier)
        output._path = path
        output._chunk_units = self._chunk_units
        output._read_iterator = None
        output._read_position = 0
        output._read_chunk = None
        output._read_chunk_offset = 0
        output._closed = False
        output._first_video_time = None
        output._current_video_origin = None
        output._output_reader = True
        for attribute in (
            "_width", "_height", "_frame_count", "_audio_rate",
            "_audio_channels", "_audio_frames_per_channel", "_audio_start_tick",
            "_source_depth", "_depth", "_has_alpha", "_video_channels",
            "_decode_pixel_format", "_output_pixel_format", "_video_units",
            "_total_units", "_fixed_byte_count", "_media_context",
        ):
            setattr(output, attribute, getattr(self, attribute))
        with output._open() as container:
            video_stream, _ = self._select_streams(container)
            output_width = video_stream.codec_context.width
            output_height = video_stream.codec_context.height
            header_format = video_stream.codec_context.format
            if header_format is not None:
                info = _video_format_info(header_format)
                output._source_depth = info[0]
                output._depth = info[2]
                output._has_alpha = info[1]
                output._video_channels = 4 if info[1] else 3
                output._decode_pixel_format = info[3]
                output._output_pixel_format = info[4]
                output._width = output_width
                output._height = output_height
                output._video_units = (
                    output._frame_count * output_width * output_height * 3
                )
                output._total_units = output._video_units + (
                    output._audio_frames_per_channel * output._audio_channels
                )
                frame_fixed_bytes = 8
                if output._depth > 8:
                    frame_fixed_bytes += 3 * output_width * output_height
                if output._has_alpha:
                    frame_fixed_bytes += output_width * output_height * (
                        1 if output._depth == 8 else 2
                    )
                audio_units = (
                    output._audio_frames_per_channel * output._audio_channels
                )
                output._fixed_byte_count = output._frame_count * frame_fixed_bytes + (
                    8 + audio_units if audio_units else 0
                )
                output._media_context = _pack_video_context(
                    output_width,
                    output_height,
                    output._frame_count,
                    output._depth,
                    output._video_channels,
                    output._audio_rate,
                    output._audio_channels,
                    output._audio_frames_per_channel,
                )
        return output

    def iter_chunks_with_fixed_bytes(self) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield bounded video chunks followed by audio chunks and fixed bytes."""
        import av

        try:
            yield from self._iter_video(True)
            yield from self._iter_audio(True)
        except CarrierAccessError:
            raise
        except (OSError, ValueError, av.error.FFmpegError) as error:
            raise CarrierAccessError("could not decode video carrier") from error

    def iter_chunks(self) -> Iterator[np.ndarray]:
        """Yield bounded RGB and audio carrier units in protocol order."""
        import av

        try:
            for units, _ in self._iter_video(False):
                yield units
            for units, _ in self._iter_audio(False):
                yield units
        except CarrierAccessError:
            raise
        except (OSError, ValueError, av.error.FFmpegError) as error:
            raise CarrierAccessError("could not decode video carrier") from error

    def _reset_reader(self) -> None:
        """Reset the persistent range reader to the start of the carrier."""
        if self._read_iterator is not None:
            close = getattr(self._read_iterator, "close", None)
            if close is not None:
                close()
        self._read_iterator = iter(self.iter_chunks())
        self._read_position = 0
        self._read_chunk = None
        self._read_chunk_offset = 0

    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        """Return a bounded carrier range using a monotonic decode cache."""
        start_unit, count = _validate_unit_range(
            start_unit, count, self.total_units
        )
        if self._closed:
            raise CarrierAccessError("video carrier is closed")
        if count == 0:
            return np.empty(0, dtype=np.uint8)
        if self._read_iterator is None or start_unit < self._read_position:
            self._reset_reader()
        result = np.empty(count, dtype=np.uint8)
        written = 0
        while written < count:
            if self._read_chunk is None or self._read_chunk_offset >= self._read_chunk.size:
                try:
                    self._read_chunk = next(self._read_iterator)
                except StopIteration as error:
                    raise CarrierAccessError("video carrier ended before its declared units") from error
                self._read_chunk_offset = 0
            if self._read_position < start_unit:
                skipped = min(
                    start_unit - self._read_position,
                    self._read_chunk.size - self._read_chunk_offset,
                )
                self._read_position += skipped
                self._read_chunk_offset += skipped
                continue
            available = self._read_chunk.size - self._read_chunk_offset
            taken = min(count - written, available)
            result[written:written + taken] = self._read_chunk[
                self._read_chunk_offset:self._read_chunk_offset + taken
            ]
            written += taken
            self._read_position += taken
            self._read_chunk_offset += taken
        return result

    def close(self) -> None:
        """Close the persistent decoder used by range reads."""
        if self._closed:
            return
        if self._read_iterator is not None:
            close = getattr(self._read_iterator, "close", None)
            if close is not None:
                close()
        self._read_iterator = None
        self._closed = True


def verify_video(
    input_path: str | bytes | PathLike[str],
    sender_public_key: rsa.RSAPublicKey,
    receiver_private_key: rsa.RSAPrivateKey,
) -> VerificationResult:
    """Verify a protocol-v3 video carrier using the sender and receiver keys."""
    import av

    try:
        source = VideoCarrier(input_path)
    except (OSError, ValueError, CarrierAccessError, av.error.FFmpegError) as error:
        return _failure_result(
            "Cannot Verify", str(error), _context_for_sender_key(sender_public_key)
        )
    try:
        return decode_carrier_source(
            source,
            VIDEO_MEDIA_CODE,
            source.media_context,
            sender_public_key,
            receiver_private_key,
        )
    finally:
        source.close()


def verify_video_to_payload_path(
    input_path: str | bytes | PathLike[str],
    sender_public_key: rsa.RSAPublicKey,
    receiver_private_key: rsa.RSAPrivateKey,
    payload_output_path: str | bytes | PathLike[str],
) -> VerificationResult:
    """Verify a video carrier and publish its payload only after Authentic."""
    import av

    try:
        source = VideoCarrier(input_path)
    except (OSError, ValueError, CarrierAccessError, av.error.FFmpegError) as error:
        return _failure_result(
            "Cannot Verify", str(error), _context_for_sender_key(sender_public_key)
        )
    try:
        return decode_carrier_source_to_payload_path(
            source,
            VIDEO_MEDIA_CODE,
            source.media_context,
            sender_public_key,
            receiver_private_key,
            payload_output_path,
        )
    finally:
        source.close()


def encode_video(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    user_payload: bytes,
    metadata: bytes,
) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode and publish a video carrier after read-back validation."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    destination = _check_video_output_resources(output_path)
    source = VideoCarrier(input_path)
    encoding: CarrierEncoding | None = None
    staged_output: Path | None = None
    try:
        encoding = prepare_carrier_encoding(
            source,
            source.media_code,
            source.media_context,
            signing_private_key,
            receiver_public_key,
            start_unit,
            lsb_count,
            user_payload,
            metadata,
        )
        staged_output = _new_video_stage(destination)
        _rewrite_checked(source, encoding, staged_output)
        try:
            os.replace(staged_output, destination)
        except BaseException:
            _remove_incomplete_output(staged_output)
            raise
        return encoding.layout, encoding.payload
    finally:
        if encoding is not None:
            encoding.close()
        source.close()
        if staged_output is not None and staged_output.exists():
            _remove_incomplete_output(staged_output)


def encode_video_from_payload_path(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
) -> tuple[EmbeddingLayout, PayloadFileRecord]:
    """Stream a payload file into a staged video carrier and publish it atomically."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    payload_size = Path(os.fsdecode(fspath(payload_path))).stat().st_size
    destination = _check_video_output_resources(output_path, payload_size)
    source = VideoCarrier(input_path)
    try:
        return _encode_file_from_payload_path(
            source,
            destination,
            signing_private_key,
            receiver_public_key,
            start_unit,
            lsb_count,
            payload_path,
            metadata,
        )
    finally:
        source.close()
