"""Read a bounded, canonical video-plus-audio carrier with PyAV."""

import os
import shutil
import struct
import tempfile
from collections.abc import Callable, Iterator
from fractions import Fraction
from os import PathLike, fspath
from pathlib import Path

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

_MAX_WIDTH = 1920
_MAX_HEIGHT = 1080
_MAX_DURATION_MS = 15_000
_AUDIO_END_SLACK_MS = 1_000
_MAX_VIDEO_FRAMES = 450
_MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
_MIN_FREE_BYTES = 3 * 1024 * 1024 * 1024
_AUDIO_CHANNEL_COUNTS = frozenset((1, 2))
_VIDEO_CONTEXT_FORMAT = ">IIQIHQ"


def _check_video_output_resources(path: str | bytes | PathLike[str]) -> Path:
    """Check destination free space and return its normalized path."""
    destination = Path(os.fsdecode(fspath(path)))
    parent = destination.parent
    if shutil.disk_usage(parent).free < _MIN_FREE_BYTES:
        raise ValueError("insufficient free disk space for video output")
    return destination


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
    PyAV is imported only when a carrier is opened, so importing ``stego`` does
    not require PyAV.
    """

    def __init__(
        self,
        path: str | bytes | PathLike[str],
        chunk_units: int = DEFAULT_CHUNK_BYTES,
    ) -> None:
        """Validate and count a video file using bounded decode passes."""
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
        chunk_units = _validate_positive_integer(chunk_units, "chunk_units")
        self._path = path
        self._chunk_units = chunk_units
        self._read_iterator: Iterator[np.ndarray] | None = None
        self._read_position = 0
        self._read_chunk: np.ndarray | None = None
        self._read_chunk_offset = 0
        self._closed = False
        self._current_video_origin: Fraction | None = None
        self._scan()

    @property
    def path(self) -> str | bytes | PathLike[str]:
        """Return the file path used to open this carrier."""
        return self._path

    @property
    def total_units(self) -> int:
        """Return RGB channel values followed by interleaved audio samples."""
        return self._total_units

    @property
    def fixed_byte_count(self) -> int:
        """Return canonical frame/audio timing and PCM high-byte count."""
        return self._fixed_byte_count

    @property
    def media_code(self) -> int:
        """Return the protocol video media code."""
        return VIDEO_MEDIA_CODE

    @property
    def media_context(self) -> bytes:
        """Return the fixed 30-byte video/audio context."""
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
        """Open an input container with a local PyAV import."""
        import av

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
            if width > _MAX_WIDTH or height > _MAX_HEIGHT:
                raise ValueError("video dimensions exceed configured limits")

        first_video_time: Fraction | None = None
        frame_count = 0
        latest_tick = 0
        with self._open() as container:
            video_stream, _ = self._select_streams(container)
            decoder = container.decode(video=0)
            for frame, tick, exact_time in _frame_ticks(decoder, video_stream):
                if frame.width != width or frame.height != height:
                    raise ValueError("video dimensions changed during decode")
                if any(
                    component.is_alpha or component.bits > 8
                    for component in frame.format.components
                ):
                    raise ValueError("unsupported video pixel format")
                if first_video_time is None:
                    first_video_time = exact_time
                frame_count += 1
                if frame_count > _MAX_VIDEO_FRAMES:
                    raise ValueError("video exceeds configured frame limit")
                latest_tick = tick
                if latest_tick > _MAX_DURATION_MS:
                    raise ValueError("video exceeds configured duration limit")
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
                    audio_end_tick = audio_start_tick + _round_fraction(
                        Fraction(audio_frames * 1000, audio_rate)
                    )
                    selected_start = min(0, audio_start_tick)
                    selected_end = max(latest_tick, audio_end_tick)
                    if selected_end - selected_start > _MAX_DURATION_MS + _AUDIO_END_SLACK_MS:
                        raise ValueError("selected media span exceeds configured duration limit")
            if audio_frames == 0 or audio_first_time is None:
                raise ValueError("audio stream contains no decoded samples")

        if latest_tick > _MAX_DURATION_MS:
            raise ValueError("video exceeds configured duration limit")
        self._width = width
        self._height = height
        self._frame_count = frame_count
        self._first_video_time = first_video_time
        self._audio_rate = audio_rate
        self._audio_channels = audio_channels
        self._audio_frames_per_channel = audio_frames
        self._audio_start_tick = audio_start_tick
        self._video_units = frame_count * width * height * 3
        audio_units = audio_frames * audio_channels
        self._total_units = self._video_units + audio_units
        self._fixed_byte_count = 8 * frame_count + (
            8 + audio_units if audio_units else 0
        )
        self._media_context = struct.pack(
            _VIDEO_CONTEXT_FORMAT,
            width,
            height,
            frame_count,
            audio_rate,
            audio_channels,
            audio_frames,
        )

    def _iter_video(
        self, with_fixed_bytes: bool
    ) -> Iterator[tuple[np.ndarray, bytes]]:
        """Yield frame RGB values as bounded chunks and one timestamp per frame."""
        frame_count = 0
        first_time = self._first_video_time
        self._current_video_origin = None
        with self._open() as container:
            stream, audio_stream = self._select_streams(container)
            if (audio_stream is None) != (self._audio_channels == 0):
                raise CarrierAccessError("audio stream presence changed after validation")
            for frame, tick, exact_time in _frame_ticks(
                container.decode(video=0), stream, first_time
            ):
                if self._current_video_origin is None:
                    self._current_video_origin = exact_time
                if frame.width != self._width or frame.height != self._height:
                    raise CarrierAccessError("video dimensions changed after validation")
                if any(
                    component.is_alpha or component.bits > 8
                    for component in frame.format.components
                ):
                    raise CarrierAccessError("unsupported video pixel format")
                rgb = frame.to_ndarray(format="rgb24")
                if rgb.shape != (self._height, self._width, 3):
                    raise CarrierAccessError("decoded video frame is not RGB24")
                flat = rgb.reshape(-1)
                first_chunk = True
                for offset in range(0, flat.size, self._chunk_units):
                    chunk = flat[offset:offset + self._chunk_units].copy()
                    fixed = _pack_tick(tick) if with_fixed_bytes and first_chunk else b""
                    yield chunk, fixed
                    first_chunk = False
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
        """Write selected RGB/s16 tracks to a tag-free FFV1/PCM Matroska file."""
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
        import av

        output = av.open(fspath(path), mode="w", format="matroska")
        # The stream rate is a nominal codec setting; explicit millisecond PTS
        # and time bases below carry the actual (including VFR) frame timing.
        video_output = output.add_stream("ffv1", rate=25)
        video_output.width = self._width
        video_output.height = self._height
        video_output.pix_fmt = "bgr0"
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
                    if frame.width != self._width or frame.height != self._height:
                        raise CarrierAccessError(
                            "video dimensions changed after validation"
                        )
                    if any(
                        component.is_alpha or component.bits > 8
                        for component in frame.format.components
                    ):
                        raise CarrierAccessError("unsupported video pixel format")
                    rgb = frame.to_ndarray(format="rgb24")
                    flat = rgb.reshape(-1)
                    rewritten = np.empty(flat.size, dtype=np.uint8)
                    first_chunk = True
                    for offset in range(0, flat.size, self._chunk_units):
                        original = flat[offset:offset + self._chunk_units].copy()
                        fixed = _pack_tick(tick) if first_chunk else b""
                        if fixed_bytes_callback is not None:
                            fixed_bytes_callback(video_units, original, fixed)
                        changed = _validate_transformed_units(
                            transform(video_units, original), original.size
                        )
                        rewritten[offset:offset + changed.size] = changed
                        video_units += original.size
                        first_chunk = False
                    encoded_frame = av.VideoFrame.from_ndarray(
                        rewritten.reshape(self._height, self._width, 3),
                        format="rgb24",
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
        for attribute in (
            "_width", "_height", "_frame_count", "_audio_rate",
            "_audio_channels", "_audio_frames_per_channel", "_audio_start_tick",
            "_video_units", "_total_units", "_fixed_byte_count", "_media_context",
        ):
            setattr(output, attribute, getattr(self, attribute))
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
        for units, _ in self.iter_chunks_with_fixed_bytes():
            yield units

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
    destination = _check_video_output_resources(output_path)
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
