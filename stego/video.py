"""Whole-file PyAV adapters for distinct video frame and PCM audio carriers.

Only this module knows about containers and codecs. The returned one-dimensional
uint8 arrays can later be supplied by a chunked adapter without changing the
public wrappers or the cryptographic carrier protocol.
"""

import os
import struct
from dataclasses import dataclass
from fractions import Fraction
from os import PathLike, fspath

import av
import numpy as np

from .bits import _validate_carrier_units
from .constants import RGB_CHANNEL_COUNT


@dataclass(frozen=True)
class VideoFramesData:
    """Decoded RGB frames and their presentation times in input order."""

    frames: tuple[np.ndarray, ...]
    width: int
    height: int
    time_base: Fraction
    rate: Fraction
    timestamps: tuple[Fraction | None, ...]


@dataclass(frozen=True)
class VideoAudioData:
    """Decoded interleaved signed 16-bit PCM and its playback parameters."""

    samples: np.ndarray
    sample_rate: int
    channels: int
    layout: str
    start_time: Fraction


def _path(path: str | bytes | PathLike[str]) -> str:
    """Return a filesystem path suitable for PyAV."""
    if not isinstance(path, (str, bytes, PathLike)):
        raise TypeError("path must be a filesystem path")
    return os.fsdecode(fspath(path))


def _mkv_path(path: str | bytes | PathLike[str]) -> str:
    """Require Matroska for the lossless encoded output."""
    path = _path(path)
    if not path.lower().endswith(".mkv"):
        raise ValueError("encoded video output must be an .mkv file")
    return path


def load_video_frames_from_path(path: str | bytes | PathLike[str]) -> VideoFramesData:
    """Decode the first visual stream into RGB24 frames in presentation order."""
    try:
        with av.open(_path(path)) as container:
            if not container.streams.video:
                raise ValueError("video contains no video stream")
            stream = container.streams.video[0]
            rate = stream.average_rate or stream.guessed_rate or Fraction(25, 1)
            time_base = stream.time_base or Fraction(rate.denominator, rate.numerator)
            frames = []
            timestamps = []
            for frame in container.decode(stream):
                try:
                    rgb = frame.to_ndarray(format="rgb24")
                except (ValueError, av.FFmpegError) as error:
                    raise ValueError(f"unsupported video pixel format: {frame.format.name}") from error
                if rgb.dtype != np.uint8 or rgb.ndim != 3 or rgb.shape[2] != RGB_CHANNEL_COUNT:
                    raise ValueError("unsupported video pixel format: expected RGB24")
                if frames and rgb.shape != frames[0].shape:
                    raise ValueError("video frame dimensions change within the stream")
                frames.append(np.ascontiguousarray(rgb))
                timestamps.append(Fraction(frame.pts) * frame.time_base if frame.pts is not None and frame.time_base is not None else None)
            if not frames:
                raise ValueError("video stream contains no decoded frames")
            height, width, _ = frames[0].shape
            return VideoFramesData(tuple(frames), width, height, Fraction(time_base), Fraction(rate), tuple(timestamps))
    except av.FFmpegError as error:
        raise ValueError(f"failed to decode video: {error}") from error


def video_frames_to_carrier(data: VideoFramesData) -> np.ndarray:
    """Flatten decoded RGB channels into a whole-file carrier copy."""
    if not isinstance(data, VideoFramesData):
        raise TypeError("data must be VideoFramesData")
    return np.concatenate([frame.reshape(-1) for frame in data.frames]).astype(np.uint8, copy=False)


def carrier_to_video_frames(carrier: np.ndarray, data: VideoFramesData) -> tuple[np.ndarray, ...]:
    """Split a modified carrier back into RGB frames of the original geometry."""
    carrier = _validate_carrier_units(carrier)
    frame_units = data.width * data.height * RGB_CHANNEL_COUNT
    if carrier.size != frame_units * len(data.frames):
        raise ValueError("carrier count does not match video frame geometry")
    return tuple(carrier[index * frame_units:(index + 1) * frame_units].copy().reshape(data.height, data.width, RGB_CHANNEL_COUNT) for index in range(len(data.frames)))


def encode_video_frame_media_context(data: VideoFramesData, carrier_unit_count: int | None = None) -> bytes:
    """Bind RGB24 geometry and frame count to a video-frame signature."""
    if not isinstance(data, VideoFramesData):
        raise TypeError("data must be VideoFramesData")
    if not 1 <= data.width <= 0xFFFFFFFF or not 1 <= data.height <= 0xFFFFFFFF or not 1 <= len(data.frames) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("video frame dimensions or count exceed media context limits")
    expected = data.width * data.height * RGB_CHANNEL_COUNT * len(data.frames)
    if carrier_unit_count is not None and carrier_unit_count != expected:
        raise ValueError("carrier count does not match video frame geometry")
    return struct.pack(">IIBQ", data.width, data.height, RGB_CHANNEL_COUNT, len(data.frames)) + b"RGB24"


def save_video_frames_to_path(data: VideoFramesData, carrier: np.ndarray, input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str]) -> None:
    """Write embedded RGB frames as FFV1 in MKV and remux original audio."""
    frames = carrier_to_video_frames(carrier, data)
    try:
        with av.open(_path(input_path)) as source, av.open(_mkv_path(output_path), mode="w", format="matroska") as output:
            video = output.add_stream("ffv1", rate=data.rate)
            video.width = data.width
            video.height = data.height
            video.pix_fmt = "bgr0"
            video.codec_context.time_base = data.time_base
            video.time_base = data.time_base
            audio_streams = {stream.index: output.add_stream_from_template(stream) for stream in source.streams.audio}
            for index, rgb in enumerate(frames):
                frame = av.VideoFrame.from_ndarray(rgb, format="rgb24")
                timestamp = data.timestamps[index]
                frame.pts = int(timestamp / data.time_base) if timestamp is not None else index
                frame.time_base = data.time_base
                for packet in video.encode(frame):
                    output.mux(packet)
            for packet in video.encode():
                output.mux(packet)
            if audio_streams:
                for packet in source.demux(*source.streams.audio):
                    if packet.dts is None:
                        continue
                    packet.stream = audio_streams[packet.stream.index]
                    output.mux(packet)
    except av.FFmpegError as error:
        raise ValueError(f"failed lossless video codec/container operation: {error}") from error


def load_video_audio_from_path(path: str | bytes | PathLike[str]) -> VideoAudioData:
    """Decode the first audio track to packed little-endian signed 16-bit PCM."""
    try:
        with av.open(_path(path)) as container:
            if not container.streams.video:
                raise ValueError("video contains no video stream")
            if not container.streams.audio:
                raise ValueError("video contains no audio stream")
            stream = container.streams.audio[0]
            blocks = []
            rate = None
            layout = None
            channels = None
            start_time = Fraction(0)
            resampler = None
            for frame in container.decode(stream):
                if resampler is None:
                    rate = frame.sample_rate
                    layout = frame.layout.name
                    channels = len(frame.layout.channels)
                    if not rate or not layout or not 1 <= channels <= 255:
                        raise ValueError("unsupported audio format or channel layout")
                    start_time = Fraction(frame.pts) * frame.time_base if frame.pts is not None and frame.time_base is not None else Fraction(0)
                    resampler = av.AudioResampler(format="s16", layout=layout, rate=rate)
                elif frame.sample_rate != rate or frame.layout.name != layout:
                    raise ValueError("audio sample rate or layout changes within the stream")
                for converted in resampler.resample(frame):
                    block = converted.to_ndarray()
                    if block.dtype != np.int16 or block.size % channels:
                        raise ValueError("unsupported decoded audio format: expected packed 16-bit PCM")
                    blocks.append(np.ascontiguousarray(block.reshape(-1)))
            if resampler is None:
                raise ValueError("audio stream contains no decoded samples")
            for converted in resampler.resample(None):
                block = converted.to_ndarray()
                if block.dtype != np.int16 or block.size % channels:
                    raise ValueError("unsupported decoded audio format: expected packed 16-bit PCM")
                blocks.append(np.ascontiguousarray(block.reshape(-1)))
            samples = np.concatenate(blocks) if blocks else np.empty(0, dtype=np.int16)
            if not samples.size:
                raise ValueError("audio stream contains no decoded samples")
            return VideoAudioData(samples, rate, channels, layout, start_time)
    except av.FFmpegError as error:
        raise ValueError(f"failed to decode video audio: {error}") from error


def video_audio_to_carrier(data: VideoAudioData) -> np.ndarray:
    """Use one least-significant byte from each interleaved PCM sample."""
    if not isinstance(data, VideoAudioData):
        raise TypeError("data must be VideoAudioData")
    return data.samples.astype("<i2", copy=False).view(np.uint8)[::2].copy()


def carrier_to_video_audio(carrier: np.ndarray, data: VideoAudioData) -> np.ndarray:
    """Replace only the least-significant byte of each PCM sample."""
    carrier = _validate_carrier_units(carrier)
    if carrier.size != data.samples.size:
        raise ValueError("carrier count does not match video audio sample count")
    samples = data.samples.astype("<i2", copy=True)
    samples.view(np.uint8)[::2] = carrier
    return samples


def encode_video_audio_media_context(data: VideoAudioData, carrier_unit_count: int | None = None) -> bytes:
    """Bind PCM rate, channels, sample width, and count to a signature.

    Container channel-layout labels are omitted: equivalent mono PCM can decode
    as either ``mono`` or ``1 channels`` after Matroska remuxing.
    """
    if not isinstance(data, VideoAudioData):
        raise TypeError("data must be VideoAudioData")
    if not 1 <= data.sample_rate <= 0xFFFFFFFF or not 1 <= data.channels <= 0xFFFF:
        raise ValueError("video audio parameters exceed media context limits")
    if data.samples.size % data.channels or data.samples.size // data.channels > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("video audio sample count is invalid")
    if carrier_unit_count is not None and carrier_unit_count != data.samples.size:
        raise ValueError("carrier count does not match video audio sample count")
    return struct.pack(">IHBQ", data.sample_rate, data.channels, 2, data.samples.size // data.channels)


def save_video_audio_to_path(data: VideoAudioData, carrier: np.ndarray, input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str]) -> None:
    """Write embedded samples as PCM s16le in MKV and remux source video."""
    samples = carrier_to_video_audio(carrier, data)
    try:
        with av.open(_path(input_path)) as source, av.open(_mkv_path(output_path), mode="w", format="matroska") as output:
            video_streams = {stream.index: output.add_stream_from_template(stream) for stream in source.streams.video}
            audio = output.add_stream("pcm_s16le", rate=data.sample_rate)
            audio.layout = data.layout
            audio.time_base = Fraction(1, data.sample_rate)
            start_sample = int(data.start_time * data.sample_rate)
            for start in range(0, samples.size, 4096 * data.channels):
                block = samples[start:start + 4096 * data.channels]
                frame = av.AudioFrame.from_ndarray(block.reshape(1, -1), format="s16", layout=data.layout)
                frame.sample_rate = data.sample_rate
                frame.pts = start_sample + start // data.channels
                frame.time_base = Fraction(1, data.sample_rate)
                for packet in audio.encode(frame):
                    output.mux(packet)
            for packet in audio.encode():
                output.mux(packet)
            for packet in source.demux(*source.streams.video):
                if packet.dts is None:
                    continue
                packet.stream = video_streams[packet.stream.index]
                output.mux(packet)
    except av.FFmpegError as error:
        raise ValueError(f"failed lossless audio codec/container operation: {error}") from error
