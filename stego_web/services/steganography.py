"""Media-independent interface and PNG/WAV LSB engine boundaries."""

from __future__ import annotations

import io
import math
import struct
import wave
from abc import ABC, abstractmethod

import numpy as np
from PIL import Image, UnidentifiedImageError

from stego_web.exceptions import (
    CapacityError,
    InvalidMediaError,
    WrongStartLocationError,
)
from stego_web.models import EmbeddedMedia, ExtractedPacket
from stego_web.services.start_location import StartLocationStrategy


FRAME_MAGIC = b"STG1"
FRAME_HEADER = struct.Struct(">4sBI")
MAX_PACKET_BYTES = 4 * 1024 * 1024


class SteganographyEngine(ABC):
    """Contract implemented once per cover-object format."""

    media_type: str

    def __init__(self, location_strategy: StartLocationStrategy) -> None:
        self.location_strategy = location_strategy
        self.lsb_encoder = LSBEncoder()

    @abstractmethod
    def validate(self, cover: bytes) -> int:
        """Fully validate media and return its number of embedding units."""

    @abstractmethod
    def embed(self, cover: bytes, packet: bytes, lsb_bits: int, secret: str) -> EmbeddedMedia:
        """Return a new media object containing a framed packet."""

    @abstractmethod
    def embed_at(self, cover: bytes, packet: bytes, lsb_bits: int, start: int) -> EmbeddedMedia:
        """Embed a framed packet beginning exactly at ``start``."""

    @abstractmethod
    def extract(self, stego: bytes, lsb_bits: int, secret: str) -> ExtractedPacket:
        """Recover a framed packet from the selected location."""


class LSBEncoder:
    """Media-independent bit packing for unsigned eight-bit carrier units."""

    @staticmethod
    def write(values: np.ndarray, data: bytes, start: int, lsb_bits: int) -> np.ndarray:
        """Return a copy of ``values`` containing ``data`` in its LSBs.

        Args:
            values: Any-shaped ``uint8`` NumPy array of carrier units.
            data: Payload and signature frame to embed.
            start: Exact first carrier-unit index. Embedding wraps at the end.
            lsb_bits: Number of low bits to replace in each unit, from 1 to 8.

        Returns:
            An array with the same shape and dtype as ``values``.
        """
        if values.dtype != np.uint8:
            raise TypeError("carrier values must have dtype uint8")
        if lsb_bits not in range(1, 9):
            raise ValueError("lsb_bits must be between 1 and 8")
        flat = values.reshape(-1).copy()
        if not isinstance(start, int) or not 0 <= start < flat.size:
            raise ValueError("start location is outside the carrier")

        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        group_count = math.ceil(bits.size / lsb_bits)
        if group_count > flat.size:
            capacity = flat.size * lsb_bits // 8
            raise CapacityError(f"Packet is too large; carrier capacity is {capacity} bytes")

        padded = np.pad(bits, (0, group_count * lsb_bits - bits.size))
        weights = 1 << np.arange(lsb_bits - 1, -1, -1, dtype=np.uint16)
        packed = (padded.reshape(-1, lsb_bits) * weights).sum(axis=1).astype(np.uint8)
        indexes = (start + np.arange(group_count)) % flat.size
        clear_mask = np.uint8(0xFF ^ ((1 << lsb_bits) - 1))
        flat[indexes] = (flat[indexes] & clear_mask) | packed
        return flat.reshape(values.shape)

    @staticmethod
    def read(values: np.ndarray, byte_count: int, start: int, lsb_bits: int) -> bytes:
        """Extract exactly ``byte_count`` bytes from carrier LSBs.

        ``start`` and ``lsb_bits`` must match the values used for embedding.
        The method raises ``InvalidMediaError`` if the request exceeds capacity.
        """
        if values.dtype != np.uint8:
            raise TypeError("carrier values must have dtype uint8")
        if lsb_bits not in range(1, 9):
            raise ValueError("lsb_bits must be between 1 and 8")
        flat = values.reshape(-1)
        if not isinstance(start, int) or not 0 <= start < flat.size:
            raise ValueError("start location is outside the carrier")
        if not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("byte_count must be a non-negative integer")

        bit_count = byte_count * 8
        group_count = math.ceil(bit_count / lsb_bits)
        if group_count > flat.size:
            raise InvalidMediaError("Requested data exceeds the carrier capacity")
        indexes = (start + np.arange(group_count)) % flat.size
        packed = flat[indexes] & np.uint8((1 << lsb_bits) - 1)
        shifts = np.arange(lsb_bits - 1, -1, -1, dtype=np.uint8)
        bits = ((packed[:, None] >> shifts) & 1).astype(np.uint8).reshape(-1)
        return np.packbits(bits[:bit_count]).tobytes()


class ImageLsbSteganography(SteganographyEngine):
    """In-memory PNG RGB implementation supporting one through eight LSBs."""

    media_type = "image"

    def validate(self, cover: bytes) -> int:
        return int(self._load_png(cover).size)

    def embed(self, cover: bytes, packet: bytes, lsb_bits: int, secret: str) -> EmbeddedMedia:
        array = self._load_png(cover)
        start = self.location_strategy.derive(secret, self.media_type, array.size, lsb_bits)
        return self._embed_array(array, packet, lsb_bits, start)

    def embed_at(self, cover: bytes, packet: bytes, lsb_bits: int, start: int) -> EmbeddedMedia:
        return self._embed_array(self._load_png(cover), packet, lsb_bits, start)

    def _embed_array(self, array: np.ndarray, packet: bytes, lsb_bits: int, start: int) -> EmbeddedMedia:
        frame = FRAME_HEADER.pack(FRAME_MAGIC, lsb_bits, len(packet)) + packet
        result = self.lsb_encoder.write(array, frame, start, lsb_bits)

        output = io.BytesIO()
        Image.fromarray(result, mode="RGB").save(output, format="PNG")
        return EmbeddedMedia(output.getvalue(), start, array.size * lsb_bits // 8)

    def extract(self, stego: bytes, lsb_bits: int, secret: str) -> ExtractedPacket:
        array = self._load_png(stego)
        start = self.location_strategy.derive(secret, self.media_type, array.size, lsb_bits)
        header = self.lsb_encoder.read(array, FRAME_HEADER.size, start, lsb_bits)
        magic, embedded_lsb_bits, packet_length = FRAME_HEADER.unpack(header)

        if magic != FRAME_MAGIC or embedded_lsb_bits != lsb_bits:
            raise WrongStartLocationError(
                "No valid frame was found; check the start secret and LSB selection."
            )
        if packet_length < 1 or packet_length > MAX_PACKET_BYTES:
            raise InvalidMediaError("The embedded packet length is invalid")

        total_length = FRAME_HEADER.size + packet_length
        if math.ceil(total_length * 8 / lsb_bits) > array.size:
            raise InvalidMediaError("The embedded packet exceeds the carrier capacity")

        frame = self.lsb_encoder.read(array, total_length, start, lsb_bits)
        return ExtractedPacket(frame[FRAME_HEADER.size:], start)

    @staticmethod
    def _load_png(raw: bytes) -> np.ndarray:
        try:
            with Image.open(io.BytesIO(raw)) as image:
                if image.format != "PNG":
                    raise InvalidMediaError("Image engine accepts PNG files only")
                image.load()
                return np.array(image.convert("RGB"), dtype=np.uint8, copy=True)
        except InvalidMediaError:
            raise
        except (OSError, UnidentifiedImageError, ValueError) as error:
            raise InvalidMediaError("Unreadable or corrupted PNG image") from error

class AudioLsbSteganography(SteganographyEngine):
    """PCM/WAV implementation that modifies sample bytes only."""

    media_type = "audio"

    def validate(self, cover: bytes) -> int:
        return len(self._load_pcm(cover)[1])

    def embed(self, cover: bytes, packet: bytes, lsb_bits: int, secret: str) -> EmbeddedMedia:
        params, frames = self._load_pcm(cover)
        start = self.location_strategy.derive(secret, self.media_type, len(frames), lsb_bits)
        return self._embed_frames(params, frames, packet, lsb_bits, start)

    def embed_at(self, cover: bytes, packet: bytes, lsb_bits: int, start: int) -> EmbeddedMedia:
        params, frames = self._load_pcm(cover)
        return self._embed_frames(params, frames, packet, lsb_bits, start)

    def _embed_frames(
        self,
        params: wave._wave_params,
        frames: bytes,
        packet: bytes,
        lsb_bits: int,
        start: int,
    ) -> EmbeddedMedia:
        frame = FRAME_HEADER.pack(FRAME_MAGIC, lsb_bits, len(packet)) + packet
        values = np.frombuffer(frames, dtype=np.uint8)
        encoded = self.lsb_encoder.write(values, frame, start, lsb_bits)
        output = io.BytesIO()
        with wave.open(output, "wb") as wav:
            wav.setparams(params)
            wav.writeframes(encoded.tobytes())
        return EmbeddedMedia(output.getvalue(), start, len(frames) * lsb_bits // 8)

    def extract(self, stego: bytes, lsb_bits: int, secret: str) -> ExtractedPacket:
        _, frames = self._load_pcm(stego)
        values = np.frombuffer(frames, dtype=np.uint8)
        start = self.location_strategy.derive(secret, self.media_type, len(frames), lsb_bits)
        header = self.lsb_encoder.read(values, FRAME_HEADER.size, start, lsb_bits)
        magic, embedded_lsb_bits, packet_length = FRAME_HEADER.unpack(header)
        if magic != FRAME_MAGIC or embedded_lsb_bits != lsb_bits:
            raise WrongStartLocationError(
                "No valid frame was found; check the start secret and LSB selection."
            )
        if packet_length < 1 or packet_length > MAX_PACKET_BYTES:
            raise InvalidMediaError("The embedded packet length is invalid")
        total_length = FRAME_HEADER.size + packet_length
        if math.ceil(total_length * 8 / lsb_bits) > values.size:
            raise InvalidMediaError("The embedded packet exceeds the carrier capacity")
        frame = self.lsb_encoder.read(values, total_length, start, lsb_bits)
        return ExtractedPacket(frame[FRAME_HEADER.size:], start)

    @staticmethod
    def _load_pcm(raw: bytes) -> tuple[wave._wave_params, bytes]:
        try:
            with wave.open(io.BytesIO(raw), "rb") as wav:
                if wav.getcomptype() != "NONE" or wav.getsampwidth() < 1:
                    raise InvalidMediaError("Audio engine accepts uncompressed PCM WAV files only")
                return wav.getparams(), wav.readframes(wav.getnframes())
        except InvalidMediaError:
            raise
        except (OSError, EOFError, wave.Error) as error:
            raise InvalidMediaError("Unreadable or corrupted WAV audio") from error


class SteganographyRegistry:
    """Resolve engines without coupling HTTP routes to concrete formats."""

    def __init__(self, engines: list[SteganographyEngine]) -> None:
        self._engines = {engine.media_type: engine for engine in engines}

    def for_media(self, media_type: str) -> SteganographyEngine:
        try:
            return self._engines[media_type]
        except KeyError as error:
            raise InvalidMediaError(f"Unsupported media type: {media_type}") from error
