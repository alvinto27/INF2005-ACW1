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
    FeatureUnavailableError,
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

    @abstractmethod
    def embed(self, cover: bytes, packet: bytes, lsb_bits: int, secret: str) -> EmbeddedMedia:
        """Return a new media object containing a framed packet."""

    @abstractmethod
    def extract(self, stego: bytes, lsb_bits: int, secret: str) -> ExtractedPacket:
        """Recover a framed packet from the selected location."""


class ImageLsbSteganography(SteganographyEngine):
    """In-memory PNG RGB implementation supporting one through eight LSBs."""

    media_type = "image"

    def embed(self, cover: bytes, packet: bytes, lsb_bits: int, secret: str) -> EmbeddedMedia:
        array = self._load_png(cover)
        frame = FRAME_HEADER.pack(FRAME_MAGIC, lsb_bits, len(packet)) + packet
        start = self.location_strategy.derive(secret, self.media_type, array.size, lsb_bits)
        result = self._write_bytes(array, frame, start, lsb_bits)

        output = io.BytesIO()
        Image.fromarray(result, mode="RGB").save(output, format="PNG")
        return EmbeddedMedia(output.getvalue(), start, array.size * lsb_bits // 8)

    def extract(self, stego: bytes, lsb_bits: int, secret: str) -> ExtractedPacket:
        array = self._load_png(stego)
        start = self.location_strategy.derive(secret, self.media_type, array.size, lsb_bits)
        header = self._read_bytes(array, FRAME_HEADER.size, start, lsb_bits)
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

        frame = self._read_bytes(array, total_length, start, lsb_bits)
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

    @staticmethod
    def _write_bytes(
        image: np.ndarray,
        data: bytes,
        start: int,
        lsb_bits: int,
    ) -> np.ndarray:
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        group_count = math.ceil(bits.size / lsb_bits)
        flat = image.reshape(-1).copy()
        if group_count > flat.size:
            capacity = flat.size * lsb_bits // 8
            raise CapacityError(f"Packet is too large; PNG capacity is {capacity} bytes")

        padded = np.pad(bits, (0, group_count * lsb_bits - bits.size))
        weights = 1 << np.arange(lsb_bits - 1, -1, -1, dtype=np.uint16)
        values = (padded.reshape(-1, lsb_bits) * weights).sum(axis=1).astype(np.uint8)
        indexes = (start + np.arange(group_count)) % flat.size
        clear_mask = np.uint8(0xFF ^ ((1 << lsb_bits) - 1))
        flat[indexes] = (flat[indexes] & clear_mask) | values
        return flat.reshape(image.shape)

    @staticmethod
    def _read_bytes(
        image: np.ndarray,
        byte_count: int,
        start: int,
        lsb_bits: int,
    ) -> bytes:
        bit_count = byte_count * 8
        group_count = math.ceil(bit_count / lsb_bits)
        flat = image.reshape(-1)
        if group_count > flat.size:
            raise InvalidMediaError("Requested data exceeds the PNG capacity")

        indexes = (start + np.arange(group_count)) % flat.size
        values = flat[indexes] & np.uint8((1 << lsb_bits) - 1)
        shifts = np.arange(lsb_bits - 1, -1, -1, dtype=np.uint8)
        bits = ((values[:, None] >> shifts) & 1).astype(np.uint8).reshape(-1)
        return np.packbits(bits[:bit_count]).tobytes()


class AudioLsbSteganography(SteganographyEngine):
    """PCM/WAV implementation that modifies sample bytes only."""

    media_type = "audio"

    def embed(self, cover: bytes, packet: bytes, lsb_bits: int, secret: str) -> EmbeddedMedia:
        params, frames = self._load_pcm(cover)
        frame = FRAME_HEADER.pack(FRAME_MAGIC, lsb_bits, len(packet)) + packet
        start = self.location_strategy.derive(secret, self.media_type, len(frames), lsb_bits)
        values = np.frombuffer(frames, dtype=np.uint8)
        encoded = ImageLsbSteganography._write_bytes(values, frame, start, lsb_bits)
        output = io.BytesIO()
        with wave.open(output, "wb") as wav:
            wav.setparams(params)
            wav.writeframes(encoded.tobytes())
        return EmbeddedMedia(output.getvalue(), start, len(frames) * lsb_bits // 8)

    def extract(self, stego: bytes, lsb_bits: int, secret: str) -> ExtractedPacket:
        _, frames = self._load_pcm(stego)
        values = np.frombuffer(frames, dtype=np.uint8)
        start = self.location_strategy.derive(secret, self.media_type, len(frames), lsb_bits)
        header = ImageLsbSteganography._read_bytes(values, FRAME_HEADER.size, start, lsb_bits)
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
        frame = ImageLsbSteganography._read_bytes(values, total_length, start, lsb_bits)
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
