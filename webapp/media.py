"""PNG and PCM/WAV carrier adapters."""

from __future__ import annotations

import io
import wave

import numpy as np
from PIL import Image

from FR1_FR5 import UnSupportedFileType
from payload_protocol import detect_media_type

from .lsb import embed_bytes, extract_bytes


class ImageCarrier:
    """Load, embed, and extract RGB PNG carriers."""

    @staticmethod
    def _array(data: bytes) -> np.ndarray:
        try:
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "PNG":
                    raise UnSupportedFileType("Only PNG images are supported")
                return np.array(image.convert("RGB"), dtype=np.uint8, copy=True)
        except UnSupportedFileType:
            raise
        except (OSError, ValueError) as error:
            raise ValueError("Unreadable or corrupted PNG image") from error

    def carrier_units(self, data: bytes) -> int:
        return int(self._array(data).size)

    def embed(self, data: bytes, packet: bytes, start_unit: int, bits_per_unit: int) -> bytes:
        array = self._array(data)
        flat = array.reshape(-1)
        encoded = embed_bytes(flat, packet, start_unit, bits_per_unit).reshape(array.shape)
        output = io.BytesIO()
        Image.fromarray(encoded, mode="RGB").save(output, format="PNG")
        return output.getvalue()

    def extract(self, data: bytes, start_unit: int, byte_count: int, bits_per_unit: int) -> bytes:
        return extract_bytes(self._array(data).reshape(-1), start_unit, byte_count, bits_per_unit)


class WavCarrier:
    """Embed in PCM sample bytes while retaining the WAV container."""

    @staticmethod
    def _frames(data: bytes) -> tuple[wave._wave_params, bytes]:
        try:
            with wave.open(io.BytesIO(data), "rb") as wav:
                if wav.getcomptype() != "NONE" or wav.getsampwidth() < 1:
                    raise ValueError("Only uncompressed PCM WAV files are supported")
                return wav.getparams(), wav.readframes(wav.getnframes())
        except (OSError, EOFError) as error:
            raise ValueError("Unreadable or corrupted WAV audio") from error

    def carrier_units(self, data: bytes) -> int:
        return len(self._frames(data)[1])

    def embed(self, data: bytes, packet: bytes, start_unit: int, bits_per_unit: int) -> bytes:
        params, frames = self._frames(data)
        values = np.frombuffer(frames, dtype=np.uint8)
        encoded = embed_bytes(values, packet, start_unit, bits_per_unit).tobytes()
        output = io.BytesIO()
        with wave.open(output, "wb") as wav:
            wav.setparams(params)
            wav.writeframes(encoded)
        return output.getvalue()

    def extract(self, data: bytes, start_unit: int, byte_count: int, bits_per_unit: int) -> bytes:
        values = np.frombuffer(self._frames(data)[1], dtype=np.uint8)
        return extract_bytes(values, start_unit, byte_count, bits_per_unit)


def carrier_for(data: bytes) -> ImageCarrier | WavCarrier:
    media_type = detect_media_type(data)
    return ImageCarrier() if media_type == "image" else WavCarrier()
