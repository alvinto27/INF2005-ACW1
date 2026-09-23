"""Cover-media ingestion and validation for the encoding pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from payload_protocol import detect_media_type

from .steganography import SteganographyEngine, SteganographyRegistry


@dataclass(frozen=True)
class ValidatedCover:
    """Validated bytes and stable properties needed by later pipeline steps."""

    data: bytes
    media_type: str
    carrier_units: int
    engine: SteganographyEngine


class CoverMediaHandler:
    """Ingest bytes, detect PNG/WAV, and perform complete format validation."""

    def __init__(self, registry: SteganographyRegistry) -> None:
        self._registry = registry

    def validate(self, cover_bytes: bytes) -> ValidatedCover:
        """Validate an uploaded cover before any hash or signature work.

        Args:
            cover_bytes: Complete uploaded PNG or uncompressed PCM/WAV bytes.

        Returns:
            A ``ValidatedCover`` containing media type, carrier-unit count, and
            the matching embedding engine.

        Raises:
            TypeError: If the input is not bytes.
            ValueError: If its media type is unsupported.
            InvalidMediaError: If decoding or PCM validation fails.
        """
        media_type = detect_media_type(cover_bytes)
        engine = self._registry.for_media(media_type)
        carrier_units = engine.validate(cover_bytes)
        return ValidatedCover(cover_bytes, media_type, carrier_units, engine)
