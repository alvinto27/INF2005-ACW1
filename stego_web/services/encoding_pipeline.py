"""Strict seven-step encoding controller independent of Flask."""

from __future__ import annotations

from dataclasses import dataclass

from stego_web.models import EmbeddedMedia

from .cover_media import CoverMediaHandler
from .crypto_service import CryptoManager
from .payload_builder import PayloadBuilder
from .start_location import StartLocationStrategy


@dataclass(frozen=True)
class EncodingResult:
    """All safe outputs needed by the HTTP response and GUI."""

    media_type: str
    embedded: EmbeddedMedia
    payload: dict
    public_key_pem: bytes
    media_hash: str


class EncodingPipeline:
    """Execute validation, hashing, payload, signing, location, LSB, output."""

    def __init__(
        self,
        cover_handler: CoverMediaHandler,
        crypto_manager: CryptoManager,
        payload_builder: PayloadBuilder,
        location_strategy: StartLocationStrategy,
    ) -> None:
        self._cover_handler = cover_handler
        self._crypto = crypto_manager
        self._payload_builder = payload_builder
        self._location = location_strategy

    def encode(
        self,
        cover_bytes: bytes,
        private_key_pem: bytes,
        key_password: str,
        team_id: str,
        sender: str,
        custom_metadata: dict[str, object] | None,
        start_secret: str,
        lsb_bits: int,
    ) -> EncodingResult:
        """Run the seven mandatory encoding steps in order.

        Args:
            cover_bytes: Complete original PNG or PCM/WAV bytes.
            private_key_pem: Existing encrypted RSA PKCS#8 PEM bytes.
            key_password: Password required to decrypt ``private_key_pem``.
            team_id: Team-defined identifier stored as signed metadata.
            sender: Sender label stored as signed metadata.
            custom_metadata: Optional JSON-compatible signed metadata.
            start_secret: Shared passphrase for deterministic start derivation.
            lsb_bits: Number of LSBs to replace in each carrier unit, 1 through 8.

        Returns:
            ``EncodingResult`` containing stego bytes, payload, hash, and the
            public key corresponding to the supplied private key.
        """
        # Step 1: reject malformed media before any cryptographic work.
        cover = self._cover_handler.validate(cover_bytes)

        # Step 2: hash the stable representation (the exact original bytes).
        media_hash = self._crypto.hash_cover(cover.data)

        # Step 3: construct compact canonical payload bytes.
        payload_bytes, payload = self._payload_builder.build(
            cover.media_type,
            media_hash,
            team_id,
            sender,
            custom_metadata,
        )

        # Step 4: load the existing key and sign the exact payload bytes.
        private_key = self._crypto.load_signing_key(private_key_pem, key_password)
        signed = self._crypto.sign_packet(payload_bytes, payload, private_key)

        # Step 5: derive a non-default location before embedding.
        start = self._location.derive(
            start_secret,
            cover.media_type,
            cover.carrier_units,
            lsb_bits,
        )

        # Step 6: replace LSBs beginning at the derived location.
        embedded = cover.engine.embed_at(cover.data, signed.packet, lsb_bits, start)

        # Step 7: expose the serialized PNG/WAV and associated safe outputs.
        return EncodingResult(
            media_type=cover.media_type,
            embedded=embedded,
            payload=signed.payload,
            public_key_pem=signed.public_key_pem,
            media_hash=media_hash,
        )
