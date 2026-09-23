"""Payload construction separated from hashing and key operations."""

from __future__ import annotations

from payload_protocol import create_payload_from_hash, decode_payload


class PayloadBuilder:
    """Build the compact FR3 payload from validated pipeline values."""

    def build(
        self,
        media_type: str,
        media_hash: str,
        team_id: str,
        sender: str,
        custom_metadata: dict[str, object] | None = None,
    ) -> tuple[bytes, dict]:
        """Return canonical payload bytes and their decoded JSON object.

        ``media_hash`` must have been computed over the original validated
        cover bytes. The returned bytes are the exact bytes that must be signed.
        """
        payload_bytes = create_payload_from_hash(
            media_type,
            media_hash,
            team_id,
            sender,
            custom_metadata,
        )
        return payload_bytes, decode_payload(payload_bytes)
