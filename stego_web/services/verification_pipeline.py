"""Shared verification controller for the existing STG1 PNG/WAV format."""

from __future__ import annotations

import hmac

from cryptography.exceptions import UnsupportedAlgorithm

from stego_web.exceptions import CapacityError, InvalidMediaError, WrongStartLocationError
from stego_web.models import Verdict
from .cover_media import CoverMediaHandler
from .crypto_service import CryptoManager
from .steganography import FRAME_HEADER


class VerificationPipeline:
    """Extract, authenticate, and compare received media without changing encoding.

    The signed hash is of the original file, not the stego file. Once that hash
    matches, embed the *extracted* packet (never re-sign randomized RSA-PSS) into
    the original and compare decoded media representations. This detects changes
    outside the payload while preserving the current on-media format.
    """

    def __init__(self, cover_handler: CoverMediaHandler, crypto: CryptoManager):
        self._covers = cover_handler
        self._crypto = crypto

    def verify(self, stego: bytes, public_key: bytes, secret: str,
               lsb_bits: int | None = None, original_cover: bytes | None = None,
               media_type: str = "auto") -> dict:
        """Return a JSON-ready verdict, individual checks, and technical details.

        Args:
            stego: Received PNG or PCM WAV bytes in the existing encoder format.
            public_key: Trusted RSA public PEM, never a private key.
            secret: Exact passphrase used for HmacStartLocation by the encoder.
            lsb_bits: 1..8, or None to try all counts and accept one STG1 frame.
            original_cover: Exact original file; needed to authenticate its hash
                and reproduce expected received media. None permits signature only.
            media_type: Optional image/audio assertion; auto detects from bytes.

        No recognizable magic cannot reliably distinguish absence from a wrong
        secret. It returns Payload Missing with this ambiguity stated explicitly.
        """
        report = {
            "file_size": len(stego), "media_type": None,
            "payload": None, "payload_extracted": False,
            "signature_valid": None, "media_hash_valid": None,
            "received_media_valid": None, "integrity_valid": None,
            "lsb_bits": lsb_bits, "start_location": None,
            "capacity_bytes": None, "payload_size": None, "signature_size": None,
            "stored_hash": None, "computed_hash": None,
            "expected_media_hash": None, "received_media_hash": None,
            "frame_version": None,
        }

        def finish(verdict: Verdict, message: str) -> dict:
            return {**report, "ok": verdict == Verdict.AUTHENTIC,
                    "verdict": verdict.value, "message": message}

        try:
            if media_type not in ("auto", "image", "audio"):
                raise ValueError("Choose auto, image, or audio")
            if lsb_bits is not None and (type(lsb_bits) is not int or not 1 <= lsb_bits <= 8):
                raise ValueError("LSB count must be 1-8 or auto")
            if not isinstance(secret, str) or len(secret) < 8:
                raise ValueError("Start secret must contain at least 8 characters")
            cover = self._covers.validate(stego)
            report["media_type"] = cover.media_type
            report["carrier_units"] = cover.carrier_units
            report["location_unit"] = "RGB channel byte" if cover.media_type == "image" else "PCM byte"
            if media_type not in ("auto", cover.media_type):
                raise ValueError("Selected media type does not match the uploaded file")
        except (InvalidMediaError, ValueError, TypeError) as error:
            return finish(Verdict.CANNOT_VERIFY, str(error))

        candidates = []
        malformed = None
        counts = range(1, 9) if lsb_bits is None else (lsb_bits,)
        for bits in counts:
            try:
                extracted = cover.engine.extract(stego, bits, secret)
                candidates.append((bits, extracted))
            except WrongStartLocationError:
                continue
            except (InvalidMediaError, ValueError, TypeError) as error:
                malformed = str(error)
        if not candidates:
            if malformed:
                return finish(Verdict.CANNOT_VERIFY, malformed)
            return finish(Verdict.PAYLOAD_MISSING,
                          "No recognizable STG1 payload found. The file may contain no payload, "
                          "or the secret/LSB count may be wrong, or its header may be damaged.")
        if len(candidates) != 1:
            return finish(Verdict.CANNOT_VERIFY, "Multiple frame candidates; select the known LSB count.")

        bits, extracted = candidates[0]
        report.update(payload_extracted=True, lsb_bits=bits,
                      start_location=extracted.start_location, frame_version="STG1",
                      capacity_bytes=cover.carrier_units * bits // 8,
                      packet_size=len(extracted.packet), frame_header_size=FRAME_HEADER.size)
        try:
            result = self._crypto.verify_signed_packet(extracted.packet, public_key, original_cover)
        except (ValueError, TypeError, RecursionError, OverflowError, UnsupportedAlgorithm):
            return finish(Verdict.CANNOT_VERIFY, "The embedded payload or public key could not be parsed.")
        report.update(result.as_dict())
        if result.verdict != Verdict.AUTHENTIC:
            if result.media_hash_valid is False:
                report["integrity_valid"] = False
            return finish(result.verdict, result.message)
        if result.payload["media_type"] != cover.media_type:
            return finish(Verdict.CANNOT_VERIFY, "Signed media type does not match the carrier.")

        try:
            original = self._covers.validate(original_cover)
            expected = original.engine.embed(original.data, extracted.packet, bits, secret)
            expected_hash = self._crypto.hash_cover(original.engine.verification_bytes(expected.media_bytes))
            received_hash = self._crypto.hash_cover(cover.engine.verification_bytes(stego))
            matches = hmac.compare_digest(expected_hash, received_hash)
            report.update(expected_media_hash=expected_hash, received_media_hash=received_hash,
                          received_media_valid=matches, integrity_valid=matches)
        except (InvalidMediaError, CapacityError, TypeError, ValueError):
            return finish(Verdict.CANNOT_VERIFY, "Cannot reconstruct expected media from the original cover.")
        if not matches:
            return finish(Verdict.TAMPERED,
                          "Signature and original-cover hash match, but the received pixels/PCM data "
                          "differ from the expected embedded media.")
        return finish(Verdict.AUTHENTIC,
                      "Signature and original-cover hash match; the received pixels/PCM data "
                      "match the expected embedded media.")
