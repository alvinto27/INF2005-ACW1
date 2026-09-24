"""Adapt the current masked-media protocol to byte-oriented Flask requests."""

import base64
import mimetypes
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from stego import (
    EmbeddingLayout,
    GCM_TAG_SIZE,
    PayloadRecord,
    VerificationResult,
    bootstrap_span,
    encode_png,
    encode_wav,
    generate_rsa_keypair,
    load_pcm_wav_from_path,
    load_png_from_path,
    max_user_payload_length,
    preserved_bit_count,
    verify_png,
    verify_wav,
)
from stego.constants import MEDIA_ID_SIZE
from stego.crypto import validate_rsa_private_key, validate_rsa_public_key
from stego.layout import build_embedding_layout
from stego.packet import serialized_record_length


_METADATA_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
_MIME_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*\Z")
_RESERVED_METADATA_KEYS = frozenset({"flow", "team", "sender", "mime", "name"})
_PREVIEW_MIME_TYPES = frozenset(
    {"text/plain", "image/png", "image/jpeg", "audio/wav", "audio/mpeg"}
)


@dataclass(frozen=True)
class WebEncodingResult:
    """Keep the current protocol outputs needed by the browser."""

    media_type: str
    media_bytes: bytes
    layout: EmbeddingLayout
    payload: PayloadRecord
    sender_public_key_pem: bytes
    payload_capacity: int
    preserved_bits: int
    preserved_ratio: float


@dataclass(frozen=True)
class GeneratedKeyPair:
    """Hold an encrypted private PEM and its matching public PEM."""

    private_key_pem: bytes
    public_key_pem: bytes


@dataclass(frozen=True)
class WebLayoutEstimate:
    """Describe one exact, pre-encode carrier layout for the web map."""

    media_type: str
    total_units: int
    width: int | None
    height: int | None
    layout: EmbeddingLayout
    payload_bytes: int
    payload_capacity: int
    preserved_bits: int
    preserved_ratio: float


class CurrentProtocolService:
    """Bridge uploaded bytes to the reduced version-2 file API."""

    def generate_key_pair(self, password: str) -> GeneratedKeyPair:
        """Generate one RSA-2048 pair with a password-protected private key."""
        password_bytes = self._password_bytes(password)
        private_key, public_key = generate_rsa_keypair()
        return GeneratedKeyPair(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password_bytes),
            ),
            self._public_key_pem(public_key),
        )

    def encode(
        self,
        cover_bytes: bytes,
        sender_private_key_pem: bytes,
        sender_key_password: str,
        receiver_public_key_pem: bytes,
        start_unit: int,
        lsb_count: int,
        user_payload: bytes,
        payload_mime: str,
        payload_name: str,
        team_id: str,
        sender: str,
        extra_metadata: str,
    ) -> WebEncodingResult:
        """Validate, encrypt, sign, and embed one web request."""
        media_type, suffix = self._detect_carrier(cover_bytes)
        if not isinstance(user_payload, bytes):
            raise TypeError("user payload must be bytes")
        metadata = self._build_metadata(
            team_id,
            sender,
            payload_mime,
            payload_name,
            extra_metadata,
        )
        with tempfile.TemporaryDirectory(prefix="inf2005-web-") as temporary:
            input_path = Path(temporary) / f"cover.{suffix}"
            output_path = Path(temporary) / f"stego.{suffix}"
            input_path.write_bytes(cover_bytes)
            validator = load_png_from_path if media_type == "image" else load_pcm_wav_from_path
            validator(input_path)
            sender_private_key = self._load_private_key(
                sender_private_key_pem, sender_key_password, "sender private key"
            )
            receiver_public_key = self._load_public_key(
                receiver_public_key_pem, "receiver public key"
            )
            encoder = encode_png if media_type == "image" else encode_wav
            layout, payload = encoder(
                input_path,
                output_path,
                sender_private_key,
                receiver_public_key,
                start_unit,
                lsb_count,
                user_payload,
                metadata,
            )
            media_bytes = output_path.read_bytes()

        record_overhead = serialized_record_length(
            len(payload.media_id.encode("utf-8")), 0, len(metadata)
        )
        capacity = max_user_payload_length(
            layout.total_units,
            layout.start_unit,
            layout.bootstrap_span,
            layout.lsb_count,
            record_overhead,
        )
        kept_bits = preserved_bit_count(
            layout.total_units,
            layout.footprint,
            layout.lsb_count,
            layout.bootstrap_span,
        )
        total_bits = layout.total_units * 8
        return WebEncodingResult(
            media_type,
            media_bytes,
            layout,
            payload,
            self._public_key_pem(sender_private_key.public_key()),
            capacity,
            kept_bits,
            kept_bits / total_bits if total_bits else 0.0,
        )

    def estimate_layout(
        self,
        cover_bytes: bytes,
        receiver_public_key_pem: bytes,
        start_unit: int,
        lsb_count: int,
        user_payload: bytes,
        payload_mime: str,
        payload_name: str,
        team_id: str,
        sender: str,
        extra_metadata: str,
    ) -> WebLayoutEstimate:
        """Calculate the exact packet footprint without encrypting or altering media."""
        media_type, suffix = self._detect_carrier(cover_bytes)
        if not isinstance(user_payload, bytes):
            raise TypeError("user payload must be bytes")
        metadata = self._build_metadata(
            team_id,
            sender,
            payload_mime,
            payload_name,
            extra_metadata,
        )
        receiver_public_key = self._load_public_key(
            receiver_public_key_pem, "receiver public key"
        )
        with tempfile.TemporaryDirectory(prefix="inf2005-web-layout-") as temporary:
            input_path = Path(temporary) / f"cover.{suffix}"
            input_path.write_bytes(cover_bytes)
            if media_type == "image":
                carrier = load_png_from_path(input_path)
                height = int(carrier.shape[0])
                width = int(carrier.shape[1])
                total_units = int(carrier.size)
            else:
                wav_data = load_pcm_wav_from_path(input_path)
                height = None
                width = None
                total_units = len(wav_data.frame_bytes) // wav_data.sample_width

        span = bootstrap_span(receiver_public_key)
        record_length = serialized_record_length(
            MEDIA_ID_SIZE,
            len(user_payload),
            len(metadata),
        )
        ciphertext_length = record_length + GCM_TAG_SIZE
        layout = build_embedding_layout(
            total_units,
            start_unit,
            lsb_count,
            ciphertext_length,
            span,
        )
        record_overhead = serialized_record_length(MEDIA_ID_SIZE, 0, len(metadata))
        capacity = max_user_payload_length(
            total_units,
            start_unit,
            span,
            lsb_count,
            record_overhead,
        )
        kept_bits = preserved_bit_count(
            total_units,
            layout.footprint,
            lsb_count,
            span,
        )
        total_bits = total_units * 8
        return WebLayoutEstimate(
            media_type,
            total_units,
            width,
            height,
            layout,
            len(user_payload),
            capacity,
            kept_bits,
            kept_bits / total_bits if total_bits else 0.0,
        )

    def verify(
        self,
        stego_bytes: bytes,
        sender_public_key_pem: bytes,
        receiver_private_key_pem: bytes,
        receiver_key_password: str,
    ) -> dict[str, object]:
        """Verify a current-protocol carrier and return a JSON-ready report."""
        try:
            media_type, suffix = self._detect_carrier(stego_bytes)
            sender_public_key = self._load_public_key(
                sender_public_key_pem, "sender public key"
            )
            receiver_private_key = self._load_private_key(
                receiver_private_key_pem,
                receiver_key_password,
                "receiver private key",
            )
        except (TypeError, ValueError) as error:
            return self._failed_report(len(stego_bytes), str(error))

        with tempfile.TemporaryDirectory(prefix="inf2005-web-") as temporary:
            input_path = Path(temporary) / f"received.{suffix}"
            input_path.write_bytes(stego_bytes)
            verifier = verify_png if media_type == "image" else verify_wav
            result = verifier(input_path, sender_public_key, receiver_private_key)
        return self._verification_report(result, media_type, len(stego_bytes))

    @staticmethod
    def payload_record(payload: PayloadRecord) -> dict[str, object]:
        """Serialize safe payload-record fields for the encoding response."""
        return {
            "media_id": payload.media_id,
            "timestamp": payload.timestamp,
            "timestamp_utc": datetime.fromtimestamp(
                payload.timestamp, timezone.utc
            ).isoformat(),
            "nonce": payload.nonce.hex(),
            "media_hash": payload.media_hash.hex(),
            "user_payload_size": len(payload.user_payload),
            "metadata": payload.metadata.decode("utf-8"),
        }

    def _verification_report(
        self,
        result: VerificationResult,
        media_type: str,
        file_size: int,
    ) -> dict[str, object]:
        """Convert a library verification result for the browser."""
        signature_valid: bool | None = None
        if result.verdict in {"Authentic", "Tampered", "Cannot Decrypt"}:
            signature_valid = True
        elif result.verdict == "Signature Invalid":
            signature_valid = False
        integrity_valid = True if result.verdict == "Authentic" else (
            False if result.verdict == "Tampered" else None
        )
        report: dict[str, object] = {
            "ok": result.valid,
            "verdict": result.verdict,
            "message": result.detail,
            "file_size": file_size,
            "media_type": media_type,
            "frame_version": 2,
            "payload_extracted": result.payload is not None,
            "signature_valid": signature_valid,
            "integrity_valid": integrity_valid,
            "media_hash_valid": integrity_valid,
            "start_location": result.start_unit,
            "lsb_bits": result.lsb_count,
            "preserved_bits": result.preserved_bits,
            "preserved_ratio": result.preserved_ratio,
            "sender_key_fingerprint": result.key_fingerprint,
            "payload": None,
        }
        if result.payload is not None:
            report["payload"] = self._verified_payload(result.payload)
        return report

    def _verified_payload(self, payload: PayloadRecord) -> dict[str, object]:
        """Return authenticated payload data with guarded preview information."""
        raw_metadata = payload.metadata.decode("utf-8")
        metadata, metadata_valid = self._parse_metadata(raw_metadata)
        declared_mime = metadata.get("mime") if metadata_valid else None
        claimed_name = metadata.get("name") if metadata_valid else None
        sniffed_mime = self._sniff_payload_mime(payload.user_payload)
        type_agrees = self._type_agrees(declared_mime, sniffed_mime, payload.user_payload)
        safe_name = self._safe_filename(claimed_name or "recovered-payload.bin")
        preview_allowed = bool(
            type_agrees and declared_mime in _PREVIEW_MIME_TYPES
        )
        return {
            **self.payload_record(payload),
            "metadata": metadata if metadata_valid else {},
            "metadata_raw": raw_metadata,
            "metadata_valid": metadata_valid,
            "user_payload_base64": base64.b64encode(payload.user_payload).decode("ascii"),
            "declared_mime": declared_mime,
            "sniffed_mime": sniffed_mime,
            "type_agrees": type_agrees,
            "preview_allowed": preview_allowed,
            "download_name": safe_name,
        }

    @staticmethod
    def _failed_report(file_size: int, message: str) -> dict[str, object]:
        """Build a stable Cannot Verify response for boundary failures."""
        return {
            "ok": False,
            "verdict": "Cannot Verify",
            "message": message,
            "file_size": file_size,
            "media_type": None,
            "frame_version": 2,
            "payload_extracted": False,
            "signature_valid": None,
            "integrity_valid": None,
            "media_hash_valid": None,
            "start_location": None,
            "lsb_bits": None,
            "preserved_bits": None,
            "preserved_ratio": None,
            "sender_key_fingerprint": None,
            "payload": None,
        }

    @staticmethod
    def _password_bytes(password: str) -> bytes:
        """Validate a web key password and encode it for cryptography."""
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("key password must contain at least 8 characters")
        return password.encode("utf-8")

    def _load_private_key(
        self, pem: bytes, password: str, label: str
    ) -> rsa.RSAPrivateKey:
        """Load one encrypted RSA-2048 private key from uploaded PEM bytes."""
        if not isinstance(pem, bytes):
            raise TypeError(f"{label} must be uploaded as bytes")
        try:
            key = serialization.load_pem_private_key(
                pem, password=self._password_bytes(password)
            )
            return validate_rsa_private_key(key)
        except (TypeError, ValueError, UnsupportedAlgorithm) as error:
            raise ValueError(f"{label} could not be loaded with that password") from error

    @staticmethod
    def _load_public_key(pem: bytes, label: str) -> rsa.RSAPublicKey:
        """Load one RSA-2048 public key from uploaded PEM bytes."""
        if not isinstance(pem, bytes):
            raise TypeError(f"{label} must be uploaded as bytes")
        try:
            return validate_rsa_public_key(serialization.load_pem_public_key(pem))
        except (TypeError, ValueError, UnsupportedAlgorithm) as error:
            raise ValueError(f"{label} is not a valid RSA-2048 public key") from error

    @staticmethod
    def _public_key_pem(public_key: rsa.RSAPublicKey) -> bytes:
        """Serialize an RSA public key for download."""
        return validate_rsa_public_key(public_key).public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def _detect_carrier(data: bytes) -> tuple[str, str]:
        """Detect the two strict carrier families from file signatures."""
        if not isinstance(data, bytes):
            raise TypeError("carrier must be uploaded as bytes")
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image", "png"
        if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            return "audio", "wav"
        raise ValueError("unsupported carrier; upload an RGB PNG or uncompressed PCM WAV")

    def _build_metadata(
        self,
        team_id: str,
        sender: str,
        payload_mime: str,
        payload_name: str,
        extra_metadata: str,
    ) -> bytes:
        """Build the protocol's semicolon-delimited typed metadata."""
        team = self._metadata_value(team_id, "team ID")
        sender_value = self._metadata_value(sender, "sender")
        mime = payload_mime.strip().lower()
        if _MIME_TYPE.fullmatch(mime) is None:
            raise ValueError("payload MIME type must look like type/subtype")
        claimed_name = self._metadata_value(payload_name, "payload name")
        name = self._safe_filename(claimed_name)
        custom, valid = self._parse_metadata(extra_metadata)
        if extra_metadata.strip() and not valid:
            raise ValueError("additional metadata must use key=value entries separated by semicolons")
        conflicts = _RESERVED_METADATA_KEYS.intersection(custom)
        if conflicts:
            raise ValueError(f"additional metadata cannot replace reserved key: {sorted(conflicts)[0]}")
        entries = {
            "flow": "web",
            "team": team,
            "sender": sender_value,
            "mime": mime,
            "name": name,
            **custom,
        }
        return ";".join(f"{key}={value}" for key, value in entries.items()).encode("utf-8")

    @staticmethod
    def _metadata_value(value: str, label: str) -> str:
        """Validate one delimiter-free metadata value."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} is required")
        cleaned = value.strip()
        if ";" in cleaned or "=" in cleaned:
            raise ValueError(f"{label} cannot contain ';' or '='")
        return cleaned

    @staticmethod
    def _parse_metadata(raw: str) -> tuple[dict[str, str], bool]:
        """Parse simple key=value metadata without silently accepting ambiguity."""
        if not isinstance(raw, str):
            return {}, False
        if not raw.strip():
            return {}, True
        result: dict[str, str] = {}
        for entry in raw.split(";"):
            if entry.count("=") != 1:
                return {}, False
            key, value = entry.split("=", 1)
            if _METADATA_KEY.fullmatch(key) is None or not value or key in result:
                return {}, False
            result[key] = value
        return result, True

    @staticmethod
    def _safe_filename(name: str) -> str:
        """Reduce an authenticated filename claim to a safe download basename."""
        if not isinstance(name, str):
            return "recovered-payload.bin"
        basename = name.replace("\\", "/").split("/")[-1].strip()
        basename = re.sub(r"[^A-Za-z0-9._ -]", "_", basename)
        basename = basename.lstrip(". ")[:120]
        return basename or "recovered-payload.bin"

    @staticmethod
    def _sniff_payload_mime(payload: bytes) -> str | None:
        """Recognize payload types whose magic bytes are checked before preview."""
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if payload.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WAVE":
            return "audio/wav"
        if payload.startswith(b"%PDF-"):
            return "application/pdf"
        if payload.startswith(b"ID3") or (
            len(payload) >= 2 and payload[0] == 0xFF and payload[1] & 0xE0 == 0xE0
        ):
            return "audio/mpeg"
        return None

    @staticmethod
    def _type_agrees(
        declared: str | None, sniffed: str | None, payload: bytes
    ) -> bool:
        """Check an authenticated MIME claim before the browser renders bytes."""
        if declared is None:
            return False
        if sniffed is not None:
            return declared == sniffed
        if declared in {"image/png", "image/jpeg", "audio/wav", "audio/mpeg", "application/pdf"}:
            return False
        if declared == "text/plain":
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError:
                return False
        return True


def infer_payload_claim(
    filename: str | None, uploaded_mime: str | None, is_message: bool
) -> tuple[str, str]:
    """Choose initial MIME and filename claims from a web payload input."""
    if is_message:
        return "text/plain", "message.txt"
    safe_input = (filename or "payload.bin").replace("\\", "/").split("/")[-1]
    guessed = mimetypes.guess_type(safe_input)[0]
    mime = guessed or (
        uploaded_mime if uploaded_mime and uploaded_mime != "application/octet-stream" else None
    )
    return mime or "application/octet-stream", safe_input or "payload.bin"
