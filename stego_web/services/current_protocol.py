"""Adapt the current masked-media protocol to byte-oriented Flask requests."""

import codecs
import mimetypes
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from stego import (
    EmbeddingLayout,
    PayloadFileRecord,
    PayloadRecord,
    VerificationResult,
    encode_png_from_payload_path,
    encode_wav_from_payload_path,
    generate_rsa_keypair,
    max_user_payload_length,
    preserved_bit_count,
    verify_png_to_payload_path,
    verify_wav_to_payload_path,
)
from stego.crypto import validate_rsa_private_key, validate_rsa_public_key
from stego.sources import detect_source_family, open_audio_source, open_image_source
from stego.packet import serialized_record_length


_METADATA_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
_MIME_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*\Z")
_RESERVED_METADATA_KEYS = frozenset({"flow", "team", "sender", "mime", "name"})
_PREVIEW_MIME_TYPES = frozenset(
    {
        "text/plain",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/bmp",
        "audio/wav",
        "audio/mpeg",
        "audio/ogg",
        "audio/flac",
        "audio/mp4",
        "audio/webm",
        "video/mp4",
        "video/webm",
        "video/ogg",
    }
)
_PAYLOAD_MIME_BY_EXTENSION = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".bmp": "image/bmp",
    ".wav": "audio/wav",
    ".wave": "audio/wav",
    ".mp3": "audio/mpeg",
    ".flac": "audio/flac",
    ".opus": "audio/ogg",
    ".m4a": "audio/mp4",
    ".m4b": "audio/mp4",
    ".aac": "audio/mp4",
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".ogv": "video/ogg",
    ".mkv": "video/x-matroska",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
}
_AMBIGUOUS_PAYLOAD_MIMES = {
    ".ogg": frozenset({"audio/ogg", "video/ogg"}),
    ".oga": frozenset({"audio/ogg"}),
    ".webm": frozenset({"audio/webm", "video/webm"}),
}


@dataclass(frozen=True)
class WebEncodingResult:
    """Keep the current protocol outputs needed by the browser."""

    media_type: str
    layout: EmbeddingLayout
    payload: PayloadRecord | PayloadFileRecord
    sender_public_key_pem: bytes
    payload_capacity: int
    preserved_bits: int
    preserved_ratio: float
    source_converted: bool
    source_format: str
    payload_mime: str
    payload_name: str


@dataclass(frozen=True)
class GeneratedKeyPair:
    """Hold an encrypted private PEM and its matching public PEM."""

    private_key_pem: bytes
    public_key_pem: bytes


class CurrentProtocolService:
    """Bridge uploaded files to the protocol version 3 file APIs."""

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
        carrier_path: Path,
        output_path: Path,
        sender_private_key_pem: bytes,
        sender_key_password: str,
        receiver_public_key_pem: bytes,
        start_unit: int,
        lsb_count: int,
        payload_path: Path,
        payload_mime: str,
        payload_name: str,
        team_id: str,
        sender: str,
        extra_metadata: str,
    ) -> WebEncodingResult:
        """Validate a file-backed cover and write its stego output to disk."""
        media_type, _, source_format = self.detect_carrier(carrier_path)
        metadata = self._build_metadata(
            team_id,
            sender,
            payload_mime,
            payload_name,
            extra_metadata,
        )
        metadata_values, _ = self._parse_metadata(metadata.decode("utf-8"))
        payload_mime = metadata_values["mime"]
        payload_name = metadata_values["name"]
        sender_private_key = self._load_private_key(
            sender_private_key_pem, sender_key_password, "sender private key"
        )
        receiver_public_key = self._load_public_key(
            receiver_public_key_pem, "receiver public key"
        )
        try:
            if media_type == "image":
                with open_image_source(carrier_path, carrier_path.parent) as source:
                    source_converted = Path(source.path).resolve() != carrier_path.resolve()
                    layout, payload = encode_png_from_payload_path(
                        source.path,
                        output_path,
                        sender_private_key,
                        receiver_public_key,
                        start_unit,
                        lsb_count,
                        payload_path,
                        metadata,
                        carrier_source=source,
                    )
            else:
                with open_audio_source(carrier_path, carrier_path.parent) as source:
                    source_converted = Path(source.path).resolve() != carrier_path.resolve()
                    layout, payload = encode_wav_from_payload_path(
                        source.path,
                        output_path,
                        sender_private_key,
                        receiver_public_key,
                        start_unit,
                        lsb_count,
                        payload_path,
                        metadata,
                        carrier_source=source,
                    )
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
                layout,
                payload,
                self._public_key_pem(sender_private_key.public_key()),
                capacity,
                kept_bits,
                kept_bits / total_bits if total_bits else 0.0,
                source_converted,
                source_format,
                payload_mime,
                payload_name,
            )
        except Exception:
            output_path.unlink(missing_ok=True)
            raise

    def verify(
        self,
        carrier_path: Path,
        payload_output_path: Path,
        sender_public_key_pem: bytes,
        receiver_private_key_pem: bytes,
        receiver_key_password: str,
    ) -> tuple[dict[str, object], Path | None]:
        """Verify a carrier and write only an authenticated payload to a file."""
        file_size = carrier_path.stat().st_size
        try:
            media_type, _, _ = self.detect_carrier(carrier_path)
            sender_public_key = self._load_public_key(
                sender_public_key_pem, "sender public key"
            )
            receiver_private_key = self._load_private_key(
                receiver_private_key_pem,
                receiver_key_password,
                "receiver private key",
            )
        except (OSError, TypeError, ValueError) as error:
            return self._failed_report(file_size, str(error)), None

        verifier = (
            verify_png_to_payload_path
            if media_type == "image"
            else verify_wav_to_payload_path
        )
        result = verifier(
            carrier_path,
            sender_public_key,
            receiver_private_key,
            payload_output_path,
        )
        report = self._verification_report(result, media_type, file_size)
        return report, result.payload_path

    @staticmethod
    def payload_record(
        payload: PayloadRecord | PayloadFileRecord,
    ) -> dict[str, object]:
        """Serialize safe payload-record fields for the encoding response."""
        return {
            "media_id": payload.media_id,
            "timestamp": payload.timestamp,
            "timestamp_utc": datetime.fromtimestamp(
                payload.timestamp, timezone.utc
            ).isoformat(),
            "nonce": payload.nonce.hex(),
            "media_hash": payload.media_hash.hex(),
            "user_payload_size": payload.user_payload_size,
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
            "frame_version": result.protocol_version,
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
            report["payload"] = self._verified_payload(
                result.payload, result.payload_path
            )
        return report

    def _verified_payload(
        self,
        payload: PayloadRecord | PayloadFileRecord,
        payload_path: Path | None,
    ) -> dict[str, object]:
        """Return authenticated payload data with guarded preview information."""
        raw_metadata = payload.metadata.decode("utf-8")
        metadata, metadata_valid = self._parse_metadata(raw_metadata)
        declared_mime = metadata.get("mime") if metadata_valid else None
        claimed_name = metadata.get("name") if metadata_valid else None
        if payload_path is None:
            raise ValueError("verified payload path is unavailable")
        sniffed_mime = self._sniff_payload_mime(payload_path)
        type_agrees = self._type_agrees(declared_mime, sniffed_mime, payload_path)
        safe_name = self.safe_filename(claimed_name or "recovered-payload.bin")
        preview_allowed = bool(
            type_agrees and declared_mime in _PREVIEW_MIME_TYPES
        )
        return {
            **self.payload_record(payload),
            "metadata": metadata if metadata_valid else {},
            "metadata_raw": raw_metadata,
            "metadata_valid": metadata_valid,
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
            "frame_version": None,
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
    def detect_carrier(carrier_path: Path) -> tuple[str, str, str]:
        """Return carrier family, output extension, and uploaded source format."""
        media_type, source_format = detect_source_family(carrier_path)
        if media_type == "video":
            raise ValueError("video covers are not supported in the web app")
        return media_type, "png" if media_type == "image" else "wav", source_format

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
        name = self.safe_filename(claimed_name)
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
    def safe_filename(name: str) -> str:
        """Reduce an authenticated filename claim to a safe download basename."""
        if not isinstance(name, str):
            return "recovered-payload.bin"
        basename = name.replace("\\", "/").split("/")[-1].strip()
        basename = re.sub(r"[^A-Za-z0-9._ -]", "_", basename)
        basename = basename.lstrip(". ")[:120]
        return basename or "recovered-payload.bin"

    @staticmethod
    def _sniff_payload_mime(payload_path: Path) -> str | None:
        """Recognize safe preview types from a fixed 4 KiB prefix."""
        with payload_path.open("rb") as payload_file:
            payload = payload_file.read(4096)
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if payload.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if payload.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if payload.startswith(b"BM"):
            return "image/bmp"
        if len(payload) >= 12 and payload[:4] == b"RIFF":
            if payload[8:12] == b"WAVE":
                return "audio/wav"
            if payload[8:12] == b"WEBP":
                return "image/webp"
        if payload.startswith(b"%PDF-"):
            return "application/pdf"
        if payload.startswith(b"ID3") or (
            len(payload) >= 2 and payload[0] == 0xFF and payload[1] & 0xE0 == 0xE0
        ):
            return "audio/mpeg"
        if payload.startswith(b"fLaC"):
            return "audio/flac"
        if payload.startswith(b"OggS"):
            codec_header = CurrentProtocolService._ogg_first_packet(payload)
            if codec_header.startswith((b"\x01vorbis", b"OpusHead")):
                return "audio/ogg"
            if codec_header.startswith(b"\x80theora"):
                return "video/ogg"
        if payload.startswith(b"\x1aE\xdf\xa3"):
            return "video/webm" if CurrentProtocolService._ebml_doc_type(payload) == "webm" else None
        return CurrentProtocolService._iso_bmff_mime(payload)

    @staticmethod
    def _ogg_first_packet(payload: bytes) -> bytes:
        """Return the first Ogg packet prefix when its page is in the bounded read."""
        if len(payload) < 27 or payload[4] != 0:
            return b""
        segment_count = payload[26]
        table_end = 27 + segment_count
        if table_end > len(payload):
            return b""
        lacing_values = payload[27:table_end]
        packet_size = 0
        for segment_size in lacing_values:
            packet_size += segment_size
            if segment_size < 255:
                packet_end = table_end + packet_size
                if packet_end > len(payload):
                    return b""
                return payload[table_end:packet_end]
        return b""

    @staticmethod
    def _ebml_doc_type(payload: bytes) -> str | None:
        """Read an EBML DocType element from the bounded file prefix."""
        marker = b"\x42\x82"
        offset = payload.find(marker, 4)
        if offset < 0 or offset + 3 > len(payload):
            return None
        first_size_byte = payload[offset + 2]
        mask = 0x80
        size_width = 1
        while size_width <= 8 and not first_size_byte & mask:
            mask >>= 1
            size_width += 1
        if size_width > 8 or offset + 2 + size_width > len(payload):
            return None
        size = first_size_byte & (mask - 1)
        for byte in payload[offset + 3:offset + 2 + size_width]:
            size = (size << 8) | byte
        start = offset + 2 + size_width
        end = start + size
        if size > 32 or end > len(payload):
            return None
        return payload[start:end].decode("ascii", errors="ignore").lower()

    @staticmethod
    def _iso_bmff_mime(payload: bytes) -> str | None:
        """Classify common ISO-BMFF preview types from ftyp brands."""
        if len(payload) < 16 or payload[4:8] != b"ftyp":
            return None
        box_size = int.from_bytes(payload[:4], "big")
        if box_size < 16:
            return None
        end = min(box_size, len(payload))
        brands = [payload[8:12]]
        brands.extend(
            payload[offset:offset + 4]
            for offset in range(16, end - 3, 4)
        )
        if any(brand in {b"avif", b"avis"} for brand in brands):
            return "image/avif"
        if any(brand in {b"M4A ", b"M4B ", b"M4P ", b"mp4a"} for brand in brands):
            return "audio/mp4"
        video_brands = {
            b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V ",
            b"iso5", b"iso6", b"av01", b"dash",
        }
        if any(brand in video_brands for brand in brands):
            return "video/mp4"
        return None

    @staticmethod
    def _type_agrees(
        declared: str | None, sniffed: str | None, payload_path: Path
    ) -> bool:
        """Check an authenticated MIME claim using bounded payload reads."""
        if declared is None:
            return False
        if sniffed is not None:
            return declared == sniffed
        if declared in (_PREVIEW_MIME_TYPES - {"text/plain"}) | {"application/pdf"}:
            return False
        if declared == "text/plain":
            decoder = codecs.getincrementaldecoder("utf-8")()
            try:
                with payload_path.open("rb") as payload_file:
                    while chunk := payload_file.read(64 * 1024):
                        decoder.decode(chunk)
                    decoder.decode(b"", final=True)
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
    extension = Path(safe_input).suffix.lower()
    mime = _PAYLOAD_MIME_BY_EXTENSION.get(extension)
    if extension in _AMBIGUOUS_PAYLOAD_MIMES:
        if uploaded_mime in _AMBIGUOUS_PAYLOAD_MIMES[extension]:
            mime = uploaded_mime
        else:
            mime = "video/webm" if extension == ".webm" else "audio/ogg"
    if mime is None:
        mime = mimetypes.guess_type(safe_input)[0]
    if mime is None and uploaded_mime and uploaded_mime != "application/octet-stream":
        mime = uploaded_mime
    return mime or "application/octet-stream", safe_input or "payload.bin"
