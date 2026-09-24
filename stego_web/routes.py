"""HTTP boundary for the current masked-media protocol and existing web UI."""

import re
import secrets
import tempfile
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
    url_for,
)

from .services.current_protocol import CurrentProtocolService, infer_payload_claim


web = Blueprint("web", __name__)
protocol_service = CurrentProtocolService()
_STEGO_ID = re.compile(r"[A-Za-z0-9_-]{22}\Z")
_DOWNLOAD_TYPES = {"png": "image/png", "wav": "audio/wav"}


@web.get("/")
def index() -> str:
    """Render the retained encoding and verification layout."""
    return render_template("index.html")


@web.post("/encode")
def encode() -> Response | tuple[Response, int]:
    """Encrypt, sign, and embed a payload using protocol version 2."""
    output_path: Path | None = None
    try:
        user_payload, payload_mime, payload_name = _payload_input()
        with tempfile.TemporaryDirectory(prefix="inf2005-cover-") as temporary:
            cover_path = Path(temporary) / "cover.upload"
            _save_carrier_upload("cover", cover_path)
            _, extension = protocol_service.detect_carrier(cover_path)
            stego_id = secrets.token_urlsafe(16)
            output_dir = Path(current_app.config["STEGO_OUTPUT_DIR"])
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"{stego_id}.{extension}"
            result = protocol_service.encode(
                cover_path,
                output_path,
                _required_upload("sender_private_key"),
                _required_form_value("sender_key_password"),
                _required_upload("receiver_public_key"),
                _integer_form_value("start_unit", minimum=0),
                _lsb_bits(),
                user_payload,
                payload_mime,
                payload_name,
                _required_form_value("team_id"),
                _required_form_value("sender"),
                request.form.get("metadata", "").strip(),
            )
        return jsonify(
            ok=True,
            protocol_version=2,
            media_type=result.media_type,
            filename=f"stego.{extension}",
            mime_type=_DOWNLOAD_TYPES[extension],
            stego_url=url_for("web.download", stego_id=stego_id, ext=extension),
            lsb_bits=result.layout.lsb_count,
            start_location=result.layout.start_unit,
            bootstrap_span=result.layout.bootstrap_span,
            footprint=result.layout.footprint,
            capacity_bytes=result.payload_capacity,
            preserved_bits=result.preserved_bits,
            preserved_ratio=result.preserved_ratio,
            payload=protocol_service.payload_record(result.payload),
            media_hash=result.payload.media_hash.hex(),
            sender_public_key_pem=result.sender_public_key_pem.decode("ascii"),
            pipeline_steps=[
                "media-and-payload-validated",
                "sender-and-receiver-keys-loaded",
                "embedding-geometry-validated",
                "masked-media-hash-created",
                "payload-encrypted-and-signed",
                "receiver-bootstrap-and-packet-embedded",
                "media-exported",
            ],
        )
    except (OSError, TypeError, ValueError) as error:
        if output_path is not None:
            output_path.unlink(missing_ok=True)
        return _error(str(error), 400)


@web.get("/download/<stego_id>.<ext>")
def download(stego_id: str, ext: str) -> Response | tuple[Response, int]:
    """Serve one stored stego carrier after validating its opaque identifier."""
    if _STEGO_ID.fullmatch(stego_id) is None or ext not in _DOWNLOAD_TYPES:
        return _error("stego file not found", 404)
    path = Path(current_app.config["STEGO_OUTPUT_DIR"]) / f"{stego_id}.{ext}"
    if not path.is_file():
        return _error("stego file not found", 404)
    return send_file(
        path,
        mimetype=_DOWNLOAD_TYPES[ext],
        as_attachment=False,
        download_name=f"stego.{ext}",
    )


@web.post("/keys/generate")
def generate_keys() -> Response | tuple[Response, int]:
    """Generate a sender or receiver RSA pair as an explicit setup action."""
    try:
        role = request.form.get("role", "key").strip().lower()
        if role not in {"sender", "receiver", "key"}:
            raise ValueError("role must be sender or receiver")
        keys = protocol_service.generate_key_pair(
            _required_form_value("key_password")
        )
    except (TypeError, ValueError) as error:
        return _error(str(error), 400)
    return jsonify(
        ok=True,
        role=role,
        private_key_pem=keys.private_key_pem.decode("ascii"),
        public_key_pem=keys.public_key_pem.decode("ascii"),
    )


@web.post("/decode")
def decode() -> Response | tuple[Response, int]:
    """Recover geometry, verify integrity, and decrypt an authenticated payload."""
    try:
        with tempfile.TemporaryDirectory(prefix="inf2005-stego-") as temporary:
            stego_path = Path(temporary) / "received.upload"
            _save_carrier_upload("stego", stego_path)
            original_name = request.files["stego"].filename
            result = protocol_service.verify(
                stego_path,
                _required_upload("sender_public_key"),
                _required_upload("receiver_private_key"),
                _required_form_value("receiver_key_password"),
            )
    except (OSError, TypeError, ValueError) as error:
        return _error(str(error), 400, "Cannot Verify")

    result["filename"] = original_name
    status = 422 if result["verdict"] == "Payload Missing" else 200
    return jsonify(result), status


def _save_carrier_upload(name: str, destination: Path) -> None:
    """Save a required carrier upload to disk and reject an empty file."""
    upload = request.files.get(name)
    if upload is None or not upload.filename:
        raise ValueError(f"missing required upload: {name}")
    upload.save(destination)
    if destination.stat().st_size == 0:
        raise ValueError(f"uploaded file is empty: {name}")


def _required_upload(name: str) -> bytes:
    """Read one required non-empty, non-carrier multipart upload."""
    upload = request.files.get(name)
    if upload is None or not upload.filename:
        raise ValueError(f"missing required upload: {name}")
    data = upload.read()
    if not data:
        raise ValueError(f"uploaded file is empty: {name}")
    return data


def _required_form_value(name: str) -> str:
    """Read one required non-empty form value."""
    value = request.form.get(name, "").strip()
    if not value:
        raise ValueError(f"missing required field: {name}")
    return value


def _integer_form_value(name: str, minimum: int) -> int:
    """Read a bounded integer form field."""
    try:
        value = int(request.form.get(name, ""))
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _lsb_bits() -> int:
    """Read the protocol's supported LSB count."""
    value = _integer_form_value("lsb_bits", minimum=1)
    if value not in range(1, 9):
        raise ValueError("lsb_bits must be between 1 and 8")
    return value


def _payload_input() -> tuple[bytes, str, str]:
    """Choose either uploaded payload bytes or a UTF-8 message and its claims."""
    upload = request.files.get("payload_file")
    message = request.form.get("secret_message", "")
    has_upload = upload is not None and bool(upload.filename)
    has_message = bool(message.strip())
    if has_upload and has_message:
        raise ValueError("choose either a payload file or a secret message, not both")
    if not has_upload and not has_message:
        raise ValueError("a payload file or secret message is required")
    if has_upload:
        payload = upload.read()
        if not payload:
            raise ValueError("payload file is empty")
        default_mime, default_name = infer_payload_claim(
            upload.filename, upload.mimetype, False
        )
    else:
        payload = message.encode("utf-8")
        default_mime, default_name = infer_payload_claim(None, None, True)
    mime = request.form.get("payload_mime", "").strip() or default_mime
    name = request.form.get("payload_name", "").strip() or default_name
    return payload, mime, name


def _error(
    message: str, status: int, verdict: str | None = None
) -> tuple[Response, int]:
    """Return a consistent JSON error response."""
    body: dict[str, object] = {"ok": False, "error": message}
    if verdict is not None:
        body["verdict"] = verdict
    return jsonify(body), status
