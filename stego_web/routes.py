"""HTTP boundary for the current masked-media protocol and existing web UI."""

import json
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

from stego import PROTOCOL_VERSION

from .services.current_protocol import (
    CurrentProtocolService,
    _PREVIEW_MIME_TYPES,
    infer_payload_claim,
)


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
    """Encrypt, sign, and embed a payload using protocol version 3."""
    output_path: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="inf2005-encode-") as temporary:
            temporary_path = Path(temporary)
            payload_path, payload_mime, payload_name = _payload_input(temporary_path)
            cover_path = temporary_path / "cover.upload"
            _save_carrier_upload("cover", cover_path)
            _, extension, _ = protocol_service.detect_carrier(cover_path)
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
                payload_path,
                payload_mime,
                payload_name,
                _required_form_value("team_id"),
                _required_form_value("sender"),
                request.form.get("metadata", "").strip(),
            )
        payload_fields = protocol_service.payload_record(result.payload)
        payload_fields["mime"] = result.payload_mime
        payload_fields["name"] = result.payload_name
        return jsonify(
            ok=True,
            protocol_version=PROTOCOL_VERSION,
            media_type=result.media_type,
            source_converted=result.source_converted,
            source_format=result.source_format,
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
            payload=payload_fields,
            media_hash=result.payload.media_hash.hex(),
            sender_public_key_pem=result.sender_public_key_pem.decode("ascii"),
            pipeline_steps=[
                "media-and-payload-validated",
                "sender-and-receiver-keys-loaded",
                "embedding-geometry-validated",
                "full-media-hash-created",
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
    """Recover geometry, verify integrity, and save an authentic payload."""
    payload_output_path: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="inf2005-stego-") as temporary:
            stego_path = Path(temporary) / "received.upload"
            _save_carrier_upload("stego", stego_path)
            original_name = request.files["stego"].filename
            output_dir = Path(current_app.config["PAYLOAD_OUTPUT_DIR"])
            output_dir.mkdir(parents=True, exist_ok=True)
            payload_output_path = _new_payload_path(output_dir)
            report, recovered_path = protocol_service.verify(
                stego_path,
                payload_output_path,
                _required_upload("sender_public_key"),
                _required_upload("receiver_private_key"),
                _required_form_value("receiver_key_password"),
            )
    except (OSError, TypeError, ValueError) as error:
        if payload_output_path is not None:
            payload_output_path.unlink(missing_ok=True)
        return _error(str(error), 400, "Cannot Verify")
    except Exception:
        if payload_output_path is not None:
            payload_output_path.unlink(missing_ok=True)
        raise

    report["filename"] = original_name
    if report["verdict"] == "Authentic":
        payload_fields = report.get("payload")
        if recovered_path is None or not isinstance(payload_fields, dict):
            return _error("verified payload file is unavailable", 500, "Cannot Verify")
        try:
            _, payload_fields["payload_url"] = _store_recovered_payload(
                recovered_path, payload_fields
            )
        except (OSError, TypeError, ValueError) as error:
            recovered_path.unlink(missing_ok=True)
            return _error(f"could not store recovered payload: {error}", 500, "Cannot Verify")

    status = 422 if report["verdict"] == "Payload Missing" else 200
    return jsonify(report), status


def _store_recovered_payload(
    payload_path: Path, payload_fields: dict[str, object]
) -> tuple[str, str]:
    """Write the sidecar for a payload file published by the protocol library."""
    output_dir = Path(current_app.config["PAYLOAD_OUTPUT_DIR"])
    download_name = payload_fields.get("download_name")
    if not isinstance(download_name, str):
        download_name = "recovered-payload.bin"
    download_name = protocol_service.safe_filename(download_name)
    claimed_mime = payload_fields.get("declared_mime")
    preview_allowed = (
        payload_fields.get("preview_allowed") is True
        and isinstance(claimed_mime, str)
        and claimed_mime in _PREVIEW_MIME_TYPES
    )
    serve_mime = claimed_mime if preview_allowed else "application/octet-stream"

    payload_id = payload_path.stem
    sidecar_path = output_dir / f"{payload_id}.json"
    payload_url = url_for("web.download_payload", payload_id=payload_id)
    try:
        with sidecar_path.open("x", encoding="utf-8") as sidecar_file:
            json.dump(
                {
                    "download_name": download_name,
                    "serve_mime": serve_mime,
                    "preview_allowed": preview_allowed,
                },
                sidecar_file,
                separators=(",", ":"),
            )
            sidecar_file.write("\n")
    except BaseException:
        sidecar_path.unlink(missing_ok=True)
        raise
    return payload_id, payload_url


@web.get("/payload/<payload_id>")
def download_payload(payload_id: str) -> Response | tuple[Response, int]:
    """Serve a recovered payload with MIME and browser-rendering safeguards."""
    if _STEGO_ID.fullmatch(payload_id) is None:
        return _error("payload file not found", 404)
    output_dir = Path(current_app.config["PAYLOAD_OUTPUT_DIR"])
    payload_path = output_dir / f"{payload_id}.bin"
    sidecar_path = output_dir / f"{payload_id}.json"
    try:
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _error("payload file not found", 404)
    if not isinstance(sidecar, dict) or not payload_path.is_file():
        return _error("payload file not found", 404)

    candidate_mime = sidecar.get("serve_mime")
    preview_allowed = (
        sidecar.get("preview_allowed") is True
        and isinstance(candidate_mime, str)
        and candidate_mime in _PREVIEW_MIME_TYPES
    )
    serve_mime = candidate_mime if preview_allowed else "application/octet-stream"
    claimed_name = sidecar.get("download_name")
    if not isinstance(claimed_name, str):
        claimed_name = "recovered-payload.bin"
    download_name = protocol_service.safe_filename(claimed_name)
    response = send_file(
        payload_path,
        mimetype=serve_mime,
        as_attachment=not preview_allowed,
        download_name=download_name,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; img-src 'self'; media-src 'self'; sandbox"
    )
    return response


def _new_payload_path(output_dir: Path) -> Path:
    """Choose an unused opaque name for an authenticated payload output."""
    for _ in range(5):
        candidate = output_dir / f"{secrets.token_urlsafe(16)}.bin"
        if not candidate.exists() and not candidate.with_suffix(".json").exists():
            return candidate
    raise OSError("could not allocate a recovered payload ID")


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


def _payload_input(directory: Path) -> tuple[Path, str, str]:
    """Save one uploaded payload or UTF-8 message to a request-scoped file."""
    upload = request.files.get("payload_file")
    message = request.form.get("secret_message", "")
    has_upload = upload is not None and bool(upload.filename)
    has_message = bool(message.strip())
    if has_upload and has_message:
        raise ValueError("choose either a payload file or a secret message, not both")
    if not has_upload and not has_message:
        raise ValueError("a payload file or secret message is required")
    payload_path = directory / "payload.upload"
    if has_upload:
        upload.save(payload_path)
        if payload_path.stat().st_size == 0:
            raise ValueError("payload file is empty")
        payload_mime, payload_name = infer_payload_claim(
            upload.filename, upload.mimetype, False
        )
    else:
        payload_path.write_bytes(message.encode("utf-8"))
        payload_mime, payload_name = infer_payload_claim(None, None, True)
    return payload_path, payload_mime, payload_name


def _error(
    message: str, status: int, verdict: str | None = None
) -> tuple[Response, int]:
    """Return a consistent JSON error response."""
    body: dict[str, object] = {"ok": False, "error": message}
    if verdict is not None:
        body["verdict"] = verdict
    return jsonify(body), status
