"""HTTP boundary: input validation and JSON serialization only."""

from __future__ import annotations

import base64
import json

from flask import Blueprint, jsonify, render_template, request

from .exceptions import (
    CapacityError,
    InvalidMediaError,
)
from .models import Verdict
from .services import (
    AudioLsbSteganography,
    CoverMediaHandler,
    CryptoManager,
    EncodingPipeline,
    HmacStartLocation,
    ImageLsbSteganography,
    PayloadBuilder,
    SteganographyRegistry,
)
from .services.verification_pipeline import VerificationPipeline

web = Blueprint("web", __name__)

location_strategy = HmacStartLocation()
crypto_manager = CryptoManager()
stego_registry = SteganographyRegistry(
    [
        ImageLsbSteganography(location_strategy),
        AudioLsbSteganography(location_strategy),
    ]
)
cover_handler = CoverMediaHandler(stego_registry)
verification_pipeline = VerificationPipeline(cover_handler, crypto_manager)
encoding_pipeline = EncodingPipeline(
    cover_handler,
    crypto_manager,
    PayloadBuilder(),
    location_strategy,
)


@web.get("/")
def index():
    return render_template("index.html")


@web.post("/encode")
def encode():
    try:
        lsb_bits = _lsb_bits()
        result = encoding_pipeline.encode(
            _required_upload("cover"),
            _required_upload("private_key"),
            _required_form_value("key_password"),
            _required_form_value("team_id"),
            _required_form_value("sender"),
            _team_metadata(),
            _required_form_value("start_secret"),
            lsb_bits,
        )
    except (CapacityError, InvalidMediaError, TypeError, ValueError) as error:
        return _error(str(error), 400)

    extension = "png" if result.media_type == "image" else "wav"
    return jsonify(
        ok=True,
        media_type=result.media_type,
        filename=f"stego.{extension}",
        mime_type="image/png" if result.media_type == "image" else "audio/wav",
        lsb_bits=lsb_bits,
        start_location=result.embedded.start_location,
        capacity_bytes=result.embedded.capacity_bytes,
        payload=result.payload,
        media_hash=result.media_hash,
        stego_base64=base64.b64encode(result.embedded.media_bytes).decode("ascii"),
        public_key_pem=result.public_key_pem.decode("ascii"),
        pipeline_steps=[
            "validated",
            "hashed",
            "payload-built",
            "signed-with-existing-key",
            "location-derived",
            "lsb-embedded",
            "media-exported",
        ],
    )


@web.post("/keys/generate")
def generate_keys():
    """Create initial demo keys; encoding itself never generates a key."""
    try:
        keys = crypto_manager.generate_key_pair(_required_form_value("key_password"))
    except (TypeError, ValueError) as error:
        return _error(str(error), 400)
    return jsonify(
        ok=True,
        private_key_pem=keys.private_key_pem.decode("ascii"),
        public_key_pem=keys.public_key_pem.decode("ascii"),
    )


@web.post("/location/derive")
def derive_location():
    """Validate a cover and expose the authoritative HMAC-derived location."""
    try:
        cover = cover_handler.validate(_required_upload("cover"))
        lsb_bits = _lsb_bits()
        start = location_strategy.derive(
            _required_form_value("start_secret"),
            cover.media_type,
            cover.carrier_units,
            lsb_bits,
        )
    except (InvalidMediaError, TypeError, ValueError) as error:
        return _error(str(error), 400)

    return jsonify(
        ok=True,
        algorithm="PBKDF2-HMAC-SHA256",
        media_type=cover.media_type,
        carrier_units=cover.carrier_units,
        start_location=start,
        non_default=start > 0,
    )


@web.post("/decode")
def decode():
    try:
        stego = _required_upload("stego")
        public_key = _required_upload("public_key")
        original_cover = _optional_upload("original_cover")
        lsb_bits = None if request.form.get("lsb_bits", "auto") == "auto" else _lsb_bits()
        result = verification_pipeline.verify(
            stego, public_key, request.form.get("start_secret", ""), lsb_bits,
            original_cover, request.form.get("media_type", "auto"),
        )
    except (InvalidMediaError, TypeError, ValueError) as error:
        return _error(str(error), 400, Verdict.CANNOT_VERIFY)

    result["filename"] = request.files["stego"].filename
    return jsonify(result), (422 if result["verdict"] == Verdict.PAYLOAD_MISSING else 200)


def _required_upload(name: str) -> bytes:
    upload = request.files.get(name)
    if upload is None or not upload.filename:
        raise ValueError(f"missing required upload: {name}")
    data = upload.read()
    if not data:
        raise ValueError(f"uploaded file is empty: {name}")
    return data


def _optional_upload(name: str) -> bytes | None:
    upload = request.files.get(name)
    if upload is None or not upload.filename:
        return None
    data = upload.read()
    return data or None


def _required_form_value(name: str) -> str:
    value = request.form.get(name, "").strip()
    if not value:
        raise ValueError(f"missing required field: {name}")
    return value


def _lsb_bits() -> int:
    try:
        value = int(request.form.get("lsb_bits", "1"))
    except ValueError as error:
        raise ValueError("lsb_bits must be an integer") from error
    if value not in range(1, 9):
        raise ValueError("lsb_bits must be between 1 and 8")
    return value


def _team_metadata() -> dict[str, object] | None:
    """Parse optional wizard metadata and message into signed metadata."""
    metadata_text = request.form.get("metadata", "").strip()
    message = request.form.get("secret_message", "").strip()
    metadata: dict[str, object] = {}
    if metadata_text:
        try:
            parsed = json.loads(metadata_text)
        except json.JSONDecodeError as error:
            raise ValueError("metadata must be valid JSON") from error
        if not isinstance(parsed, dict):
            raise ValueError("metadata must be a JSON object")
        metadata.update(parsed)
    if message:
        metadata["secret_message"] = message
    return metadata or None


def _error(message: str, status: int, verdict: Verdict | None = None):
    body = {"ok": False, "error": message}
    if verdict is not None:
        body["verdict"] = verdict.value
    return jsonify(body), status
