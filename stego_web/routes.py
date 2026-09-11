"""HTTP boundary: input validation and JSON serialization only."""

from __future__ import annotations

import base64

from flask import Blueprint, jsonify, render_template, request

from payload_protocol import detect_media_type

from .exceptions import (
    CapacityError,
    FeatureUnavailableError,
    InvalidMediaError,
    WrongStartLocationError,
)
from .models import Verdict
from .services import (
    AudioLsbSteganography,
    CryptographyService,
    HmacStartLocation,
    ImageLsbSteganography,
    SteganographyRegistry,
)

web = Blueprint("web", __name__)

location_strategy = HmacStartLocation()
crypto_service = CryptographyService()
stego_registry = SteganographyRegistry(
    [
        ImageLsbSteganography(location_strategy),
        AudioLsbSteganography(location_strategy),
    ]
)


@web.get("/")
def index():
    return render_template("index.html")


@web.post("/encode")
def encode():
    try:
        cover = _required_upload("cover")
        lsb_bits = _lsb_bits()
        secret = _required_form_value("start_secret")
        signed = crypto_service.create_signed_packet(
            cover,
            _required_form_value("team_id"),
            _required_form_value("sender"),
            _required_form_value("key_password"),
        )
        media_type = detect_media_type(cover)
        embedded = stego_registry.for_media(media_type).embed(
            cover, signed.packet, lsb_bits, secret
        )
    except FeatureUnavailableError as error:
        return _error(str(error), 501, Verdict.CANNOT_VERIFY)
    except (CapacityError, InvalidMediaError, TypeError, ValueError) as error:
        return _error(str(error), 400)

    extension = "png" if media_type == "image" else "wav"
    return jsonify(
        ok=True,
        media_type=media_type,
        filename=f"stego.{extension}",
        mime_type="image/png" if media_type == "image" else "audio/wav",
        lsb_bits=lsb_bits,
        start_location=embedded.start_location,
        capacity_bytes=embedded.capacity_bytes,
        payload=signed.payload,
        stego_base64=base64.b64encode(embedded.media_bytes).decode("ascii"),
        public_key_pem=signed.public_key_pem.decode("ascii"),
        private_key_pem=signed.private_key_pem.decode("ascii"),
    )


@web.post("/decode")
def decode():
    try:
        stego = _required_upload("stego")
        public_key = _required_upload("public_key")
        original_cover = _optional_upload("original_cover")
        lsb_bits = _lsb_bits()
        secret = _required_form_value("start_secret")
        media_type = detect_media_type(stego)
        extracted = stego_registry.for_media(media_type).extract(stego, lsb_bits, secret)
        result = crypto_service.verify_signed_packet(
            extracted.packet, public_key, original_cover
        )
    except WrongStartLocationError as error:
        return _error(str(error), 422, Verdict.WRONG_START_LOCATION)
    except FeatureUnavailableError as error:
        return _error(str(error), 501, Verdict.CANNOT_VERIFY)
    except (InvalidMediaError, TypeError, ValueError) as error:
        return _error(str(error), 400, Verdict.PAYLOAD_MISSING)

    response = result.as_dict()
    response.update(ok=result.verdict == Verdict.AUTHENTIC, media_type=media_type)
    return jsonify(response)


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


def _error(message: str, status: int, verdict: Verdict | None = None):
    body = {"ok": False, "error": message}
    if verdict is not None:
        body["verdict"] = verdict.value
    return jsonify(body), status
