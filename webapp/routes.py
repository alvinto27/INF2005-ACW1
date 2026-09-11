"""HTTP routing for encode/decode and the starter GUI."""

from __future__ import annotations

import base64

from flask import Blueprint, current_app, jsonify, render_template, request, send_file

from payload_protocol import detect_media_type

from .media import carrier_for
from .start_location import StartLocationDeriver

routes = Blueprint("routes", __name__)


def _bits() -> int:
    try:
        value = int(request.form.get("lsb", "1"))
    except ValueError as error:
        raise ValueError("lsb must be an integer from 1 to 8") from error
    if not 1 <= value <= 8:
        raise ValueError("lsb must be an integer from 1 to 8")
    return value


def _upload() -> tuple[str, bytes]:
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        raise ValueError("multipart field 'file' is required")
    data = uploaded.read()
    if not data:
        raise ValueError("uploaded file is empty")
    return uploaded.filename, data


@routes.get("/")
def index():
    return render_template("index.html")


@routes.post("/encode")
def encode():
    try:
        filename, cover = _upload()
        bits = _bits()
        media_type = detect_media_type(cover)
        carrier = carrier_for(cover)
        service = current_app.config["CRYPTO_SERVICE"]
        _, packet = service.create_packet(
            cover,
            request.form.get("team_id", "team-local"),
            request.form.get("sender", "localhost"),
        )
        start = StartLocationDeriver(service.public_key_bytes()).derive(carrier.carrier_units(cover), bits)
        stego = carrier.embed(cover, packet, start, bits)
        suffix = "_stego.png" if media_type == "image" else "_stego.wav"
        download_name = f"{filename.rsplit('.', 1)[0]}{suffix}"
        response = send_file(__import__("io").BytesIO(stego), mimetype="image/png" if media_type == "image" else "audio/wav", as_attachment=True, download_name=download_name)
        response.headers["X-Media-Type"] = media_type
        response.headers["X-Start-Unit"] = str(start)
        response.headers["X-LSB"] = str(bits)
        return response
    except (TypeError, ValueError) as error:
        return jsonify(error=str(error)), 400


@routes.post("/decode")
def decode():
    try:
        _, stego = _upload()
        bits = _bits()
        service = current_app.config["CRYPTO_SERVICE"]
        carrier = carrier_for(stego)
        start = StartLocationDeriver(service.public_key_bytes()).derive(carrier.carrier_units(stego), bits)
        signature_length = (service.public_key.key_size + 7) // 8
        header = carrier.extract(stego, start, 4, bits)
        packet_length = int.from_bytes(header, "big")
        packet = carrier.extract(stego, start, 4 + packet_length + signature_length, bits)
        valid, verdict, payload = service.verify_packet(packet)
        # Useful to client-side previews without exposing the private key.
        return jsonify(valid=valid, verdict=verdict, payload=payload, start_unit=start, lsb=bits,
                       packet_b64=base64.b64encode(packet).decode("ascii") if valid else None)
    except (TypeError, ValueError) as error:
        return jsonify(valid=False, verdict=str(error), payload=None), 400
