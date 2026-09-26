"""Integration tests for the Flask UI on the current masked-media protocol."""

import io
import json
import os
import struct
import tempfile
import unittest
import wave
import zlib
from pathlib import Path
from unittest.mock import patch

import av
import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PIL import Image

from stego import (
    BOOTSTRAP_LSB_COUNT,
    PROTOCOL_VERSION,
    bit_sequence_to_bytes,
    bootstrap_span,
    bytes_to_bit_sequence,
    display_rsa_public_key_fingerprint,
    generate_rsa_keypair,
    open_with_private_key,
    parse_bootstrap,
    read_lsb_bits,
    seal_to_public_key,
    write_lsb_bits,
)
from stego.media import _PNG_MAX_DECODED_BYTES
from stego_web import create_app
from stego_web.services.current_protocol import CurrentProtocolService


PASSWORD = "test-password"


def sample_png() -> bytes:
    """Return a strict RGB PNG with enough carrier units for protocol v3."""
    output = io.BytesIO()
    Image.new("RGB", (96, 96), (46, 112, 99)).save(output, format="PNG")
    return output.getvalue()


def sample_16bit_png() -> bytes:
    """Return an RGB 16-bit PNG written with the PyAV PNG encoder."""
    with tempfile.TemporaryDirectory() as directory_name:
        path = Path(directory_name) / "cover.png"
        pixels = np.arange(96 * 96 * 3, dtype=np.uint16).reshape((96, 96, 3))
        container = av.open(str(path), mode="w", format="image2pipe")
        try:
            stream = container.add_stream("png")
            stream.width = 96
            stream.height = 96
            stream.pix_fmt = "rgb48be"
            frame = av.VideoFrame.from_ndarray(pixels, format="rgb48be")
            for packet in (*stream.encode(frame), *stream.encode(None)):
                container.mux(packet)
        finally:
            container.close()
        return path.read_bytes()


def sample_rgba_png() -> tuple[bytes, np.ndarray]:
    """Return an RGBA PNG and a copy of its expected alpha channel."""
    pixels = np.zeros((96, 96, 4), dtype=np.uint8)
    pixels[:, :, :3] = (46, 112, 99)
    pixels[:, :, 3] = 255
    pixels[:, :8, 3] = 0
    pixels[:, -8:, 3] = 0
    pixels[40:56, :, 3] = 128
    alpha = pixels[:, :, 3].copy()
    output = io.BytesIO()
    Image.fromarray(pixels, mode="RGBA").save(output, format="PNG")
    return output.getvalue(), alpha


def sample_palette_png() -> bytes:
    """Return a palette PNG to test the strict web carrier boundary."""
    output = io.BytesIO()
    Image.new("P", (96, 96)).save(output, format="PNG")
    return output.getvalue()


def oversized_rgb_png() -> bytes:
    """Build a 66-byte RGB PNG above the decoded-byte cap."""
    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)

    header = struct.pack(">IIBBBBB", 20_000, 20_000, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"x"))
        + chunk(b"IEND", b"")
    )


def sample_wav() -> bytes:
    """Return a mono 16-bit PCM WAV with enough samples for protocol v3."""
    output = io.BytesIO()
    with wave.open(output, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(8000)
        wav_file.writeframes(b"\x00\x00" * 8000)
    return output.getvalue()


def private_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a test private key with the shared test password."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSWORD.encode("utf-8")),
    )


def public_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize a test public key."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class WebApplicationTests(unittest.TestCase):
    """Exercise the changed sender/receiver web contract end to end."""

    def setUp(self) -> None:
        """Create an isolated app and independent sender/receiver key pairs."""
        self.output_temp = tempfile.TemporaryDirectory(prefix="inf2005-test-output-")
        self.payload_temp = tempfile.TemporaryDirectory(prefix="inf2005-test-payload-")
        self.addCleanup(self.output_temp.cleanup)
        self.addCleanup(self.payload_temp.cleanup)
        self.output_dir = Path(self.output_temp.name)
        self.payload_dir = Path(self.payload_temp.name)
        self.client = create_app(
            {
                "TESTING": True,
                "STEGO_OUTPUT_DIR": self.output_dir,
                "PAYLOAD_OUTPUT_DIR": self.payload_dir,
            }
        ).test_client()
        self.sender_private, self.sender_public = generate_rsa_keypair()
        self.receiver_private, self.receiver_public = generate_rsa_keypair()
        self.sender_private_pem = private_pem(self.sender_private)
        self.sender_public_pem = public_pem(self.sender_public)
        self.receiver_private_pem = private_pem(self.receiver_private)
        self.receiver_public_pem = public_pem(self.receiver_public)

    def encode(
        self,
        cover: bytes,
        filename: str,
        lsb_bits: int = 1,
        message: str = "authenticated message",
        payload: tuple[bytes, str] | None = None,
        payload_mime: str = "",
    ) -> object:
        """Post one valid encoding request and return its Flask response."""
        data: dict[str, object] = {
            "cover": (io.BytesIO(cover), filename),
            "sender_private_key": (
                io.BytesIO(self.sender_private_pem),
                "sender-private.pem",
            ),
            "sender_key_password": PASSWORD,
            "receiver_public_key": (
                io.BytesIO(self.receiver_public_pem),
                "receiver-public.pem",
            ),
            "team_id": "P1-4",
            "sender": "Test User",
            "secret_message": message,
            "metadata": "project=verification;sequence=1",
            "start_unit": "2048",
            "lsb_bits": str(lsb_bits),
        }
        if payload is not None:
            data["secret_message"] = ""
            data["payload_file"] = (io.BytesIO(payload[0]), payload[1])
        if payload_mime:
            data["payload_mime"] = payload_mime
        response = self.client.post(
            "/encode", data=data, content_type="multipart/form-data"
        )
        self.assertFalse(
            any(path.name.startswith(".stego-staging-") for path in self.output_dir.iterdir())
        )
        return response

    def download_stego(self, encoded: dict[str, object]) -> bytes:
        """Fetch the carrier bytes from the API's download URL."""
        response = self.client.get(str(encoded["stego_url"]))
        body = response.get_data()
        response.close()
        self.assertEqual(response.status_code, 200, body[:200].decode("utf-8", "replace"))
        return body

    def decode(
        self,
        encoded: dict[str, object],
        filename: str,
        sender_public: bytes | None = None,
        receiver_private: bytes | None = None,
    ) -> object:
        """Download one encoded file, then post it for verification."""
        return self.decode_bytes(
            self.download_stego(encoded), filename, sender_public, receiver_private
        )

    def decode_bytes(
        self,
        stego_bytes: bytes,
        filename: str,
        sender_public: bytes | None = None,
        receiver_private: bytes | None = None,
    ) -> object:
        """Post carrier bytes with independently selectable verification keys."""
        response = self.client.post(
            "/decode",
            data={
                "stego": (io.BytesIO(stego_bytes), filename),
                "sender_public_key": (
                    io.BytesIO(sender_public or self.sender_public_pem),
                    "sender-public.pem",
                ),
                "receiver_private_key": (
                    io.BytesIO(receiver_private or self.receiver_private_pem),
                    "receiver-private.pem",
                ),
                "receiver_key_password": PASSWORD,
            },
            content_type="multipart/form-data",
        )
        self.assertFalse(
            any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir())
        )
        return response

    def get_payload(self, payload: dict[str, object]) -> object:
        """Fetch one payload by the URL returned in an Authentic report."""
        response = self.client.get(str(payload["payload_url"]))
        body = response.get_data()
        self.assertEqual(response.status_code, 200, body[:200])
        response.close()
        return response

    def assert_no_recovered_payloads(self) -> None:
        """Check that no payload or sidecar was stored after failure."""
        self.assertEqual(list(self.payload_dir.iterdir()), [])

    def test_index_uses_current_protocol_inputs_and_retains_layout(self) -> None:
        """The original wizard remains while obsolete inputs are absent."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Encode", response.data)
        self.assertIn(b"Decode and verify", response.data)
        self.assertIn(b"sender_private_key", response.data)
        self.assertIn(b"receiver_public_key", response.data)
        self.assertIn(b"receiver_private_key", response.data)
        self.assertIn(b"payload_file", response.data)
        self.assertIn(b"RGB or RGBA PNG, or uncompressed PCM WAV", response.data)
        self.assertIn(b"protocol v3", response.data)
        self.assertNotIn(b"start_secret", response.data)
        self.assertNotIn(b"original_cover", response.data)
        self.assertIn(b"gsap@3.15", response.data)

    def test_16bit_png_cover_works_through_web_routes(self) -> None:
        """The web routes encode and verify a native 16-bit PNG cover."""
        encoded_response = self.encode(sample_16bit_png(), "cover-16.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        decoded_response = self.decode(encoded_response.get_json(), "stego-16.png")
        self.assertEqual(
            decoded_response.status_code, 200, decoded_response.get_data(as_text=True)
        )
        report = decoded_response.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(
            self.get_payload(report["payload"]).get_data(), b"authenticated message"
        )

    def test_png_message_round_trip_recovers_geometry_and_metadata(self) -> None:
        """PNG encoding and receiver-gated decoding expose authenticated data."""
        encoded_response = self.encode(sample_png(), "cover.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["protocol_version"], PROTOCOL_VERSION)
        self.assertEqual(encoded["protocol_version"], 3)
        self.assertEqual(encoded["bootstrap_span"], 2048)
        decoded = self.decode(encoded, "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["frame_version"], PROTOCOL_VERSION)
        self.assertEqual(report["frame_version"], 3)
        self.assertEqual(report["start_location"], 2048)
        self.assertEqual(report["lsb_bits"], 3)
        self.assertEqual(report["payload"]["metadata"]["team"], "P1-4")
        self.assertNotIn("user_payload_base64", report["payload"])
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.get_data(), b"authenticated message")
        self.assertEqual(payload_response.mimetype, "text/plain")
        self.assertEqual(
            payload_response.headers["Content-Disposition"].split(";")[0], "inline"
        )
        self.assertEqual(payload_response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(payload_response.headers["Cache-Control"], "no-store")
        payload_id = str(report["payload"]["payload_url"]).rsplit("/", 1)[-1]
        sidecar = json.loads((self.payload_dir / f"{payload_id}.json").read_text())
        self.assertEqual(
            sidecar,
            {
                "download_name": "message.txt",
                "serve_mime": "text/plain",
                "preview_allowed": True,
            },
        )
        self.assertEqual(
            payload_response.headers["Content-Security-Policy"],
            "default-src 'none'; img-src 'self'; media-src 'self'; sandbox",
        )
        self.assertTrue(report["payload"]["preview_allowed"])
        second_response = self.get_payload(report["payload"])
        self.assertEqual(second_response.get_data(), b"authenticated message")
        self.assertEqual(len(list(self.payload_dir.glob("*.bin"))), 1)
        self.assertEqual(len(list(self.payload_dir.glob("*.json"))), 1)

    def test_png_payload_file_upload_round_trip(self) -> None:
        """PNG carrier uploads preserve an uploaded typed payload file."""
        payload = b"\x89PNG\r\n\x1a\nsmall uploaded PNG payload"
        with patch("stego.media.av.open", wraps=av.open) as av_open:
            encoded_response = self.encode(
                sample_png(),
                "cover.png",
                payload=(payload, "image.png"),
                payload_mime="image/png",
            )
        input_opens = [
            call for call in av_open.call_args_list if call.kwargs.get("mode") == "r"
        ]
        self.assertEqual(len(input_opens), 1, "the uploaded PNG cover must be decoded once")
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        decoded = self.decode(encoded_response.get_json(), "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertTrue(report["payload"]["preview_allowed"])
        self.assertEqual(self.get_payload(report["payload"]).get_data(), payload)
        self.assertFalse(any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir()))

    def test_rgba_png_web_round_trip_keeps_alpha_bytes(self) -> None:
        """The web flow encodes and verifies RGBA without changing alpha."""
        cover, expected_alpha = sample_rgba_png()
        encoded_response = self.encode(cover, "cover.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["protocol_version"], PROTOCOL_VERSION)
        stego_bytes = self.download_stego(encoded)
        with Image.open(io.BytesIO(stego_bytes)) as stego_image:
            self.assertEqual(stego_image.mode, "RGBA")
            stego_alpha = np.asarray(stego_image, dtype=np.uint8)[:, :, 3].copy()
        self.assertTrue(np.array_equal(stego_alpha, expected_alpha))

        decoded = self.decode_bytes(stego_bytes, "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["frame_version"], PROTOCOL_VERSION)

    def test_palette_png_errors_reach_encode_and_verify(self) -> None:
        """Palette PNG failures keep the library's exact format detail."""
        detail = "PNG must be RGB or RGBA; palette and grayscale images are not supported"
        encoded = self.encode(sample_palette_png(), "palette.png")
        self.assertEqual(encoded.status_code, 400)
        self.assertEqual(encoded.get_json()["error"], detail)

        decoded = self.decode_bytes(sample_palette_png(), "palette.png")
        self.assertEqual(decoded.status_code, 200)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertEqual(report["message"], detail)
        self.assertIsNone(report["frame_version"])

    def test_rgb_png_with_trns_colour_key_is_refused_at_encode(self) -> None:
        """An RGB colour-key PNG is refused with HTTP 400 and no output file."""
        output = io.BytesIO()
        Image.new("RGB", (96, 96), (46, 112, 99)).save(output, format="PNG", transparency=(0, 0, 0))
        response = self.encode(output.getvalue(), "keyed.png")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "RGB PNG with a tRNS colour key is not supported; convert the image to RGBA",
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_invalid_carrier_error_precedes_invalid_sender_key(self) -> None:
        """Validate a PNG carrier before reporting an invalid sender key."""
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_palette_png()), "palette.png"),
                "sender_private_key": (io.BytesIO(b"not a private key"), "sender.pem"),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem),
                    "receiver.pem",
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "authenticated message",
                "metadata": "project=verification;sequence=1",
                "start_unit": "2048",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "PNG must be RGB or RGBA; palette and grayscale images are not supported",
        )

    def test_oversized_png_errors_reach_encode_and_verify(self) -> None:
        """The fixed decoded-byte cap gives a clear encode error and verify report."""
        decoded_bytes = 20_000 * 20_000 * 3
        limit = _PNG_MAX_DECODED_BYTES
        detail = (
            "PNG decoded size exceeds configured limit: "
            f"{decoded_bytes} bytes > {limit} bytes"
        )
        png_bytes = oversized_rgb_png()
        self.assertEqual(len(png_bytes), 66)

        encoded = self.encode(png_bytes, "oversized.png")
        self.assertEqual(encoded.status_code, 400)
        self.assertTrue(encoded.is_json)
        self.assertEqual(
            encoded.get_json(),
            {"ok": False, "error": detail},
        )

        decoded = self.decode_bytes(png_bytes, "oversized.png")
        self.assertEqual(decoded.status_code, 200)
        self.assertTrue(decoded.is_json)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertEqual(report["message"], detail)

    def test_unexpected_route_errors_return_safe_json(self) -> None:
        """Unexpected failures return generic JSON; HTTP errors keep their status."""
        self.client.application.config["PROPAGATE_EXCEPTIONS"] = False
        with patch(
            "stego_web.routes.protocol_service.encode",
            side_effect=RuntimeError("secret /home/path"),
        ):
            response = self.encode(sample_png(), "cover.png")
        self.assertEqual(response.status_code, 500)
        self.assertTrue(response.is_json)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "verdict": "Cannot Verify", "error": "internal server error"},
        )
        body = response.get_data(as_text=True)
        self.assertNotIn("secret", body)
        self.assertNotIn("/home", body)

        missing = self.client.get("/not-a-route")
        self.assertEqual(missing.status_code, 404)

    def test_wav_binary_payload_round_trip(self) -> None:
        """WAV carriers preserve an arbitrary binary payload and type claim."""
        payload = b"RIFF\x04\x00\x00\x00WAVE"
        encoded_response = self.encode(
            sample_wav(),
            "cover.wav",
            lsb_bits=2,
            payload=(payload, "clip.wav"),
            payload_mime="audio/wav",
        )
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        decoded = self.decode(encoded_response.get_json(), "stego.wav")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.get_data(), payload)
        self.assertEqual(payload_response.mimetype, "audio/wav")
        self.assertEqual(report["payload"]["declared_mime"], "audio/wav")
        self.assertNotIn("user_payload_base64", report["payload"])

    def test_png_supports_every_lsb_count(self) -> None:
        """The retained 1-8 control maps exactly to protocol LSB counts."""
        for lsb_bits in range(1, 9):
            with self.subTest(lsb_bits=lsb_bits):
                encoded = self.encode(sample_png(), "cover.png", lsb_bits=lsb_bits)
                self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
                report = self.decode(encoded.get_json(), "stego.png").get_json()
                self.assertEqual(report["verdict"], "Authentic")
                self.assertEqual(report["lsb_bits"], lsb_bits)

    def test_bad_verify_key_returns_cannot_verify_report(self) -> None:
        """An unreadable key remains a Cannot Verify report with file size."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        response = self.decode_bytes(
            stego_bytes, "stego.png", sender_public=b"not an RSA key"
        )
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertIsNone(report["frame_version"])
        self.assertEqual(report["file_size"], len(stego_bytes))

    def test_wrong_receiver_key_is_payload_missing(self) -> None:
        """A non-recipient cannot open the RSA-OAEP bootstrap."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        wrong_private, _ = generate_rsa_keypair()
        decoded = self.decode(
            encoded, "stego.png", receiver_private=private_pem(wrong_private)
        )
        self.assertEqual(decoded.status_code, 422)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Payload Missing")
        self.assertIsNone(report["payload"])
        self.assertNotIn("payload_url", report)
        self.assert_no_recovered_payloads()

    def test_wrong_sender_key_is_signature_invalid(self) -> None:
        """The receiver rejects a packet under an unrelated sender identity."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        _, wrong_public = generate_rsa_keypair()
        decoded = self.decode(
            encoded, "stego.png", sender_public=public_pem(wrong_public)
        )
        self.assertEqual(decoded.status_code, 200)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Signature Invalid")
        self.assertIsNone(report["payload"])
        self.assertNotIn("payload_url", report)
        self.assert_no_recovered_payloads()

    def test_changed_preserved_image_bit_is_tampered(self) -> None:
        """A carrier change outside the packet footprint fails the masked hash."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        raw = self.download_stego(encoded)
        with Image.open(io.BytesIO(raw)) as image:
            array = np.array(image, dtype=np.uint8, copy=True)
        array.reshape(-1)[-1] ^= np.uint8(0x80)
        changed_output = io.BytesIO()
        Image.fromarray(array, mode="RGB").save(changed_output, format="PNG")
        decoded = self.decode_bytes(changed_output.getvalue(), "changed.png")
        self.assertEqual(decoded.status_code, 200)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Tampered")
        self.assertIsNone(report["payload"])
        self.assertNotIn("payload_url", report)
        self.assert_no_recovered_payloads()

    def rewrite_png_bootstrap(
        self,
        stego_bytes: bytes,
        version: int | None = None,
        start_unit: int | None = None,
        flip_session_key: bool = False,
    ) -> bytes:
        """Reseal the receiver bootstrap of an RGB PNG with changed fields."""
        with Image.open(io.BytesIO(stego_bytes)) as image:
            pixels = np.array(image, dtype=np.uint8, copy=True)
        units = pixels.reshape(-1)
        span = bootstrap_span(self.receiver_private)
        envelope = bit_sequence_to_bytes(
            read_lsb_bits(units[:span], span, BOOTSTRAP_LSB_COUNT)
        )
        fields = parse_bootstrap(open_with_private_key(envelope, self.receiver_private))
        session_key = fields.session_key
        if flip_session_key:
            session_key = bytes((session_key[0] ^ 1,)) + session_key[1:]
        plaintext = (
            struct.pack(
                ">BB",
                fields.version if version is None else version,
                fields.lsb_count,
            )
            + (fields.start_unit if start_unit is None else start_unit).to_bytes(8, "big")
            + fields.ciphertext_length.to_bytes(8, "big")
            + session_key
            + fields.aead_nonce
        )
        sealed = seal_to_public_key(plaintext, self.receiver_public)
        units[:span] = write_lsb_bits(
            units[:span], bytes_to_bit_sequence(sealed), BOOTSTRAP_LSB_COUNT
        )
        output = io.BytesIO()
        Image.fromarray(pixels, mode="RGB").save(output, format="PNG")
        return output.getvalue()

    def test_verdict_reports_keep_recovered_fields_and_leave_no_staging(self) -> None:
        """Each verdict reports the fields that verification reached and recovered."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        with Image.open(io.BytesIO(stego_bytes)) as image:
            tampered_pixels = np.array(image, dtype=np.uint8, copy=True)
        tampered_pixels.reshape(-1)[-1] ^= np.uint8(0x80)
        tampered_output = io.BytesIO()
        Image.fromarray(tampered_pixels, mode="RGB").save(tampered_output, format="PNG")
        wrong_receiver, _ = generate_rsa_keypair()
        _, wrong_sender = generate_rsa_keypair()
        span = bootstrap_span(self.receiver_private)
        sender_fingerprint = display_rsa_public_key_fingerprint(self.sender_public)
        # Each row: carrier, sender PEM, receiver PEM, verdict, HTTP status,
        # frame_version, start_location, lsb_bits, preserved bits expected.
        cases = (
            ("Authentic", stego_bytes, None, None, 200, 3, 2048, 1, True),
            (
                "Signature Invalid", stego_bytes, public_pem(wrong_sender),
                None, 200, 3, 2048, 1, True,
            ),
            (
                "Payload Missing", stego_bytes, None,
                private_pem(wrong_receiver), 422, None, None, None, False,
            ),
            (
                "Tampered", tampered_output.getvalue(), None,
                None, 200, 3, 2048, 1, True,
            ),
            (
                "Cannot Decrypt",
                self.rewrite_png_bootstrap(stego_bytes, flip_session_key=True),
                None, None, 200, 3, 2048, 1, True,
            ),
            (
                "Wrong Start Location",
                self.rewrite_png_bootstrap(stego_bytes, start_unit=span - 1),
                None, None, 200, 3, span - 1, 1, False,
            ),
            (
                "Cannot Verify",
                self.rewrite_png_bootstrap(stego_bytes, version=2),
                None, None, 200, 2, None, None, False,
            ),
        )
        for (
            verdict, carrier_bytes, sender_public, receiver_private, status,
            frame_version, start_location, lsb_bits, has_preserved,
        ) in cases:
            with self.subTest(verdict=verdict):
                for path in self.payload_dir.iterdir():
                    path.unlink()
                response = self.decode_bytes(
                    carrier_bytes, "stego.png", sender_public, receiver_private
                )
                self.assertEqual(response.status_code, status, response.get_data(as_text=True))
                report = response.get_json()
                self.assertEqual(report["verdict"], verdict)
                self.assertEqual(report["frame_version"], frame_version)
                self.assertEqual(report["start_location"], start_location)
                self.assertEqual(report["lsb_bits"], lsb_bits)
                if has_preserved:
                    self.assertIsInstance(report["preserved_bits"], int)
                    self.assertIsInstance(report["preserved_ratio"], float)
                else:
                    self.assertIsNone(report["preserved_bits"])
                    self.assertIsNone(report["preserved_ratio"])
                expected_fingerprint = (
                    display_rsa_public_key_fingerprint(wrong_sender)
                    if sender_public is not None
                    else sender_fingerprint
                )
                self.assertEqual(report["sender_key_fingerprint"], expected_fingerprint)
                self.assertFalse(
                    any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir())
                )
                if verdict == "Authentic":
                    self.assertIn("payload_url", report["payload"])
                    self.assertEqual(len(list(self.payload_dir.glob("*.bin"))), 1)
                else:
                    self.assertIsNone(report["payload"])
                    self.assertFalse(report["payload_extracted"])
                    self.assert_no_recovered_payloads()

    def test_mime_mismatch_disables_preview_without_invalidating_signature(self) -> None:
        """A false typed-payload claim remains authenticated but is not rendered."""
        encoded = self.encode(
            sample_png(), "cover.png", payload_mime="image/png"
        ).get_json()
        report = self.decode(encoded, "stego.png").get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertFalse(report["payload"]["type_agrees"])
        self.assertFalse(report["payload"]["preview_allowed"])
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.mimetype, "application/octet-stream")
        self.assertTrue(
            payload_response.headers["Content-Disposition"].startswith("attachment;")
        )
        self.assertEqual(payload_response.headers["X-Content-Type-Options"], "nosniff")

    def test_pdf_payload_is_download_only(self) -> None:
        """A correctly typed PDF is downloadable but never rendered inline."""
        pdf_bytes = b"%PDF-1.7\nminimal PDF payload\n"
        encoded = self.encode(
            sample_png(),
            "cover.png",
            payload=(pdf_bytes, "assignment.pdf"),
            payload_mime="application/pdf",
        ).get_json()
        report = self.decode(encoded, "stego.png").get_json()
        self.assertEqual(report["verdict"], "Authentic")
        payload = report["payload"]
        self.assertTrue(payload["type_agrees"])
        self.assertFalse(payload["preview_allowed"])
        response = self.get_payload(payload)
        self.assertEqual(response.get_data(), pdf_bytes)
        self.assertEqual(response.mimetype, "application/octet-stream")
        self.assertTrue(response.headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            "default-src 'none'; img-src 'self'; media-src 'self'; sandbox",
        )
        self.assertIn("filename=assignment.pdf", response.headers["Content-Disposition"])

    def test_payload_route_rejects_staging_directories_and_files(self) -> None:
        """Private staging names and nested files cannot use payload download URLs."""
        staging_dir = self.payload_dir / ".stego-staging-test"
        staging_dir.mkdir()
        payload_id = "A" * 22
        (staging_dir / f"{payload_id}.bin").write_bytes(b"private staging bytes")
        (staging_dir / f"{payload_id}.json").write_text("{}", encoding="utf-8")
        for identifier in (staging_dir.name, payload_id):
            with self.subTest(identifier=identifier):
                response = self.client.get(f"/payload/{identifier}")
                self.assertEqual(response.status_code, 404)

    def test_incremental_utf8_check_handles_chunk_boundaries(self) -> None:
        """Text validation accepts split UTF-8 characters and rejects bad bytes."""
        service = CurrentProtocolService()
        with tempfile.TemporaryDirectory(prefix="inf2005-utf8-test-") as temporary:
            path = Path(temporary) / "payload.txt"
            path.write_bytes(b"a" * (64 * 1024 - 1) + "é".encode("utf-8") + b"z")
            self.assertTrue(service._type_agrees("text/plain", None, path))
            path.write_bytes(b"a" * (64 * 1024) + b"\xff")
            self.assertFalse(service._type_agrees("text/plain", None, path))

    def test_payload_route_rejects_invalid_and_missing_ids(self) -> None:
        """Invalid tokens and absent sidecars return JSON 404 responses."""
        for payload_id in ("invalid!", "short", "a" * 21):
            with self.subTest(payload_id=payload_id):
                response = self.client.get(f"/payload/{payload_id}")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.get_json()["error"], "payload file not found")
        missing = self.client.get(f"/payload/{'a' * 22}")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.get_json()["error"], "payload file not found")

    def test_payload_sidecar_failure_removes_partial_payload(self) -> None:
        """A failed sidecar write removes the already-written payload bytes."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        with patch("stego_web.routes.json.dump", side_effect=OSError("sidecar failed")):
            response = self.decode(encoded, "stego.png")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")
        self.assert_no_recovered_payloads()

    def test_key_generation_supports_both_roles(self) -> None:
        """Sender and receiver setup both produce encrypted RSA key pairs."""
        for role in ("sender", "receiver"):
            with self.subTest(role=role):
                response = self.client.post(
                    "/keys/generate",
                    data={"role": role, "key_password": "setup-password"},
                )
                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertEqual(body["role"], role)
                self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", body["private_key_pem"])
                self.assertIn("BEGIN PUBLIC KEY", body["public_key_pem"])

    def test_obsolete_or_ambiguous_inputs_are_rejected(self) -> None:
        """The route requires current keys, valid layout, and exactly one payload."""
        missing_receiver = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "sender_private_key": (
                    io.BytesIO(self.sender_private_pem),
                    "sender-private.pem",
                ),
                "sender_key_password": PASSWORD,
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "message",
                "start_unit": "2048",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(missing_receiver.status_code, 400)
        self.assertIn("receiver_public_key", missing_receiver.get_json()["error"])

        inside_bootstrap = self.encode(sample_png(), "cover.png").get_json()
        self.assertEqual(inside_bootstrap["start_location"], 2048)
        invalid = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "sender_private_key": (
                    io.BytesIO(self.sender_private_pem),
                    "sender-private.pem",
                ),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem),
                    "receiver-public.pem",
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "message",
                "start_unit": "2047",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertIn("bootstrap", invalid.get_json()["error"])

    def test_download_route_serves_png_and_wav_files(self) -> None:
        """Stored PNG and WAV outputs stream with their carrier MIME types."""
        cases = (("png", sample_png(), "image/png"), ("wav", sample_wav(), "audio/wav"))
        for extension, cover, expected_mime in cases:
            with self.subTest(extension=extension):
                encoded_response = self.encode(cover, f"cover.{extension}")
                self.assertEqual(
                    encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
                )
                body = encoded_response.get_json()
                self.assertNotIn("stego_base64", body)
                self.assertEqual(body["mime_type"], expected_mime)
                download_response = self.client.get(body["stego_url"])
                download_bytes = download_response.get_data()
                self.assertEqual(download_response.status_code, 200)
                self.assertEqual(download_response.mimetype, expected_mime)
                self.assertTrue(
                    download_response.headers["Content-Disposition"].startswith(
                        f"inline; filename=stego.{extension}"
                    )
                )
                self.assertEqual(download_response.headers["Cache-Control"], "no-store")
                stored_path = self.output_dir / str(body["stego_url"]).rsplit("/", 1)[1]
                self.assertEqual(download_bytes, stored_path.read_bytes())
                download_response.close()

    def test_downloaded_stego_file_remains_available(self) -> None:
        """A download does not delete the stored stego file."""
        body = self.encode(sample_png(), "cover.png").get_json()
        first = self.client.get(body["stego_url"])
        first_bytes = first.get_data()
        self.assertEqual(first.status_code, 200)
        stored_path = self.output_dir / str(body["stego_url"]).rsplit("/", 1)[1]
        self.assertTrue(stored_path.is_file())
        first.close()
        second = self.client.get(body["stego_url"])
        second_bytes = second.get_data()
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second_bytes, first_bytes)
        second.close()

    def test_download_rejects_bad_ids_and_extensions(self) -> None:
        """The download route accepts only token-safe IDs and PNG/WAV suffixes."""
        urls = (
            f"/download/{'A' * 22}.png",
            f"/download/{'A' * 21}!.png",
            "/download/..png",
            f"/download/{'A' * 22}.jpg",
            f"/download/{'A' * 23}.png",
        )
        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 404)
                if url == urls[0]:
                    self.assertEqual(
                        response.get_json(),
                        {"ok": False, "error": "stego file not found"},
                    )

    def test_unsupported_carrier_error_is_unchanged(self) -> None:
        """Unsupported files keep the established carrier-error text."""
        response = self.encode(b"not a media file", "cover.bin")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "unsupported carrier; upload an RGB or RGBA PNG or uncompressed PCM WAV",
        )

    def test_missing_and_empty_carrier_upload_errors_remain(self) -> None:
        """Missing and empty carrier uploads keep their established messages."""
        missing = self.client.post(
            "/encode", data={"secret_message": "message"}, content_type="multipart/form-data"
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.get_json()["error"], "missing required upload: cover")
        empty = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(b""), "empty.png"),
                "secret_message": "message",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(empty.status_code, 400)
        self.assertEqual(empty.get_json()["error"], "uploaded file is empty: cover")
        missing_stego = self.client.post(
            "/decode", data={}, content_type="multipart/form-data"
        )
        self.assertEqual(missing_stego.status_code, 400)
        self.assertEqual(
            missing_stego.get_json()["error"], "missing required upload: stego"
        )
        empty_stego = self.client.post(
            "/decode",
            data={"stego": (io.BytesIO(b""), "empty.wav")},
            content_type="multipart/form-data",
        )
        self.assertEqual(empty_stego.status_code, 400)
        self.assertEqual(
            empty_stego.get_json()["error"], "uploaded file is empty: stego"
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_failed_encode_leaves_no_output_file(self) -> None:
        """An encode refusal removes any incomplete output file."""
        response = self.encode(
            sample_png(), "cover.png", payload=(b"x" * (128 * 1024), "large.bin")
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("user payload exceeds capacity", response.get_json()["error"])
        self.assertEqual(list(self.output_dir.iterdir()), [])

    @unittest.skipUnless(
        os.environ.get("STEGO_LARGE_WAV_TEST") == "1",
        "set STEGO_LARGE_WAV_TEST=1 to run the >32 MiB web WAV round trip",
    )
    def test_large_wav_web_encode_download_decode(self) -> None:
        """A WAV larger than 32 MiB round-trips under the default web limit."""
        frame_count = 33 * 1024 * 1024
        cover_stream = io.BytesIO()
        with wave.open(cover_stream, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(1)
            wav_file.setframerate(8000)
            wav_file.writeframes(b"\x80" * frame_count)
        cover = cover_stream.getvalue()
        self.assertGreater(len(cover), 32 * 1024 * 1024)
        encoded_response = self.encode(cover, "large-cover.wav")
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["mime_type"], "audio/wav")
        stego_bytes = self.download_stego(encoded)
        self.assertGreater(len(stego_bytes), 32 * 1024 * 1024)
        decoded = self.decode_bytes(stego_bytes, "large-stego.wav")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertGreater(report["file_size"], 32 * 1024 * 1024)

    @unittest.skipUnless(
        os.environ.get("STEGO_LARGE_WAV_TEST") == "1",
        "set STEGO_LARGE_WAV_TEST=1 to run the 20 MiB WAV payload round trip",
    )
    def test_large_wav_payload_upload_streams_to_recovered_file(self) -> None:
        """A large uploaded payload round-trips through WAV file APIs."""
        payload_size = 20 * 1024 * 1024
        frame_count = 22 * 1024 * 1024
        cover_stream = io.BytesIO()
        with wave.open(cover_stream, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(1)
            wav_file.setframerate(8000)
            wav_file.writeframes(b"\x80" * frame_count)
        payload = b"x" * payload_size
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(cover_stream.getvalue()), "cover.wav"),
                "payload_file": (io.BytesIO(payload), "large.txt"),
                "payload_mime": "text/plain",
                "sender_private_key": (io.BytesIO(self.sender_private_pem), "sender.pem"),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (io.BytesIO(self.receiver_public_pem), "receiver.pem"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_unit": "2048",
                "lsb_bits": "8",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        decoded = self.decode(response.get_json(), "large-stego.wav")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["payload"]["user_payload_size"], payload_size)
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.get_data(), payload)
        self.assertFalse(any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir()))

    def test_upload_limit_returns_json(self) -> None:
        """The default is 256 MiB and test apps can override the limit."""
        self.assertEqual(
            self.client.application.config["MAX_CONTENT_LENGTH"], 256 * 1024 * 1024
        )
        client = create_app(
            {
                "TESTING": True,
                "MAX_CONTENT_LENGTH": 100,
                "STEGO_OUTPUT_DIR": self.output_dir,
                "PAYLOAD_OUTPUT_DIR": self.payload_dir,
            }
        ).test_client()
        response = client.post(
            "/decode", data={"stego": (io.BytesIO(b"x" * 200), "file")}
        )
        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")


if __name__ == "__main__":
    unittest.main()
