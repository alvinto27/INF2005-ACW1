"""Integration tests for the Flask UI on the current masked-media protocol."""

import base64
import io
import shutil
import subprocess
import unittest
import wave
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PIL import Image

from stego import generate_rsa_keypair
from stego_web import create_app


PASSWORD = "test-password"


def sample_png() -> bytes:
    """Return a strict RGB PNG with enough carrier units for protocol v2."""
    output = io.BytesIO()
    Image.new("RGB", (96, 96), (46, 112, 99)).save(output, format="PNG")
    return output.getvalue()


def sample_wav() -> bytes:
    """Return a mono 16-bit PCM WAV with enough samples for protocol v2."""
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
        self.client = create_app({"TESTING": True}).test_client()
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
        start_unit: int = 2048,
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
            "start_unit": str(start_unit),
            "lsb_bits": str(lsb_bits),
        }
        if payload is not None:
            data["secret_message"] = ""
            data["payload_file"] = (io.BytesIO(payload[0]), payload[1])
        if payload_mime:
            data["payload_mime"] = payload_mime
        return self.client.post(
            "/encode", data=data, content_type="multipart/form-data"
        )

    def estimate(
        self,
        cover: bytes,
        filename: str,
        lsb_bits: int = 1,
        start_unit: int = 2049,
        message: str = "authenticated message",
    ) -> object:
        """Post the map's pre-encode layout request."""
        return self.client.post(
            "/layout/estimate",
            data={
                "cover": (io.BytesIO(cover), filename),
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem),
                    "receiver-public.pem",
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": message,
                "metadata": "project=verification;sequence=1",
                "start_unit": str(start_unit),
                "lsb_bits": str(lsb_bits),
            },
            content_type="multipart/form-data",
        )

    def decode(
        self,
        encoded: dict[str, object],
        filename: str,
        sender_public: bytes | None = None,
        receiver_private: bytes | None = None,
    ) -> object:
        """Post one verification request with independently selectable keys."""
        return self.client.post(
            "/decode",
            data={
                "stego": (
                    io.BytesIO(base64.b64decode(str(encoded["stego_base64"]))),
                    filename,
                ),
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
        self.assertNotIn(b"start_secret", response.data)
        self.assertNotIn(b"original_cover", response.data)
        self.assertIn(b"gsap@3.15", response.data)
        self.assertEqual(response.data.count(b'class="file-picker"'), 6)
        self.assertIn(b"Browse media", response.data)
        self.assertIn(b"Browse key", response.data)
        self.assertIn(b'id="stego-map-stage"', response.data)
        self.assertIn(b'id="manual-placement"', response.data)
        self.assertIn(b"vendor/three/three.module.min.js", response.data)
        self.assertIn(b"stego-map.js", response.data)

    def test_png_layout_estimate_matches_encoded_packet_geometry(self) -> None:
        """The map receives the same authoritative footprint as the encoder."""
        estimated_response = self.estimate(
            sample_png(), "cover.png", lsb_bits=3, start_unit=2049
        )
        self.assertEqual(
            estimated_response.status_code,
            200,
            estimated_response.get_data(as_text=True),
        )
        estimated = estimated_response.get_json()
        encoded_response = self.encode(
            sample_png(), "cover.png", lsb_bits=3, start_unit=2049
        )
        self.assertEqual(
            encoded_response.status_code,
            200,
            encoded_response.get_data(as_text=True),
        )
        encoded = encoded_response.get_json()
        self.assertEqual(estimated["media_type"], "image")
        self.assertEqual((estimated["width"], estimated["height"]), (96, 96))
        self.assertEqual(estimated["total_units"], 96 * 96 * 3)
        self.assertEqual(estimated["bootstrap_span"], 2048)
        self.assertEqual(estimated["start_unit"], encoded["start_location"])
        self.assertEqual(estimated["footprint"], encoded["footprint"])
        self.assertEqual(estimated["capacity_bytes"], encoded["capacity_bytes"])
        self.assertEqual(
            estimated["remaining_units"],
            estimated["total_units"]
            - estimated["start_unit"]
            - estimated["footprint"],
        )

    def test_layout_estimate_tracks_lsb_capacity_and_rejects_bad_starts(self) -> None:
        """LSB changes update geometry, while reserved and overflowing starts fail."""
        one_lsb = self.estimate(sample_png(), "cover.png", lsb_bits=1).get_json()
        four_lsb = self.estimate(sample_png(), "cover.png", lsb_bits=4).get_json()
        self.assertLess(four_lsb["footprint"], one_lsb["footprint"])
        self.assertGreater(four_lsb["capacity_bytes"], one_lsb["capacity_bytes"])
        larger_payload = self.estimate(
            sample_png(), "cover.png", lsb_bits=4, message="x" * 1000
        ).get_json()
        self.assertGreater(larger_payload["footprint"], four_lsb["footprint"])

        reserved = self.estimate(
            sample_png(), "cover.png", start_unit=2047
        )
        self.assertEqual(reserved.status_code, 400)
        self.assertIn("bootstrap", reserved.get_json()["error"])

        overflowing = self.estimate(
            sample_png(), "cover.png", start_unit=(96 * 96 * 3) - 1
        )
        self.assertEqual(overflowing.status_code, 400)
        self.assertRegex(overflowing.get_json()["error"], r"carrier|footprint")

    def test_wav_layout_estimate_keeps_linear_manual_geometry(self) -> None:
        """WAV estimation remains supported without pretending samples are pixels."""
        response = self.estimate(sample_wav(), "cover.wav", lsb_bits=2)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        estimated = response.get_json()
        self.assertEqual(estimated["media_type"], "audio")
        self.assertIsNone(estimated["width"])
        self.assertIsNone(estimated["height"])
        self.assertEqual(estimated["total_units"], 8000)

    @unittest.skipUnless(
        shutil.which("node"), "Node.js is needed for ES-module helper tests"
    )
    def test_stego_map_coordinate_helpers(self) -> None:
        """The actual browser helpers preserve pixel order, Y origin, and row spans."""
        script = """
          import * as map from './stego_web/static/stego-map-geometry.js';
          const same = (actual, expected, label) => {
            if (JSON.stringify(actual) !== JSON.stringify(expected)) {
              throw new Error(`${label}: ${JSON.stringify(actual)}`);
            }
          };
          same(map.pixelToStartUnit(10, 5, 100, 20), 1530, 'reserved example');
          same(map.pixelToStartUnit(200, 100, 1000, 200), 300600, 'valid example');
          same(map.startUnitToPixel(300600, 1000, 200), {x: 200, y: 100, pixelIndex: 100200, channel: 0}, 'inverse');
          same(map.uvToPixel(0, 1, 100, 20), {x: 0, y: 0}, 'top left');
          same(map.uvToPixel(1, 0, 100, 20), {x: 99, y: 19}, 'bottom right');
          same(map.firstSelectablePixelUnit(2048, 96, 96), 2049, 'bootstrap boundary');
          same(map.carrierRangeToPixelRectangles(29, 12, 10, 10), [
            {x: 9, y: 0, width: 1, height: 1},
            {x: 0, y: 1, width: 4, height: 1},
          ], 'partial rows');
        """
        completed = subprocess.run(
            [str(shutil.which("node")), "--input-type=module", "-e", script],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_png_message_round_trip_recovers_geometry_and_metadata(self) -> None:
        """PNG encoding and receiver-gated decoding expose authenticated data."""
        encoded_response = self.encode(sample_png(), "cover.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["protocol_version"], 2)
        self.assertEqual(encoded["bootstrap_span"], 2048)
        decoded = self.decode(encoded, "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["start_location"], 2048)
        self.assertEqual(report["lsb_bits"], 3)
        self.assertEqual(report["payload"]["metadata"]["team"], "P1-4")
        self.assertEqual(
            base64.b64decode(report["payload"]["user_payload_base64"]),
            b"authenticated message",
        )
        self.assertTrue(report["payload"]["preview_allowed"])

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
        self.assertEqual(
            base64.b64decode(report["payload"]["user_payload_base64"]), payload
        )
        self.assertEqual(report["payload"]["declared_mime"], "audio/wav")

    def test_png_supports_every_lsb_count(self) -> None:
        """The retained 1-8 control maps exactly to protocol LSB counts."""
        for lsb_bits in range(1, 9):
            with self.subTest(lsb_bits=lsb_bits):
                encoded = self.encode(sample_png(), "cover.png", lsb_bits=lsb_bits)
                self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
                report = self.decode(encoded.get_json(), "stego.png").get_json()
                self.assertEqual(report["verdict"], "Authentic")
                self.assertEqual(report["lsb_bits"], lsb_bits)

    def test_wrong_receiver_key_is_payload_missing(self) -> None:
        """A non-recipient cannot open the RSA-OAEP bootstrap."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        wrong_private, _ = generate_rsa_keypair()
        decoded = self.decode(
            encoded, "stego.png", receiver_private=private_pem(wrong_private)
        )
        self.assertEqual(decoded.status_code, 422)
        self.assertEqual(decoded.get_json()["verdict"], "Payload Missing")

    def test_wrong_sender_key_is_signature_invalid(self) -> None:
        """The receiver rejects a packet under an unrelated sender identity."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        _, wrong_public = generate_rsa_keypair()
        decoded = self.decode(
            encoded, "stego.png", sender_public=public_pem(wrong_public)
        )
        self.assertEqual(decoded.status_code, 200)
        self.assertEqual(decoded.get_json()["verdict"], "Signature Invalid")

    def test_changed_preserved_image_bit_is_tampered(self) -> None:
        """A carrier change outside the packet footprint fails the masked hash."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        raw = base64.b64decode(encoded["stego_base64"])
        with Image.open(io.BytesIO(raw)) as image:
            array = np.array(image, dtype=np.uint8, copy=True)
        array.reshape(-1)[-1] ^= np.uint8(0x80)
        changed_output = io.BytesIO()
        Image.fromarray(array, mode="RGB").save(changed_output, format="PNG")
        encoded["stego_base64"] = base64.b64encode(changed_output.getvalue()).decode(
            "ascii"
        )
        decoded = self.decode(encoded, "changed.png")
        self.assertEqual(decoded.status_code, 200)
        self.assertEqual(decoded.get_json()["verdict"], "Tampered")

    def test_mime_mismatch_disables_preview_without_invalidating_signature(self) -> None:
        """A false typed-payload claim remains authenticated but is not rendered."""
        encoded = self.encode(
            sample_png(), "cover.png", payload_mime="image/png"
        ).get_json()
        report = self.decode(encoded, "stego.png").get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertFalse(report["payload"]["type_agrees"])
        self.assertFalse(report["payload"]["preview_allowed"])

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

    def test_upload_limit_returns_json(self) -> None:
        """Flask request-size failures remain machine-readable."""
        client = create_app({"TESTING": True, "MAX_CONTENT_LENGTH": 100}).test_client()
        response = client.post(
            "/decode", data={"stego": (io.BytesIO(b"x" * 200), "file")}
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")


if __name__ == "__main__":
    unittest.main()
