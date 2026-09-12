"""Integration tests for the Flask routes and PNG LSB service."""

from __future__ import annotations

import base64
import io
import unittest
import wave

from PIL import Image

from payload_protocol import export_private_key_pem, generate_rsa_keypair
from stego_web import create_app


def sample_png() -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (96, 96), (46, 112, 99)).save(output, format="PNG")
    return output.getvalue()


def sample_wav() -> bytes:
    output = io.BytesIO()
    with wave.open(output, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes((b"\x00\x00" * 8000))
    return output.getvalue()


class WebApplicationTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app({"TESTING": True}).test_client()
        private_key, _ = generate_rsa_keypair()
        self.private_key_pem = export_private_key_pem(private_key, "test-password")

    def test_index_contains_both_workflows(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Encode", response.data)
        self.assertIn(b"Decode and verify", response.data)

    def test_png_encode_and_authentic_decode(self):
        cover = sample_png()
        encoded = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(cover), "cover.png"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct horse battery staple",
                "key_password": "test-password",
                "private_key": (io.BytesIO(self.private_key_pem), "private-key.pem"),
                "lsb_bits": "3",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
        encoded_data = encoded.get_json()

        decoded = self.client.post(
            "/decode",
            data={
                "stego": (
                    io.BytesIO(base64.b64decode(encoded_data["stego_base64"])),
                    "stego.png",
                ),
                "public_key": (
                    io.BytesIO(encoded_data["public_key_pem"].encode("ascii")),
                    "public-key.pem",
                ),
                "original_cover": (io.BytesIO(cover), "cover.png"),
                "start_secret": "correct horse battery staple",
                "lsb_bits": "3",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        self.assertEqual(decoded.get_json()["verdict"], "Authentic")

    def test_wrong_start_secret_has_strict_verdict(self):
        cover = sample_png()
        encoded = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(cover), "cover.png"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct-secret",
                "key_password": "test-password",
                "private_key": (io.BytesIO(self.private_key_pem), "private-key.pem"),
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        ).get_json()

        decoded = self.client.post(
            "/decode",
            data={
                "stego": (
                    io.BytesIO(base64.b64decode(encoded["stego_base64"])),
                    "stego.png",
                ),
                "public_key": (
                    io.BytesIO(encoded["public_key_pem"].encode("ascii")),
                    "public-key.pem",
                ),
                "start_secret": "incorrect-secret",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(decoded.status_code, 422)
        self.assertEqual(decoded.get_json()["verdict"], "Wrong Start Location")

    def test_wav_encode_and_authentic_decode(self):
        cover = sample_wav()
        encoded = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(cover), "cover.wav"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct horse battery staple",
                "key_password": "test-password",
                "private_key": (io.BytesIO(self.private_key_pem), "private-key.pem"),
                "lsb_bits": "2",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
        body = encoded.get_json()

        decoded = self.client.post(
            "/decode",
            data={
                "stego": (io.BytesIO(base64.b64decode(body["stego_base64"])), "stego.wav"),
                "public_key": (io.BytesIO(body["public_key_pem"].encode("ascii")), "public-key.pem"),
                "original_cover": (io.BytesIO(cover), "cover.wav"),
                "start_secret": "correct horse battery staple",
                "lsb_bits": "2",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        self.assertEqual(decoded.get_json()["verdict"], "Authentic")

    def test_key_generation_is_separate_from_encoding(self):
        response = self.client.post(
            "/keys/generate",
            data={"key_password": "setup-password"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", body["private_key_pem"])
        self.assertIn("BEGIN PUBLIC KEY", body["public_key_pem"])

    def test_encode_requires_existing_private_key(self):
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct-secret",
                "key_password": "test-password",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("private_key", response.get_json()["error"])

    def test_png_supports_each_lsb_depth(self):
        for lsb_bits in range(1, 9):
            with self.subTest(lsb_bits=lsb_bits):
                response = self.client.post(
                    "/encode",
                    data={
                        "cover": (io.BytesIO(sample_png()), "cover.png"),
                        "private_key": (io.BytesIO(self.private_key_pem), "private-key.pem"),
                        "team_id": "P1-4",
                        "sender": "Test User",
                        "start_secret": "correct-secret",
                        "key_password": "test-password",
                        "lsb_bits": str(lsb_bits),
                    },
                    content_type="multipart/form-data",
                )
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                self.assertEqual(response.get_json()["lsb_bits"], lsb_bits)

    def test_malformed_png_is_rejected_before_private_key_loading(self):
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(b"\x89PNG\r\n\x1a\ncorrupt"), "broken.png"),
                "private_key": (io.BytesIO(b"not a key"), "private-key.pem"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct-secret",
                "key_password": "test-password",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("PNG", response.get_json()["error"])

    def test_wrong_private_key_password_is_rejected(self):
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "private_key": (io.BytesIO(self.private_key_pem), "private-key.pem"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct-secret",
                "key_password": "wrong-password",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_location_endpoint_matches_encoding_pipeline(self):
        cover = sample_png()
        derived = self.client.post(
            "/location/derive",
            data={
                "cover": (io.BytesIO(cover), "cover.png"),
                "start_secret": "correct-secret",
                "lsb_bits": "4",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(derived.status_code, 200, derived.get_data(as_text=True))
        location = derived.get_json()
        self.assertEqual(location["algorithm"], "PBKDF2-HMAC-SHA256")
        self.assertTrue(location["non_default"])

        encoded = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(cover), "cover.png"),
                "private_key": (io.BytesIO(self.private_key_pem), "private-key.pem"),
                "team_id": "P1-4",
                "sender": "Test User",
                "start_secret": "correct-secret",
                "key_password": "test-password",
                "lsb_bits": "4",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
        self.assertEqual(encoded.get_json()["start_location"], location["start_location"])


if __name__ == "__main__":
    unittest.main()
