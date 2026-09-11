"""Integration tests for the Flask routes and PNG LSB service."""

from __future__ import annotations

import base64
import io
import unittest
import wave

from PIL import Image

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


if __name__ == "__main__":
    unittest.main()
