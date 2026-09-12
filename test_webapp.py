"""Integration tests for the Flask routes and PNG LSB service."""

from __future__ import annotations

import base64
import io
import json
import struct
import unittest
import wave

from PIL import Image

from payload_protocol import (
    build_verification_packet, export_private_key_pem, export_public_key_pem,
    generate_rsa_keypair, sign_payload,
)
from stego_web import create_app
from stego_web.routes import stego_registry
from stego_web.services.steganography import FRAME_HEADER, FRAME_MAGIC


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
        self.assertIn(b"gsap@3.15", response.data)
        self.assertIn(b"motion.js", response.data)

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
        # A missing header cannot prove whether the secret is wrong or no payload exists.
        self.assertEqual(decoded.get_json()["verdict"], "Payload Missing")
        self.assertIn("secret", decoded.get_json()["message"])

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


class VerificationPipelineTests(unittest.TestCase):
    """Current-encoder interoperability and failures, for both mandatory formats."""

    @classmethod
    def setUpClass(cls):
        cls.client = create_app({"TESTING": True}).test_client()
        cls.private, public = generate_rsa_keypair()
        cls.private_pem = export_private_key_pem(cls.private, "test-password")
        cls.public_pem = export_public_key_pem(public)
        cls.covers = {"image": sample_png(), "audio": sample_wav()}
        cls.encoded = {}
        for kind, cover in cls.covers.items():
            for bits in range(1, 9):
                response = cls.client.post('/encode', data={
                    'cover': (io.BytesIO(cover), 'cover'),
                    'private_key': (io.BytesIO(cls.private_pem), 'private.pem'),
                    'key_password': 'test-password', 'team_id': 'P1-4', 'sender': 'Tester',
                    'start_secret': 'shared-secret', 'lsb_bits': str(bits),
                    'metadata': '{"project":"verification","sequence":1}',
                    'secret_message': 'message preserved',
                })
                if response.status_code != 200:
                    raise AssertionError(response.get_data(as_text=True))
                cls.encoded[kind, bits] = response.get_json()

    def verify(self, kind, *, bits=1, data=None, selected='auto', secret='shared-secret',
               public=None, original=True, media_type='auto'):
        body = {
            'stego': (io.BytesIO(data if data is not None else base64.b64decode(
                self.encoded[kind, bits]['stego_base64'])), 'received.' + ('png' if kind == 'image' else 'wav')),
            'public_key': (io.BytesIO(self.public_pem if public is None else public), 'public.pem'),
            'start_secret': secret, 'lsb_bits': str(selected), 'media_type': media_type,
        }
        if original is not False:
            body['original_cover'] = (io.BytesIO(self.covers[kind] if original is True else original), 'original')
        response = self.client.post('/decode', data=body)
        self.assertLess(response.status_code, 500, response.get_data(as_text=True))
        self.assertTrue(response.is_json)
        return response.get_json()

    def packet(self, kind):
        raw = base64.b64decode(self.encoded[kind, 1]['stego_base64'])
        return stego_registry.for_media(kind).extract(raw, 1, 'shared-secret').packet

    def embed_packet(self, kind, packet):
        return stego_registry.for_media(kind).embed(self.covers[kind], packet, 1, 'shared-secret').media_bytes

    def rewrite_carrier(self, kind, raw, mutate):
        engine = stego_registry.for_media(kind)
        output = io.BytesIO()
        if kind == 'image':
            array = engine._load_png(raw)
            mutate(array.reshape(-1))
            Image.fromarray(array).save(output, format='PNG')
        else:
            params, frames = engine._load_pcm(raw)
            import numpy as np
            array = np.frombuffer(frames, dtype=np.uint8).copy()
            mutate(array)
            with wave.open(output, 'wb') as wav:
                wav.setparams(params)
                wav.writeframes(array.tobytes())
        return output.getvalue()

    def test_current_encoder_roundtrips_all_lsb_depths_for_both_media(self):
        for kind in self.covers:
            for bits in range(1, 9):
                for selected in ('auto', bits):
                    with self.subTest(kind=kind, bits=bits, selected=selected):
                        result = self.verify(kind, bits=bits, selected=selected)
                        self.assertEqual(result['verdict'], 'Authentic', result)
                        self.assertTrue(result['signature_valid'])
                        self.assertTrue(result['integrity_valid'])
                        self.assertEqual(result['lsb_bits'], bits)
                        self.assertEqual(result['start_location'], self.encoded[kind, bits]['start_location'])
                        self.assertEqual(result['stored_hash'], result['computed_hash'])
                        self.assertEqual(result['expected_media_hash'], result['received_media_hash'])
                        self.assertEqual(result['signature_size'], 256)
                        self.assertEqual(result['payload']['metadata']['secret_message'], 'message preserved')
                        self.assertNotIn('private_key_pem', result)

    def test_changed_media_outside_packet_is_tampered(self):
        for kind in self.covers:
            with self.subTest(kind=kind):
                raw = base64.b64decode(self.encoded[kind, 1]['stego_base64'])
                start = self.encoded[kind, 1]['start_location']
                def mutate(values):
                    values[(start - 1) % values.size] ^= 128
                changed = self.rewrite_carrier(kind, raw, mutate)
                result = self.verify(kind, data=changed)
                self.assertEqual(result['verdict'], 'Tampered', result)
                self.assertTrue(result['signature_valid'])
                self.assertTrue(result['media_hash_valid'])
                self.assertFalse(result['received_media_valid'])

    def test_wrong_key_and_corrupt_signature(self):
        _, wrong_public = generate_rsa_keypair()
        for kind in self.covers:
            with self.subTest(kind=kind):
                result = self.verify(kind, public=export_public_key_pem(wrong_public))
                self.assertEqual(result['verdict'], 'Signature Invalid')
                self.assertFalse(result['signature_valid'])
                packet = self.packet(kind)
                corrupted = packet[:-1] + bytes([packet[-1] ^ 1])
                result = self.verify(kind, data=self.embed_packet(kind, corrupted))
                self.assertEqual(result['verdict'], 'Signature Invalid')

    def test_unsigned_payload_change_fails_signature(self):
        for kind in self.covers:
            packet = bytearray(self.packet(kind))
            packet[10] ^= 1
            result = self.verify(kind, data=self.embed_packet(kind, bytes(packet)))
            self.assertEqual(result['verdict'], 'Signature Invalid')

    def test_missing_payload_wrong_secret_and_wrong_lsb_are_explained(self):
        for kind in self.covers:
            for kwargs in ({'data': self.covers[kind]}, {'secret': 'wrong-secret'}, {'selected': 8}):
                with self.subTest(kind=kind, kwargs=tuple(kwargs)):
                    result = self.verify(kind, **kwargs)
                    self.assertEqual(result['verdict'], 'Payload Missing', result)
                    self.assertIsNone(result['signature_valid'])
                    self.assertIn('secret/LSB', result['message'])

    def test_no_original_and_wrong_original(self):
        for kind in self.covers:
            result = self.verify(kind, original=False)
            self.assertEqual(result['verdict'], 'Cannot Verify')
            self.assertTrue(result['signature_valid'])
            self.assertIsNone(result['integrity_valid'])
            result = self.verify(kind, original=self.covers[kind] + b'changed')
            self.assertEqual(result['verdict'], 'Tampered')
            self.assertFalse(result['media_hash_valid'])

    def test_invalid_truncated_media_and_key(self):
        for kind in self.covers:
            for raw in (b'not media', self.covers[kind][:20], self.covers[kind][:-10]):
                with self.subTest(kind=kind, size=len(raw)):
                    self.assertEqual(self.verify(kind, data=raw)['verdict'], 'Cannot Verify')
            self.assertEqual(self.verify(kind, public=b'not a key')['verdict'], 'Cannot Verify')
            opposite = 'audio' if kind == 'image' else 'image'
            self.assertEqual(self.verify(kind, media_type=opposite)['verdict'], 'Cannot Verify')

    def test_signed_malformed_schema_and_json_cannot_verify(self):
        for kind in self.covers:
            bad_hash = dict(self.encoded[kind, 1]['payload'], media_hash='non-ASCII \u2603')
            missing = dict(self.encoded[kind, 1]['payload'])
            missing.pop('nonce')
            for contents in (b'{', b'[]', b'{}', json.dumps(missing).encode(), json.dumps(bad_hash).encode()):
                packet = build_verification_packet(contents, sign_payload(contents, self.private))
                result = self.verify(kind, data=self.embed_packet(kind, packet))
                self.assertEqual(result['verdict'], 'Cannot Verify', result)
                self.assertTrue(result['signature_valid'])

    def test_bad_lengths_versions_and_truncated_packets(self):
        for kind in self.covers:
            packet = self.packet(kind)
            for broken in (packet[:20], struct.pack('>I', 0xFFFFFFFF) + packet[4:], packet + b'extra'):
                result = self.verify(kind, data=self.embed_packet(kind, broken))
                self.assertEqual(result['verdict'], 'Cannot Verify', result)
            raw = base64.b64decode(self.encoded[kind, 1]['stego_base64'])
            start = self.encoded[kind, 1]['start_location']
            engine = stego_registry.for_media(kind)
            for magic, length in ((FRAME_MAGIC, 0xFFFFFFFF), (FRAME_MAGIC, 0),
                                  (FRAME_MAGIC, 1_000_000), (b'STG2', len(packet))):
                header = FRAME_HEADER.pack(magic, 1, length)
                def mutate(values):
                    values[:] = engine.lsb_encoder.write(values, header, start, 1)
                changed = self.rewrite_carrier(kind, raw, mutate)
                self.assertEqual(self.verify(kind, data=changed)['verdict'], 'Cannot Verify')

    def test_upload_limit_returns_json(self):
        client = create_app({'TESTING': True, 'MAX_CONTENT_LENGTH': 100}).test_client()
        response = client.post('/decode', data={'stego': (io.BytesIO(b'x' * 200), 'file')})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()['verdict'], 'Cannot Verify')


if __name__ == "__main__":
    unittest.main()
