"""Run with python -m unittest -v."""

import hashlib
import json
import struct
import unittest
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from payload_protocol import (
    create_payload,
    export_key_pem,
    generate_rsa_keypair,
    load_key_pem,
    pack_verification_packet,
    unpack_and_verify_packet,
)


class PayloadProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = generate_rsa_keypair()
        cls.cover = b"original cover\x00\xff"
        cls.metadata = {"author": "Alice", "nested": {"z": [1, True], "a": "\u732b"}}
        cls.payload_bytes = create_payload("media-123", cls.cover, cls.metadata)
        cls.payload = json.loads(cls.payload_bytes)
        cls.packet = pack_verification_packet(cls.payload_bytes, cls.private_key)

    def verify(self, packet, cover=None):
        return unpack_and_verify_packet(packet, self.public_key, cover)

    def test_happy_path_and_exact_metadata(self):
        self.assertEqual(self.verify(self.packet, self.cover), (True, "Authentic", self.payload))
        self.assertEqual(self.payload["media_id"], "media-123")
        self.assertEqual(self.payload["metadata"], self.metadata)
        self.assertEqual(self.payload["cover_hash"], hashlib.sha256(self.cover).hexdigest())

    def test_canonical_json_timestamp_and_nonce(self):
        expected = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(self.payload_bytes, expected)
        self.assertEqual(datetime.fromisoformat(self.payload["timestamp"]).utcoffset(), timedelta(0))
        self.assertEqual(len(bytes.fromhex(self.payload["nonce"])), 16)
        fresh = json.loads(create_payload("media-123", self.cover))
        self.assertNotEqual(fresh["nonce"], self.payload["nonce"])

    def test_optional_metadata(self):
        self.assertNotIn("metadata", json.loads(create_payload("id", b"")))
        self.assertEqual(json.loads(create_payload("id", b"", {}))["metadata"], {})

    def test_binary_layout_and_deterministic_signature(self):
        length = struct.unpack(">I", self.packet[:4])[0]
        self.assertEqual(length, len(self.payload_bytes))
        self.assertEqual(self.packet[4:4 + length], self.payload_bytes)
        self.assertEqual(len(self.packet), 4 + length + 256)
        self.public_key.verify(self.packet[-256:], self.payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(self.packet, pack_verification_packet(self.payload_bytes, self.private_key))

    def test_tampered_cover(self):
        changed = bytes([self.cover[0] ^ 1]) + self.cover[1:]
        self.assertEqual(self.verify(self.packet, changed), (False, "Tampered", self.payload))
        self.assertEqual(self.verify(self.packet), (True, "Authentic", self.payload))

    def test_empty_cover_is_checked(self):
        self.assertEqual(self.verify(self.packet, b""), (False, "Tampered", self.payload))
        payload = create_payload("empty", b"")
        packet = pack_verification_packet(payload, self.private_key)
        self.assertEqual(self.verify(packet, b"")[0:2], (True, "Authentic"))

    def test_signature_bit_flip(self):
        changed = self.packet[:-1] + bytes([self.packet[-1] ^ 1])
        self.assertEqual(self.verify(changed), (False, "Signature Invalid", None))

    def test_payload_bit_flip(self):
        changed = self.packet[:4] + bytes([self.packet[4] ^ 1]) + self.packet[5:]
        self.assertEqual(self.verify(changed), (False, "Signature Invalid", None))

    def test_wrong_public_key(self):
        _, other_public = generate_rsa_keypair()
        self.assertEqual(unpack_and_verify_packet(self.packet, other_public), (False, "Signature Invalid", None))

    def test_all_truncations(self):
        for length in range(len(self.packet)):
            with self.subTest(length=length):
                message = "Payload Missing or Incomplete" if length < 260 else "Payload Missing or Corrupted"
                self.assertEqual(self.verify(self.packet[:length]), (False, message, None))

    def test_oversized_length(self):
        packet = struct.pack(">I", 0xFFFFFFFF) + self.packet[4:]
        self.assertEqual(self.verify(packet), (False, "Payload Missing or Corrupted", None))

    def test_trailing_cover_bytes(self):
        self.assertEqual(self.verify(self.packet + b"unused extracted bytes", self.cover), (True, "Authentic", self.payload))

    def test_signed_invalid_json(self):
        for content in (b"", b"{", b"\xff", b"[]", b"null", b'"text"'):
            with self.subTest(content=content):
                packet = pack_verification_packet(content, self.private_key)
                self.assertEqual(self.verify(packet), (False, "Payload Missing or Corrupted", None))

    def test_missing_cover_hash(self):
        packet = pack_verification_packet(b"{}", self.private_key)
        self.assertEqual(self.verify(packet, self.cover), (False, "Payload Missing or Corrupted", None))

    def test_pem_round_trip(self):
        private = load_key_pem(export_key_pem(self.private_key))
        public = load_key_pem(export_key_pem(self.public_key))
        packet = pack_verification_packet(self.payload_bytes, private)
        self.assertEqual(unpack_and_verify_packet(packet, public, self.cover), (True, "Authentic", self.payload))

    def test_invalid_pem_and_non_rsa_keys(self):
        with self.assertRaises(ValueError):
            load_key_pem(b"not a PEM key")
        with self.assertRaises(TypeError):
            export_key_pem(ec.generate_private_key(ec.SECP256R1()))

    def test_non_default_key_size(self):
        private, public = generate_rsa_keypair(3072)
        packet = pack_verification_packet(self.payload_bytes, private)
        self.assertEqual(len(packet), 4 + len(self.payload_bytes) + 384)
        self.assertEqual(unpack_and_verify_packet(packet, public, self.cover), (True, "Authentic", self.payload))

    def test_invalid_payload_inputs(self):
        with self.assertRaises(TypeError):
            create_payload(123, self.cover)
        with self.assertRaises(TypeError):
            create_payload("id", self.cover, [])
        with self.assertRaises(ValueError):
            create_payload("id", self.cover, {"invalid": float("nan")})


if __name__ == "__main__":
    unittest.main()
