"""Run with: python -m unittest -v"""

import hashlib
import json
import struct
import unittest
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec

from payload_protocol import (
    build_verification_packet,
    create_payload,
    decode_payload,
    detect_media_type,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    sign_payload,
    unpack_verification_packet,
    verify_signature,
    verify_verification_packet,
)


class PayloadProtocolTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.private_key, cls.public_key = (
            generate_rsa_keypair()
        )

        # Minimal byte sequences containing the correct
        # PNG/WAV signatures.
        #
        # These are sufficient for testing automatic
        # media-type detection.

        cls.png_cover = (
            b"\x89PNG\r\n\x1a\n"
            b"example PNG test bytes"
        )

        cls.wav_cover = (
            b"RIFF"
            b"\x24\x00\x00\x00"
            b"WAVE"
            b"example WAV test bytes"
        )

        # FR3 automatically detects this as an image.
        cls.payload_bytes = create_payload(
            cover_bytes=cls.png_cover,
            team_id="P1-4",
            sender="Sitt",
        )

        cls.payload = decode_payload(
            cls.payload_bytes
        )

        # FR4
        cls.signature = sign_payload(
            cls.payload_bytes,
            cls.private_key,
        )

        cls.packet = build_verification_packet(
            cls.payload_bytes,
            cls.signature,
        )


    # ======================================================
    # FR3 - MEDIA TYPE DETECTION
    # ======================================================

    def test_detect_png_as_image(self):

        self.assertEqual(
            detect_media_type(
                self.png_cover
            ),
            "image",
        )


    def test_detect_wav_as_audio(self):

        self.assertEqual(
            detect_media_type(
                self.wav_cover
            ),
            "audio",
        )


    def test_reject_unsupported_media(self):

        with self.assertRaises(ValueError):

            detect_media_type(
                b"This is not PNG or WAV"
            )


    # ======================================================
    # FR3 - PAYLOAD GENERATION
    # ======================================================

    def test_payload_contains_required_fields(self):

        required_fields = {
            "media_id",
            "media_type",
            "timestamp",
            "media_hash",
            "nonce",
            "metadata",
        }

        self.assertEqual(
            set(self.payload.keys()),
            required_fields,
        )

        self.assertEqual(
            self.payload["media_type"],
            "image",
        )

        self.assertEqual(
            self.payload["metadata"]["team_id"],
            "P1-4",
        )

        self.assertEqual(
            self.payload["metadata"]["sender"],
            "Sitt",
        )

        self.assertEqual(
            self.payload["media_hash"],
            hashlib.sha256(
                self.png_cover
            ).hexdigest(),
        )


    def test_image_media_id_prefix(self):

        self.assertTrue(
            self.payload[
                "media_id"
            ].startswith("IMG-")
        )

        self.assertEqual(
            len(
                self.payload["media_id"]
            ),
            12,
        )


    def test_audio_payload_is_automatic(self):

        audio_payload = decode_payload(
            create_payload(
                cover_bytes=self.wav_cover,
                team_id="P1-4",
                sender="Sitt",
            )
        )

        self.assertEqual(
            audio_payload["media_type"],
            "audio",
        )

        self.assertTrue(
            audio_payload[
                "media_id"
            ].startswith("AUD-")
        )

        self.assertEqual(
            audio_payload["media_hash"],
            hashlib.sha256(
                self.wav_cover
            ).hexdigest(),
        )


    def test_compact_canonical_json(self):

        expected = json.dumps(
            self.payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        self.assertEqual(
            self.payload_bytes,
            expected,
        )


    def test_timestamp_format_and_nonce(self):

        # Confirm the timestamp has the expected UTC format.
        datetime.strptime(
            self.payload["timestamp"],
            "%Y-%m-%dT%H:%M:%SZ",
        )

        # 16 bytes = 128 bits
        self.assertEqual(
            len(
                bytes.fromhex(
                    self.payload["nonce"]
                )
            ),
            16,
        )

        fresh_payload = decode_payload(
            create_payload(
                cover_bytes=self.png_cover,
                team_id="P1-4",
                sender="Sitt",
            )
        )

        # Fresh payload should get a new nonce.
        self.assertNotEqual(
            fresh_payload["nonce"],
            self.payload["nonce"],
        )

        # Fresh payload should also get a new media ID.
        self.assertNotEqual(
            fresh_payload["media_id"],
            self.payload["media_id"],
        )


    def test_required_metadata_validation(self):

        with self.assertRaises(ValueError):

            create_payload(
                self.png_cover,
                "",
                "Sitt",
            )

        with self.assertRaises(ValueError):

            create_payload(
                self.png_cover,
                "P1-4",
                "",
            )


    def test_invalid_payload_input_types(self):

        with self.assertRaises(TypeError):

            create_payload(
                "not bytes",
                "P1-4",
                "Sitt",
            )

        with self.assertRaises(TypeError):

            create_payload(
                self.png_cover,
                123,
                "Sitt",
            )

        with self.assertRaises(TypeError):

            create_payload(
                self.png_cover,
                "P1-4",
                123,
            )


    def test_decode_payload(self):

        self.assertEqual(
            decode_payload(
                self.payload_bytes
            ),
            self.payload,
        )

        invalid_payloads = (
            b"{",
            b"\xff",
            b"[]",
            b"null",
            b'"text"',
        )

        for invalid in invalid_payloads:

            with self.subTest(
                invalid=invalid
            ):

                with self.assertRaises(
                    ValueError
                ):

                    decode_payload(
                        invalid
                    )


    # ======================================================
    # FR4 - DIGITAL SIGNATURE
    # ======================================================

    def test_signature_valid(self):

        self.assertTrue(
            verify_signature(
                self.payload_bytes,
                self.signature,
                self.public_key,
            )
        )


    def test_modified_payload_invalidates_signature(self):

        changed_payload = (
            bytes(
                [
                    self.payload_bytes[0] ^ 1
                ]
            )
            + self.payload_bytes[1:]
        )

        self.assertFalse(
            verify_signature(
                changed_payload,
                self.signature,
                self.public_key,
            )
        )


    def test_modified_signature_is_invalid(self):

        changed_signature = (
            self.signature[:-1]
            + bytes(
                [
                    self.signature[-1] ^ 1
                ]
            )
        )

        self.assertFalse(
            verify_signature(
                self.payload_bytes,
                changed_signature,
                self.public_key,
            )
        )


    def test_wrong_public_key(self):

        _, other_public_key = (
            generate_rsa_keypair()
        )

        self.assertFalse(
            verify_signature(
                self.payload_bytes,
                self.signature,
                other_public_key,
            )
        )


    def test_rsa_pss_signature_length_and_verification(self):

        
        self.assertEqual(
            len(self.signature),
            256,
        )

        # RSA-PSS uses randomness
        another_signature = sign_payload(
            self.payload_bytes,
            self.private_key,
        )

        self.assertTrue(
            verify_signature(
                self.payload_bytes,
                another_signature,
                self.public_key,
            )
        )


    # ======================================================
    # PACKET / INTEGRATION
    # ======================================================

    def test_packet_binary_layout(self):

        payload_length = struct.unpack(
            ">I",
            self.packet[:4],
        )[0]

        self.assertEqual(
            payload_length,
            len(self.payload_bytes),
        )

        self.assertEqual(
            self.packet[
                4:4 + payload_length
            ],
            self.payload_bytes,
        )

        self.assertEqual(
            len(self.packet),
            4
            + len(self.payload_bytes)
            + 256,
        )


    def test_unpack_packet(self):

        payload_bytes, signature = (
            unpack_verification_packet(
                self.packet,
                self.public_key,
            )
        )

        self.assertEqual(
            payload_bytes,
            self.payload_bytes,
        )

        self.assertEqual(
            signature,
            self.signature,
        )


    def test_complete_packet_verification(self):

        self.assertEqual(
            verify_verification_packet(
                self.packet,
                self.public_key,
            ),
            (
                True,
                "Signature Valid",
                self.payload,
            ),
        )


    def test_packet_payload_bit_flip(self):

        changed = (
            self.packet[:4]
            + bytes(
                [
                    self.packet[4] ^ 1
                ]
            )
            + self.packet[5:]
        )

        self.assertEqual(
            verify_verification_packet(
                changed,
                self.public_key,
            ),
            (
                False,
                "Signature Invalid",
                None,
            ),
        )


    def test_packet_signature_bit_flip(self):

        changed = (
            self.packet[:-1]
            + bytes(
                [
                    self.packet[-1] ^ 1
                ]
            )
        )

        self.assertEqual(
            verify_verification_packet(
                changed,
                self.public_key,
            ),
            (
                False,
                "Signature Invalid",
                None,
            ),
        )


    def test_truncated_packets(self):

        for length in range(
            len(self.packet)
        ):

            with self.subTest(
                length=length
            ):

                valid, message, payload = (
                    verify_verification_packet(
                        self.packet[:length],
                        self.public_key,
                    )
                )

                self.assertFalse(
                    valid
                )

                self.assertIsNone(
                    payload
                )

                if length < 260:

                    self.assertEqual(
                        message,
                        "Payload missing or incomplete",
                    )

                else:

                    self.assertEqual(
                        message,
                        "Payload missing or corrupted",
                    )


    def test_oversized_payload_length(self):

        changed_packet = (
            struct.pack(
                ">I",
                0xFFFFFFFF,
            )
            + self.packet[4:]
        )

        self.assertEqual(
            verify_verification_packet(
                changed_packet,
                self.public_key,
            ),
            (
                False,
                "Payload missing or corrupted",
                None,
            ),
        )


    def test_trailing_bytes_are_ignored(self):

        packet_with_extra_data = (
            self.packet
            + b"unused extracted bytes"
        )

        self.assertEqual(
            verify_verification_packet(
                packet_with_extra_data,
                self.public_key,
            ),
            (
                True,
                "Signature Valid",
                self.payload,
            ),
        )


    def test_signed_invalid_json(self):

        invalid_contents = (
            b"",
            b"{",
            b"\xff",
            b"[]",
            b"null",
            b'"text"',
        )

        for content in invalid_contents:

            with self.subTest(
                content=content
            ):

                signature = sign_payload(
                    content,
                    self.private_key,
                )

                packet = build_verification_packet(
                    content,
                    signature,
                )

                self.assertEqual(
                    verify_verification_packet(
                        packet,
                        self.public_key,
                    ),
                    (
                        False,
                        "Payload Missing or Corrupted",
                        None,
                    ),
                )


    # ======================================================
    # PEM KEY TESTS
    # ======================================================

    def test_pem_round_trip(self):

        password = (
            "INF2005-demo-password"
        )

        private_pem = (
            export_private_key_pem(
                self.private_key,
                password,
            )
        )

        public_pem = (
            export_public_key_pem(
                self.public_key,
            )
        )

        loaded_private = (
            load_private_key_pem(
                private_pem,
                password,
            )
        )

        loaded_public = (
            load_public_key_pem(
                public_pem
            )
        )

        signature = sign_payload(
            self.payload_bytes,
            loaded_private,
        )

        self.assertTrue(
            verify_signature(
                self.payload_bytes,
                signature,
                loaded_public,
            )
        )


    def test_wrong_private_key_password(self):

        private_pem = (
            export_private_key_pem(
                self.private_key,
                "correct-password",
            )
        )

        with self.assertRaises(
            ValueError
        ):

            load_private_key_pem(
                private_pem,
                "wrong-password",
            )


    def test_invalid_pem_and_non_rsa_keys(self):

        with self.assertRaises(
            ValueError
        ):

            load_public_key_pem(
                b"not a PEM key"
            )

        ec_private_key = (
            ec.generate_private_key(
                ec.SECP256R1()
            )
        )

        with self.assertRaises(
            TypeError
        ):

            export_private_key_pem(
                ec_private_key,
                "password",
            )

        with self.assertRaises(
            TypeError
        ):

            export_public_key_pem(
                ec_private_key.public_key()
            )


if __name__ == "__main__":
    unittest.main()