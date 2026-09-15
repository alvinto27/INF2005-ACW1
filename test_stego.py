import hashlib
import struct
import unittest
import wave
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np
from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from stego import *
from stego.constants import MEDIA_ID_SIZE
from stego.bits import encode_protocol_field
from stego.crypto import sign_bytes, verify_signature
from stego.layout import build_embedding_layout
from stego.packet import serialized_record_length


SIGNING_PRIVATE_KEY, SENDER_PUBLIC_KEY = generate_rsa_keypair()
RECEIVER_PRIVATE_KEY, RECEIVER_PUBLIC_KEY = generate_rsa_keypair()
OTHER_PRIVATE_KEY, OTHER_PUBLIC_KEY = generate_rsa_keypair()
PRIVATE_KEY = SIGNING_PRIVATE_KEY
PUBLIC_KEY = SENDER_PUBLIC_KEY


def carrier(size=24000):
    return np.arange(size, dtype=np.uint8)


def payload_length(user_payload=b"hello", metadata=b"{}"):
    media_id_length = len("IMG-" + "0" * 32)
    return serialized_record_length(media_id_length, len(user_payload), len(metadata))


def encode_image_carrier(source=None, start=2048, k=3, user_payload=b"hello", metadata=b"{}"):
    if source is None:
        source = carrier()
    context = struct.pack(">II", source.size // 3, 1)
    return encode_carrier(source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, start, k, user_payload, metadata), context


def raw_bootstrap(version: int, lsb_count: int, start_unit: int, ciphertext_length: int, session_key: bytes, aead_nonce: bytes, extra: bytes = b"") -> bytes:
    plaintext = (
        struct.pack(">BB", version, lsb_count)
        + start_unit.to_bytes(8, "big")
        + ciphertext_length.to_bytes(8, "big")
        + session_key
        + aead_nonce
        + extra
    )
    return seal_to_public_key(plaintext, RECEIVER_PUBLIC_KEY)


def bootstrap_fields_from_carrier(encoded: np.ndarray) -> BootstrapFields:
    span = bootstrap_span(RECEIVER_PRIVATE_KEY)
    envelope_bits = read_lsb_bits(encoded[:span], span, BOOTSTRAP_LSB_COUNT)
    envelope = bit_sequence_to_bytes(envelope_bits)
    return parse_bootstrap(open_with_private_key(envelope, RECEIVER_PRIVATE_KEY))


def reseal_bootstrap(fields: BootstrapFields, version: int | None = None, lsb_count: int | None = None, start_unit: int | None = None, ciphertext_length: int | None = None) -> bytes:
    return raw_bootstrap(
        fields.version if version is None else version,
        fields.lsb_count if lsb_count is None else lsb_count,
        fields.start_unit if start_unit is None else start_unit,
        fields.ciphertext_length if ciphertext_length is None else ciphertext_length,
        fields.session_key,
        fields.aead_nonce,
    )


def embedded_bit_flip(encoded, start, k, bit_offset):
    result = encoded.copy()
    unit_offset, within = divmod(bit_offset, k)
    result[start + unit_offset] ^= np.uint8(1 << (k - 1 - within))
    return result


def decode_pcm_samples(frame_bytes: bytes, sample_width: int) -> list[int]:
    return [
        int.from_bytes(frame_bytes[offset:offset + sample_width], "little", signed=True)
        for offset in range(0, len(frame_bytes), sample_width)
    ]


class TestMaskedStego(unittest.TestCase):
    def test_constants_and_minimal_media_contexts(self) -> None:
        self.assertEqual(MEDIA_HASH_DOMAIN, b"INF2005-ACW1\x00MEDIA-HASH\x00")
        self.assertEqual(SIGNING_DOMAIN, b"INF2005-ACW1\x00SIGN\x00")
        self.assertEqual(encode_png_media_context((7, 11, 3)), struct.pack(">II", 11, 7))
        wav_data = WavPcmData(2, 2, 44100, 3, bytes(12))
        self.assertEqual(encode_wav_media_context(wav_data), struct.pack(">HBIQ", 2, 2, 44100, 3))

    def test_payload_binary_round_trip_and_utf8_metadata(self):
        record = PayloadRecord(
            "IMG-test",
            1_700_000_000,
            bytes(range(16)),
            bytes(range(32)),
            b"\x00\xff\x80binary\x00",
            "author: 张三".encode(),
        )
        encoded = serialize_payload(record)
        self.assertEqual(parse_payload(encoded), record)
        with self.assertRaisesRegex(ValueError, "metadata must contain valid UTF-8"):
            PayloadRecord("IMG-test", 1, bytes(16), bytes(32), b"", b"\xff")
        with self.assertRaisesRegex(ValueError, "trailing bytes"):
            parse_payload(encoded + b"x")

    def test_payload_record_fixed_width_overhead(self) -> None:
        record = PayloadRecord(
            "IMG-" + "0" * 32,
            1_700_000_000,
            bytes(range(16)),
            bytes(range(32)),
            b"hello",
            b"{}",
        )
        encoded = serialize_payload(record)
        self.assertEqual(len(encoded), 109 + 5 + 2)
        self.assertEqual(parse_payload(encoded), record)

    def test_payload_record_length_above_uint32_is_u64(self) -> None:
        large_length = 1 << 32
        self.assertEqual(
            serialized_record_length(MEDIA_ID_SIZE, large_length, 0),
            73 + MEDIA_ID_SIZE + large_length,
        )
        media_id = b"IMG-" + b"0" * 32
        declared = (
            bytes((len(media_id),))
            + media_id
            + bytes(8 + 16 + 32)
            + large_length.to_bytes(8, "big")
        )
        with self.assertRaisesRegex(ValueError, "truncated in user payload"):
            parse_payload(declared)
        declared_metadata = (
            bytes((len(media_id),))
            + media_id
            + bytes(8 + 16 + 32)
            + (0).to_bytes(8, "big")
            + (1).to_bytes(8, "big")
        )
        with self.assertRaisesRegex(ValueError, "truncated in metadata"):
            parse_payload(declared_metadata)

    def test_serialized_record_length_field_boundaries(self) -> None:
        with self.assertRaisesRegex(ValueError, "media_id UTF-8 length must be between 1 and 255 bytes"):
            serialized_record_length(256, 0, 0)
        self.assertEqual(
            serialized_record_length(255, 0, 0),
            73 + 255,
        )
        for user_payload_length, metadata_length in ((2**64, 0), (0, 2**64)):
            with self.subTest(user_payload_length=user_payload_length, metadata_length=metadata_length):
                with self.assertRaisesRegex(ValueError, "must fit in 8 bytes"):
                    serialized_record_length(MEDIA_ID_SIZE, user_payload_length, metadata_length)

    def test_payload_record_timestamp_u64_boundaries(self) -> None:
        with self.assertRaisesRegex(ValueError, "timestamp must fit in 8 bytes"):
            PayloadRecord("IMG-test", 2**64, bytes(16), bytes(32), b"", b"")
        record = PayloadRecord("IMG-test", 2**64 - 1, bytes(16), bytes(32), b"", b"")
        self.assertEqual(parse_payload(serialize_payload(record)), record)

    def test_power_of_two_carrier_round_trip(self) -> None:
        source = carrier(65536)
        context = struct.pack(">II", source.size, 1)
        encoded, layout, payload = encode_carrier(
            source,
            IMAGE_MEDIA_CODE,
            context,
            PRIVATE_KEY,
            RECEIVER_PUBLIC_KEY,
            bootstrap_span(RECEIVER_PUBLIC_KEY),
            3,
            b"power-of-two width",
            b"",
        )
        result = decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
        self.assertEqual(result.verdict, "Authentic")
        self.assertEqual(result.payload, payload)

    def test_masked_media_hash_has_exact_approved_preimage(self):
        source = np.array([0xFF, 0xA5, 0x5A, 0x00], dtype=np.uint8)
        expected_masked = source.copy()
        expected_masked[1:3] &= np.uint8(0xF8)
        preimage = (
            MEDIA_HASH_DOMAIN
            + struct.pack(">BB", IMAGE_MEDIA_CODE, 3)
            + b"\x00\x00\x00\x00\x00\x00\x00\x04"
            + b"\x00\x00\x00\x00\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00\x00\x00\x00\x02"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + expected_masked.tobytes()
        )
        self.assertEqual(len(preimage), 62)
        self.assertEqual(calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 3, 1, 2, 0), hashlib.sha256(preimage).digest())
        self.assertTrue(np.array_equal(source, np.array([0xFF, 0xA5, 0x5A, 0x00], dtype=np.uint8)))

    def test_signing_input_has_exact_approved_bytes(self):
        layout = EmbeddingLayout(1000, 13, 300, 3, 5, 0, 0)
        payload = b"abcde"
        expected = (
            SIGNING_DOMAIN
            + struct.pack(">BBB", 2, IMAGE_MEDIA_CODE, 3)
            + b"\x00\x00\x00\x00\x00\x00\x03\xe8"
            + b"\x00\x00\x00\x00\x00\x00\x00\x0d"
            + b"\x00\x00\x00\x00\x00\x00\x01\x2c"
            + b"\x00\x00\x00\x00\x00\x00\x00\x05"
            + b"context"
            + payload
        )
        self.assertEqual(len(expected), 65)
        self.assertEqual(encode_signing_input(IMAGE_MEDIA_CODE, b"context", layout, payload), expected)

    def test_preserved_bit_count_accounts_for_bootstrap(self) -> None:
        self.assertEqual(preserved_bit_count(10000, 500, 3, 0), 78500)
        self.assertEqual(preserved_bit_count(10000, 500, 3, 2048), 76452)

    def test_preserved_bit_count_bootstrap_cost_is_span(self) -> None:
        for lsb_count in (1, 3, 8):
            with self.subTest(lsb_count=lsb_count):
                without_bootstrap = preserved_bit_count(10000, 500, lsb_count, 0)
                with_bootstrap = preserved_bit_count(10000, 500, lsb_count, 2048)
                self.assertEqual(without_bootstrap - with_bootstrap, 2048)

    def test_preserved_bit_count_rejects_overlapping_regions(self) -> None:
        with self.assertRaises(ValueError):
            preserved_bit_count(10, 6, 1, 5)

    def test_masked_hash_masks_bootstrap_and_packet_regions(self) -> None:
        source = np.array([0x01, 0x03, 0x05, 0x07, 0x09, 0xAB, 0xCD, 0xEF], dtype=np.uint8)
        expected_masked = source.copy()
        expected_masked[0:2] &= np.uint8(0xFE)
        expected_masked[4:6] &= np.uint8(0xF8)
        preimage = (
            MEDIA_HASH_DOMAIN
            + struct.pack(">BB", IMAGE_MEDIA_CODE, 3)
            + b"\x00\x00\x00\x00\x00\x00\x00\x08"
            + b"\x00\x00\x00\x00\x00\x00\x00\x04"
            + b"\x00\x00\x00\x00\x00\x00\x00\x02"
            + b"\x00\x00\x00\x00\x00\x00\x00\x02"
            + expected_masked.tobytes()
        )
        self.assertTrue(np.all((expected_masked[0:2] & np.uint8(1)) == 0))
        self.assertTrue(np.all((expected_masked[4:6] & np.uint8(7)) == 0))
        self.assertEqual(
            calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 3, 4, 2, 2),
            hashlib.sha256(preimage).digest(),
        )

    def test_masked_hash_rejects_overlapping_bootstrap_region(self) -> None:
        with self.assertRaisesRegex(ValueError, "start_unit must be at least bootstrap_span"):
            calculate_masked_media_hash(carrier(8), IMAGE_MEDIA_CODE, 3, 1, 2, 2)

    def test_protocol_field_boundaries(self) -> None:
        self.assertEqual(encode_protocol_field(2**64 - 1, "field"), b"\xff" * 8)
        with self.assertRaisesRegex(ValueError, "must fit in 8 bytes"):
            encode_protocol_field(2**64, "field")

    def test_signing_input_uses_fixed_width_fields(self) -> None:
        payload = b"abcde"
        narrow = encode_signing_input(
            IMAGE_MEDIA_CODE,
            b"context",
            EmbeddingLayout(255, 13, 3, 3, 5, 0, 0),
            payload,
        )
        wide = encode_signing_input(
            IMAGE_MEDIA_CODE,
            b"context",
            EmbeddingLayout(256, 13, 3, 3, 5, 0, 0),
            payload,
        )
        prefix_length = len(SIGNING_DOMAIN) + 3
        self.assertEqual(narrow[prefix_length:prefix_length + 8], b"\x00\x00\x00\x00\x00\x00\x00\xff")
        self.assertEqual(wide[prefix_length:prefix_length + 8], b"\x00\x00\x00\x00\x00\x00\x01\x00")
        self.assertEqual(len(wide) - len(narrow), 0)

    def test_bootstrap_round_trip_and_aad(self) -> None:
        fields = BootstrapFields(2, 3, 13, 37, bytes(range(32)), bytes(range(12)))
        expected_aad = b"\x02\x03" + (13).to_bytes(8, "big") + (37).to_bytes(8, "big")
        serialized = serialize_bootstrap(fields)
        self.assertEqual(len(serialized), 62)
        self.assertEqual(parse_bootstrap(serialized), fields)
        self.assertEqual(encode_bootstrap_aad(fields), expected_aad)

    def test_bootstrap_span_and_oaep_envelope_limit(self) -> None:
        fields = BootstrapFields(2, 3, 13, 37, bytes(range(32)), bytes(range(12)))
        serialized = serialize_bootstrap(fields)
        self.assertEqual(bootstrap_span(PUBLIC_KEY), 2048)  # 256-byte serialised envelope at 1 LSB.
        oaep_plaintext_limit = PUBLIC_KEY.key_size // 8 - 2 * 32 - 2
        self.assertEqual(oaep_plaintext_limit, 190)
        self.assertLess(len(serialized), oaep_plaintext_limit)

    def test_rsa_oaep_seal_open_round_trip(self) -> None:
        plaintext = b"bootstrap envelope"
        ciphertext = seal_to_public_key(plaintext, PUBLIC_KEY)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(open_with_private_key(ciphertext, PRIVATE_KEY), plaintext)

    def test_aead_seal_open_and_tampering(self) -> None:
        key = bytes(range(32))
        nonce = bytes(range(12))
        aad = b"bootstrap aad"
        plaintext = b"record plaintext"
        ciphertext = aead_seal(key, nonce, aad, plaintext)
        self.assertEqual(aead_open(key, nonce, aad, ciphertext), plaintext)
        changed_aad = aad + b"x"
        changed_nonce = bytes((nonce[0] ^ 1,)) + nonce[1:]
        changed_key = bytes((key[0] ^ 1,)) + key[1:]
        changed_ciphertext = ciphertext[:-1] + bytes((ciphertext[-1] ^ 1,))
        for changed in (
            (changed_key, nonce, aad, ciphertext),
            (key, changed_nonce, aad, ciphertext),
            (key, nonce, changed_aad, ciphertext),
            (key, nonce, aad, changed_ciphertext),
        ):
            with self.subTest(change=changed):
                with self.assertRaises(InvalidTag):
                    aead_open(*changed)

    def test_bootstrap_parse_rejects_malformed_inputs(self) -> None:
        fields = BootstrapFields(2, 3, 13, 37, bytes(range(32)), bytes(range(12)))
        serialized = serialize_bootstrap(fields)
        malformed = []
        malformed.append(serialized[:-1])
        malformed.append(serialized + b"x")
        version_one = bytearray(serialized)
        version_one[0] = 1
        malformed.append(bytes(version_one))
        lsb_zero = bytearray(serialized)
        lsb_zero[1] = 0
        malformed.append(bytes(lsb_zero))
        lsb_nine = bytearray(serialized)
        lsb_nine[1] = 9
        malformed.append(bytes(lsb_nine))
        wrong_key_size = struct.pack(">BB", 1, 3) + b"\x00" * 16 + b"x" * 31 + bytes(12)
        malformed.append(wrong_key_size)
        for plaintext in malformed:
            with self.subTest(length=len(plaintext), prefix=plaintext[:3]):
                with self.assertRaises(ValueError):
                    parse_bootstrap(plaintext)

    def test_aead_sizes_match_bootstrap_constants(self) -> None:
        key = bytes(SESSION_KEY_SIZE)
        nonce = bytes(AEAD_NONCE_SIZE)
        ciphertext = aead_seal(key, nonce, b"", b"plaintext")
        self.assertEqual(aead_open(key, nonce, b"", ciphertext), b"plaintext")
        for key_length in (SESSION_KEY_SIZE - 1, SESSION_KEY_SIZE + 1):
            with self.subTest(key_length=key_length):
                with self.assertRaises(ValueError):
                    aead_seal(b"x" * key_length, nonce, b"", b"")
        for nonce_length in (AEAD_NONCE_SIZE - 1, AEAD_NONCE_SIZE + 1):
            with self.subTest(nonce_length=nonce_length):
                with self.assertRaises(ValueError):
                    aead_seal(key, b"x" * nonce_length, b"", b"")

    def test_all_lsb_counts_and_start_locations_round_trip(self) -> None:
        source = carrier(30000)
        context = struct.pack(">II", 10000, 1)
        cases = []
        for k in SUPPORTED_LSB_COUNTS:
            for start_kind in ("zero", "middle", "boundary"):
                footprint = ceil_unit_count((payload_length() + GCM_TAG_SIZE + RSA_SIGNATURE_SIZE) * 8, k)
                start = {"zero": bootstrap_span(RECEIVER_PUBLIC_KEY), "middle": bootstrap_span(RECEIVER_PUBLIC_KEY) + 211, "boundary": source.size - footprint}[start_kind]
                encoded, layout, payload = encode_carrier(source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, start, k, b"hello", b"{}")
                result = decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, "Authentic", (k, start_kind, result.detail))
                self.assertEqual(result.payload, payload)
                self.assertEqual((result.start_unit, result.lsb_count), (start, k))
                cases.append((k, start))
        self.assertEqual(len(cases), 24)

    def test_empty_short_large_and_binary_user_payloads_and_metadata(self) -> None:
        values = (
            (b"", b""),
            (b"short", b"name=alice"),
            (bytes(range(256)) * 20, "说明".encode()),
            (b"\xff\x00\x80\xfe", b""),
        )
        for user_payload, metadata in values:
            with self.subTest(length=len(user_payload), metadata=metadata):
                (encoded, layout, payload), context = encode_image_carrier(carrier(50000), user_payload=user_payload, metadata=metadata)
                result = decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, "Authentic")
                self.assertEqual(result.payload.user_payload, user_payload)
                self.assertEqual(result.payload.metadata, metadata)
                self.assertEqual(payload, result.payload)

    def test_exact_negative_verdicts_for_bit_changes(self) -> None:
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3, user_payload=b"payload", metadata=b"meta")
        packet_bits = layout.ciphertext_length * 8

        outside = encoded.copy()
        outside[layout.start_unit + layout.footprint] ^= np.uint8(1)
        self.assertEqual(decode_carrier(outside, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Tampered")

        upper_inside = encoded.copy()
        upper_inside[layout.start_unit + 5] ^= np.uint8(1 << layout.lsb_count)
        self.assertEqual(decode_carrier(upper_inside, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Tampered")

        first_ciphertext = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, 0)
        self.assertEqual(decode_carrier(first_ciphertext, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Signature Invalid")
        last_ciphertext = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, packet_bits - 1)
        self.assertEqual(decode_carrier(last_ciphertext, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Signature Invalid")
        changed_signature = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, packet_bits)
        self.assertEqual(decode_carrier(changed_signature, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Signature Invalid")
        self.assertEqual(decode_carrier(encoded, IMAGE_MEDIA_CODE, context, OTHER_PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Signature Invalid")

        changed_bootstrap = encoded.copy()
        changed_bootstrap[0] ^= np.uint8(1)
        self.assertEqual(decode_carrier(changed_bootstrap, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Payload Missing")

    def test_signature_verification_precedes_decryption(self) -> None:
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3)
        signature_invalid = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, 0)
        with patch("stego.core.aead_open", wraps=aead_open) as decrypt_mock:
            authentic = decode_carrier(
                encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY
            )
            self.assertEqual(authentic.verdict, "Authentic")
            decrypt_mock.assert_called_once()
            decrypt_mock.reset_mock()
            invalid = decode_carrier(
                signature_invalid,
                IMAGE_MEDIA_CODE,
                context,
                PUBLIC_KEY,
                RECEIVER_PRIVATE_KEY,
            )
            self.assertEqual(invalid.verdict, "Signature Invalid")
            decrypt_mock.assert_not_called()

    def test_bootstrap_authenticated_decryption_rejects_changed_session_material(self) -> None:
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3)
        fields = bootstrap_fields_from_carrier(encoded)
        for change in ("session", "nonce"):
            with self.subTest(change=change):
                session_key = fields.session_key
                aead_nonce = fields.aead_nonce
                if change == "session":
                    session_key = bytes((session_key[0] ^ 1,)) + session_key[1:]
                else:
                    aead_nonce = bytes((aead_nonce[0] ^ 1,)) + aead_nonce[1:]
                envelope = raw_bootstrap(
                    fields.version, fields.lsb_count,
                    fields.start_unit, fields.ciphertext_length, session_key, aead_nonce,
                )
                changed = write_lsb_bits(encoded.copy(), bytes_to_bit_sequence(envelope), BOOTSTRAP_LSB_COUNT)
                self.assertEqual(
                    decode_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict,
                    "Cannot Decrypt",
                )

    def test_exact_empty_packet_capacities_include_bootstrap(self) -> None:
        expected_totals = {1: 5096, 3: 3064, 8: 2429}
        span = bootstrap_span(RECEIVER_PUBLIC_KEY)
        for lsb_count, expected_total in expected_totals.items():
            with self.subTest(lsb_count=lsb_count):
                packet_bytes = serialized_record_length(
                    MEDIA_ID_SIZE, 0, 0
                ) + GCM_TAG_SIZE + RSA_SIGNATURE_SIZE
                total_units = span + ceil_unit_count(packet_bytes * 8, lsb_count)
                self.assertEqual(total_units, expected_total)
                source = carrier(total_units)
                context = struct.pack(">II", total_units // 3, 1)
                encoded, layout, _ = encode_carrier(
                    source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY,
                    span, lsb_count, b"", b"",
                )
                self.assertEqual(layout.footprint + span, total_units)
                self.assertEqual(
                    decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict,
                    "Authentic",
                )

    def test_media_interpretation_changes_invalidate_signature(self) -> None:
        (encoded, layout, _), context = encode_image_carrier(start=2048, k=3)
        self.assertEqual(
            decode_carrier(encoded, AUDIO_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict,
            "Signature Invalid",
        )
        self.assertEqual(
            decode_carrier(encoded, IMAGE_MEDIA_CODE, context + b"changed", PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict,
            "Signature Invalid",
        )

    def test_raw_packet_hides_record_and_signs_ciphertext(self) -> None:
        source = carrier(30000)
        context = struct.pack(">II", 10000, 1)
        encoded, layout, payload = encode_carrier(
            source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"hello", b"{}"
        )
        self.assertEqual(layout.ciphertext_length, 132)
        self.assertEqual(layout.footprint, 1035)
        self.assertEqual(layout.pad_bits, 1)
        all_bits = read_lsb_bits(
            encoded[layout.start_unit:layout.start_unit + layout.footprint],
            layout.footprint * layout.lsb_count,
            layout.lsb_count,
        )
        packet_bits_length = (132 + 256) * 8
        packet = bit_sequence_to_bytes(all_bits[:packet_bits_length])
        ciphertext = packet[:132]
        signature = packet[132:]
        self.assertEqual(len(packet), 388)
        self.assertEqual(len(signature), 256)
        record_bytes = serialize_payload(payload)
        self.assertEqual(len(record_bytes), 116)
        self.assertNotIn(record_bytes, encoded.tobytes())
        self.assertFalse(ciphertext.startswith(b"\x24IMG-"))
        self.assertTrue(
            verify_signature(
                encode_signing_input(IMAGE_MEDIA_CODE, context, layout, ciphertext),
                signature,
                PUBLIC_KEY,
            )
        )
        self.assertTrue(np.all(all_bits[packet_bits_length:] == 0))

    def test_relocated_packet_is_signature_invalid(self) -> None:
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3)
        bits = read_lsb_bits(encoded[layout.start_unit:layout.start_unit + layout.footprint], layout.footprint * layout.lsb_count, layout.lsb_count)
        relocated = source.copy()
        new_start = 5000
        relocated[new_start:new_start + layout.footprint] = write_lsb_bits(
            relocated[new_start:new_start + layout.footprint], bits, layout.lsb_count
        )
        fields = bootstrap_fields_from_carrier(encoded)
        moved_bootstrap = reseal_bootstrap(fields, start_unit=new_start)
        relocated = write_lsb_bits(relocated, bytes_to_bit_sequence(moved_bootstrap), BOOTSTRAP_LSB_COUNT)
        self.assertEqual(decode_carrier(relocated, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Signature Invalid")

    def test_supplied_geometry_out_of_range_is_wrong_start_location(self) -> None:
        encoded_result, context = encode_image_carrier(carrier(30000), start=2048, k=3)
        encoded, layout, _ = encoded_result
        fields = bootstrap_fields_from_carrier(encoded)
        forged = reseal_bootstrap(fields, start_unit=encoded.size - layout.footprint + 1)
        changed = write_lsb_bits(encoded.copy(), bytes_to_bit_sequence(forged), BOOTSTRAP_LSB_COUNT)
        result = decode_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
        self.assertEqual(result.verdict, "Wrong Start Location")

    def test_pristine_and_wrong_receiver_carriers_are_payload_missing(self) -> None:
        source = carrier(10000)
        context = struct.pack(">II", source.size // 3, 1)
        for pristine in (source, np.zeros(source.size, dtype=np.uint8)):
            with self.subTest(first_unit=int(pristine[0])):
                result = decode_carrier(pristine, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, "Payload Missing")
        (encoded, _, _), _ = encode_image_carrier(source)
        self.assertEqual(
            decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, OTHER_PRIVATE_KEY).verdict,
            "Payload Missing",
        )

    def test_invalid_bootstrap_fields_are_rejected_after_one_bootstrap_read(self) -> None:
        source = carrier(10000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3)
        fields = bootstrap_fields_from_carrier(encoded)
        cases = (
            {"version": 1},
            {"lsb_count": 0},
            {"lsb_count": 9},
            {"ciphertext_length": 0},
            {"extra": b"x"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                if "extra" in changes:
                    envelope = raw_bootstrap(fields.version, fields.lsb_count, fields.start_unit, fields.ciphertext_length, fields.session_key, fields.aead_nonce, changes["extra"])
                else:
                    envelope = reseal_bootstrap(fields, **changes)
                changed = write_lsb_bits(encoded.copy(), bytes_to_bit_sequence(envelope), BOOTSTRAP_LSB_COUNT)
                with patch("stego.core.read_lsb_bits", wraps=read_lsb_bits) as read_bits:
                    result = decode_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, "Cannot Verify")
                self.assertEqual(read_bits.call_count, 1)

    def test_valid_changed_geometry_is_signature_invalid(self) -> None:
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3)
        fields = bootstrap_fields_from_carrier(encoded)
        for changes, expected_verdict in (
            ({"lsb_count": 4}, "Signature Invalid"),
            ({"ciphertext_length": fields.ciphertext_length + 1}, "Cannot Verify"),
        ):
            with self.subTest(changes=changes):
                envelope = reseal_bootstrap(fields, **changes)
                changed = write_lsb_bits(encoded.copy(), bytes_to_bit_sequence(envelope), BOOTSTRAP_LSB_COUNT)
                result = decode_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, expected_verdict)

    def test_unreadable_bootstrap_geometry_is_wrong_start_after_one_read(self) -> None:
        source = carrier(10000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=3)
        fields = bootstrap_fields_from_carrier(encoded)
        cases = (
            {"start_unit": bootstrap_span(RECEIVER_PRIVATE_KEY) - 1},
            {"start_unit": source.size},
            {"ciphertext_length": source.size},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                envelope = reseal_bootstrap(fields, **changes)
                changed = write_lsb_bits(encoded.copy(), bytes_to_bit_sequence(envelope), BOOTSTRAP_LSB_COUNT)
                with patch("stego.core.read_lsb_bits", wraps=read_lsb_bits) as read_bits:
                    result = decode_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, "Wrong Start Location")
                self.assertEqual(read_bits.call_count, 1)

    def test_nonzero_alignment_padding_is_cannot_verify(self) -> None:
        (encoded, layout, _), context = encode_image_carrier(start=2048, k=5, user_payload=b"x")
        self.assertGreater(layout.pad_bits, 0)
        changed = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, layout.footprint * layout.lsb_count - 1)
        self.assertEqual(decode_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Cannot Verify")

    def test_capacity_failure_does_not_modify_input(self) -> None:
        source = carrier(1000)
        before = source.copy()
        with self.assertRaisesRegex(ValueError, "carrier is too small"):
            encode_carrier(source, IMAGE_MEDIA_CODE, struct.pack(">II", 1, 1), PRIVATE_KEY, RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 1, b"x" * 5000, b"")
        self.assertTrue(np.array_equal(source, before))

    def test_k8_hash_and_preservation_honesty(self) -> None:
        source = carrier(10000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=8)
        result = decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
        self.assertEqual(result.verdict, "Authentic")
        expected = (
            8 * (source.size - layout.footprint - layout.bootstrap_span)
            + 0 * layout.footprint
            + 7 * layout.bootstrap_span
        )
        self.assertEqual(result.preserved_bits, expected)
        self.assertEqual(result.preserved_ratio, expected / (source.size * 8))

        inside_changed = source.copy()
        inside_changed[layout.start_unit] ^= np.uint8(0xFF)
        self.assertEqual(
            calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint, layout.bootstrap_span),
            calculate_masked_media_hash(inside_changed, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint, layout.bootstrap_span),
        )
        outside_changed = source.copy()
        outside_changed[0] ^= np.uint8(2)
        self.assertNotEqual(
            calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint, layout.bootstrap_span),
            calculate_masked_media_hash(outside_changed, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint, layout.bootstrap_span),
        )

        packet_bytes = payload_length(b"", b"") + GCM_TAG_SIZE + RSA_SIGNATURE_SIZE
        exact_footprint = ceil_unit_count(packet_bytes * 8, 8)
        exact_size = bootstrap_span(RECEIVER_PUBLIC_KEY) + exact_footprint
        exact_source = carrier(exact_size)
        exact_context = struct.pack(">II", exact_size, 1)
        exact_encoded, exact_layout, _ = encode_carrier(
            exact_source, IMAGE_MEDIA_CODE, exact_context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, bootstrap_span(RECEIVER_PUBLIC_KEY), 8, b"", b""
        )
        exact_result = decode_carrier(exact_encoded, IMAGE_MEDIA_CODE, exact_context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
        self.assertEqual(exact_layout.footprint, exact_footprint)
        self.assertEqual(exact_layout.bootstrap_span + exact_layout.footprint, exact_size)
        self.assertEqual(exact_result.verdict, "Authentic")
        self.assertEqual(exact_result.preserved_bits, 7 * exact_layout.bootstrap_span)

    def test_png_and_wav_file_round_trips(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            png_input = directory / "input.png"
            png_output = directory / "output.png"
            image = np.arange(120 * 120 * 3, dtype=np.uint8).reshape((120, 120, 3))
            Image.fromarray(image, mode="RGB").save(png_input)
            png_layout, _ = encode_png(png_input, png_output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"PNG bytes \xff", b"kind=image")
            png_result = verify_png(png_output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(png_result.verdict, "Authentic")
            self.assertEqual(png_result.payload.user_payload, b"PNG bytes \xff")

            wav_input = directory / "input.wav"
            wav_output = directory / "output.wav"
            with wave.open(str(wav_input), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(1)
                wav_file.setframerate(8000)
                wav_file.writeframes(bytes(range(256)) * 80)
            wav_layout, _ = encode_wav(wav_input, wav_output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 5, b"WAV bytes", b"kind=audio")
            wav_result = verify_wav(wav_output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(wav_result.verdict, "Authentic")
            self.assertEqual(wav_result.payload.metadata, b"kind=audio")

    def test_wav_tampering_outside_footprint_is_tampered(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            wav_input = directory / "input.wav"
            wav_output = directory / "output.wav"
            wav_tampered = directory / "tampered.wav"
            with wave.open(str(wav_input), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(1)
                wav_file.setframerate(8000)
                wav_file.writeframes(bytes(range(256)) * 80)
            layout, _ = encode_wav(wav_input, wav_output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 5, b"WAV bytes", b"kind=audio")
            wav_data = load_pcm_wav_from_path(wav_output)
            changed = wav_frame_bytes_to_carrier(wav_data.frame_bytes, wav_data.sample_width)
            changed[layout.start_unit + layout.footprint] ^= np.uint8(1)
            save_pcm_wav_to_path(wav_data_with_carrier(wav_data, changed), wav_tampered)
            self.assertEqual(verify_wav(wav_tampered, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Tampered")

    def test_multibyte_wav_sample_stride_round_trips(self) -> None:
        sample_count = 6000
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            for sample_width in (2, 3, 4):
                signed_limit = 1 << (sample_width * 8 - 1)
                sample_values = [
                    ((index * 7919) % (signed_limit * 2)) - signed_limit
                    for index in range(sample_count)
                ]
                frame_bytes = b"".join(
                    value.to_bytes(sample_width, "little", signed=True)
                    for value in sample_values
                )
                wav_input = directory / f"width-{sample_width}-input.wav"
                with wave.open(str(wav_input), "wb") as wav_file:
                    wav_file.setnchannels(1)
                    wav_file.setsampwidth(sample_width)
                    wav_file.setframerate(8000)
                    wav_file.writeframes(frame_bytes)
                original = load_pcm_wav_from_path(wav_input)
                for lsb_count in (1, 3, 8):
                    with self.subTest(sample_width=sample_width, lsb_count=lsb_count):
                        wav_output = directory / f"width-{sample_width}-k-{lsb_count}.wav"
                        payload = f"width={sample_width};k={lsb_count}".encode("ascii")
                        layout, _ = encode_wav(
                            wav_input,
                            wav_output,
                            PRIVATE_KEY,
                            RECEIVER_PUBLIC_KEY,
                            2048,
                            lsb_count,
                            payload,
                            b"multi-byte",
                        )
                        result = verify_wav(wav_output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                        self.assertEqual(result.verdict, "Authentic", result.detail)
                        self.assertEqual(result.payload.user_payload, payload)
                        stego_data = load_pcm_wav_from_path(wav_output)
                        original_samples = decode_pcm_samples(original.frame_bytes, sample_width)
                        stego_samples = decode_pcm_samples(stego_data.frame_bytes, sample_width)
                        max_delta = max(
                            abs(before - after)
                            for before, after in zip(original_samples, stego_samples)
                        )
                        self.assertLessEqual(max_delta, (1 << lsb_count) - 1)
                        self.assertTrue(
                            all(
                                before == after
                                for index, (before, after) in enumerate(
                                    zip(original.frame_bytes, stego_data.frame_bytes)
                                )
                                if index % sample_width != 0
                            )
                        )

    def test_multibyte_wav_capacity_uses_sample_count(self) -> None:
        sample_width = 2
        sample_count = 6000
        lsb_count = 3
        wav_data = WavPcmData(1, sample_width, 8000, sample_count, bytes(sample_count * sample_width))
        carrier = wav_frame_bytes_to_carrier(wav_data.frame_bytes, wav_data.sample_width)
        context = encode_wav_media_context(wav_data, carrier.size)
        span = bootstrap_span(RECEIVER_PUBLIC_KEY)
        record_overhead = serialized_record_length(MEDIA_ID_SIZE, 0, 0)
        maximum = max_user_payload_length(carrier.size, span, span, lsb_count, record_overhead)
        self.assertGreater(maximum, 0)
        before = carrier.copy()
        encoded, layout, payload = encode_carrier(
            carrier, AUDIO_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY,
            span, lsb_count, b"x" * maximum, b"",
        )
        self.assertEqual(layout.total_units, sample_count)
        self.assertEqual(encoded.size, sample_count)
        self.assertEqual(len(payload.user_payload), maximum)
        with self.assertRaisesRegex(ValueError, "user payload exceeds capacity"):
            encode_carrier(
                carrier, AUDIO_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY,
                span, lsb_count, b"x" * (maximum + 1), b"",
            )
        self.assertTrue(np.array_equal(carrier, before))

    def test_wav_carrier_stride_validation(self) -> None:
        carrier = wav_frame_bytes_to_carrier(bytes(range(12)), 3)
        self.assertTrue(carrier.flags["C_CONTIGUOUS"])
        self.assertEqual(carrier.tolist(), [0, 3, 6, 9])
        with self.assertRaises(ValueError):
            wav_frame_bytes_to_carrier(b"12345", 2)
        for sample_width in (0, 5):
            with self.subTest(sample_width=sample_width):
                with self.assertRaises(ValueError):
                    wav_frame_bytes_to_carrier(b"1234", sample_width)

    def test_generated_media_id_matches_constant(self) -> None:
        (_, _, payload), _ = encode_image_carrier()
        self.assertEqual(len(payload.media_id.encode("utf-8")), MEDIA_ID_SIZE)

    def test_payload_capacity_boundary_is_exact(self) -> None:
        cases = ((5000, 137, 0), (10000, bootstrap_span(RECEIVER_PUBLIC_KEY) + 137, bootstrap_span(RECEIVER_PUBLIC_KEY)))
        for total_units, start_unit, span in cases:
            for lsb_count in (1, 3, 8):
                with self.subTest(total_units=total_units, lsb_count=lsb_count):
                    maximum = max_record_length(total_units, start_unit, span, lsb_count)
                    layout = build_embedding_layout(total_units, start_unit, lsb_count, maximum + GCM_TAG_SIZE, span)
                    self.assertLessEqual(start_unit + layout.footprint, total_units)
                    with self.assertRaises(ValueError):
                        build_embedding_layout(total_units, start_unit, lsb_count, maximum + GCM_TAG_SIZE + 1, span)

    def test_minimum_carrier_units_and_zero_capacity_boundaries(self) -> None:
        span = bootstrap_span(RECEIVER_PUBLIC_KEY)
        expected_minimums = {1: 5096, 3: 3064, 8: 2429}
        for lsb_count, expected_minimum in expected_minimums.items():
            with self.subTest(lsb_count=lsb_count):
                minimum_record_length = serialized_record_length(
                    MEDIA_ID_SIZE, 0, 0
                )
                self.assertEqual(
                    minimum_carrier_units(span, lsb_count, minimum_record_length),
                    expected_minimum,
                )
                self.assertEqual(
                    max_user_payload_length(
                        expected_minimum,
                        span,
                        span,
                        lsb_count,
                        minimum_record_length,
                    ),
                    0,
                )
                source = carrier(expected_minimum)
                context = struct.pack(">II", expected_minimum, 1)
                encoded, _, _ = encode_carrier(
                    source,
                    IMAGE_MEDIA_CODE,
                    context,
                    PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    span,
                    lsb_count,
                    b"",
                    b"",
                )
                self.assertEqual(
                    decode_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict,
                    "Authentic",
                )
                too_small = carrier(expected_minimum - 1)
                before = too_small.copy()
                too_small_record_length = serialized_record_length(
                    MEDIA_ID_SIZE, 0, 0
                )
                too_small_minimum_units = minimum_carrier_units(
                    span, lsb_count, too_small_record_length
                )
                for user_payload in (b"", b"x"):
                    with self.subTest(payload=user_payload):
                        with self.assertRaisesRegex(
                            ValueError,
                            f"carrier is too small for the protocol.*total_units={expected_minimum - 1}.*"
                            f"start_unit={span}.*lsb_count={lsb_count}.*minimum_units={too_small_minimum_units}",
                        ):
                            encode_carrier(
                                too_small,
                                IMAGE_MEDIA_CODE,
                                context,
                                PRIVATE_KEY,
                                RECEIVER_PUBLIC_KEY,
                                span,
                                lsb_count,
                                user_payload,
                                b"",
                            )
                        self.assertTrue(np.array_equal(too_small, before))
                record_maximum = max_record_length(
                    expected_minimum - 1,
                    span,
                    span,
                    lsb_count,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    f"record overhead exceeds record capacity.*record_overhead={minimum_record_length}.*"
                    f"record_maximum={record_maximum}.*total_units={expected_minimum - 1}.*"
                    f"start_unit={span}.*lsb_count={lsb_count}.*minimum_units={expected_minimum}",
                ):
                    max_user_payload_length(
                        expected_minimum - 1,
                        span,
                        span,
                        lsb_count,
                        minimum_record_length,
                    )

    def test_oversized_metadata_reports_record_capacity_not_carrier_size(self) -> None:
        total_units = 10000
        span = bootstrap_span(RECEIVER_PUBLIC_KEY)
        start_unit = span
        lsb_count = 1
        metadata = b"m" * 2048
        source = carrier(total_units)
        before = source.copy()
        context = struct.pack(">II", total_units // 3, 1)
        record_overhead = serialized_record_length(MEDIA_ID_SIZE, 0, len(metadata))
        record_maximum = max_record_length(total_units, start_unit, span, lsb_count)
        expected_details = (
            f"record overhead exceeds record capacity: record_overhead={record_overhead}, "
            f"record_maximum={record_maximum}"
        )

        with self.assertRaises(ValueError) as error:
            encode_carrier(
                source,
                IMAGE_MEDIA_CODE,
                context,
                PRIVATE_KEY,
                RECEIVER_PUBLIC_KEY,
                start_unit,
                lsb_count,
                b"",
                metadata,
            )

        message = str(error.exception)
        self.assertIn(expected_details, message)
        self.assertNotIn("carrier is too small for the protocol", message)
        self.assertTrue(np.array_equal(source, before))

    def test_payload_capacity_refuses_carrier_without_packet(self) -> None:
        total_units = RSA_SIGNATURE_SIZE - 1
        with self.assertRaisesRegex(
            ValueError,
            "carrier cannot hold a packet.*total_units=255.*start_unit=0.*lsb_count=8.*minimum_units=",
        ):
            max_record_length(total_units, 0, 0, 8)

    def test_signature_only_layout_boundary_is_exact(self) -> None:
        with self.assertRaisesRegex(ValueError, "carrier cannot hold a packet"):
            build_embedding_layout(255, 0, 8, 0, 0)
        layout = build_embedding_layout(256, 0, 8, 0, 0)
        self.assertEqual(layout.footprint, 256)
        self.assertEqual(layout.pad_bits, 0)

    def test_payload_capacity_rejection_names_capacity_inputs(self) -> None:
        cases = ((5000, 137, 0), (10000, bootstrap_span(RECEIVER_PUBLIC_KEY) + 137, bootstrap_span(RECEIVER_PUBLIC_KEY)))
        for total_units, start_unit, span in cases:
            with self.subTest(total_units=total_units, span=span):
                lsb_count = 3
                maximum = max_record_length(total_units, start_unit, span, lsb_count)
                with self.assertRaises(ValueError) as raised:
                    build_embedding_layout(total_units, start_unit, lsb_count, maximum + GCM_TAG_SIZE + 1, span)
                message = str(raised.exception)
                for expected in (
                    f"total_units={total_units}",
                    f"start_unit={start_unit}",
                    f"lsb_count={lsb_count}",
                    f"max_record_length={maximum}",
                ):
                    self.assertIn(expected, message)

    def test_payload_over_sixteen_mebibytes_uses_carrier_capacity(self) -> None:
        payload_length = 16 * 1024 * 1024 + 1
        total_units = RSA_SIGNATURE_SIZE + payload_length
        maximum = max_record_length(total_units, 0, 0, 8)
        self.assertEqual(maximum, payload_length - GCM_TAG_SIZE)
        layout = build_embedding_layout(total_units, 0, 8, payload_length - GCM_TAG_SIZE, 0)
        self.assertEqual(layout.ciphertext_length, payload_length - GCM_TAG_SIZE)
        self.assertEqual(layout.footprint, total_units - GCM_TAG_SIZE)

    def test_user_payload_capacity_boundary_is_exact(self) -> None:
        total_units = 10000
        start_unit = bootstrap_span(RECEIVER_PUBLIC_KEY)
        metadata = b"m" * 17
        fixed_record_overhead = serialized_record_length(MEDIA_ID_SIZE, 0, 0)
        self.assertEqual(fixed_record_overhead, 109)
        record_overhead = serialized_record_length(MEDIA_ID_SIZE, 0, len(metadata))
        self.assertEqual(record_overhead, 126)
        expected_record_maxima = tuple(max_record_length(total_units, start_unit, bootstrap_span(RECEIVER_PUBLIC_KEY), k) for k in (1, 3, 8))
        expected_user_maxima = tuple(value - record_overhead for value in expected_record_maxima)
        source = carrier(total_units)
        context = struct.pack(">II", total_units // 3, 1)
        for lsb_count, expected_record, expected_user in zip(
            (1, 3, 8), expected_record_maxima, expected_user_maxima
        ):
            with self.subTest(lsb_count=lsb_count):
                record_maximum = max_record_length(total_units, start_unit, bootstrap_span(RECEIVER_PUBLIC_KEY), lsb_count)
                user_maximum = max_user_payload_length(total_units, start_unit, bootstrap_span(RECEIVER_PUBLIC_KEY), lsb_count, record_overhead)
                self.assertEqual(record_maximum, expected_record)
                self.assertEqual(user_maximum, expected_user)
                self.assertEqual(record_maximum - user_maximum, record_overhead)
                before = source.copy()
                encoded, layout, payload = encode_carrier(
                    source,
                    IMAGE_MEDIA_CODE,
                    context,
                    PRIVATE_KEY,
                    RECEIVER_PUBLIC_KEY,
                    start_unit,
                    lsb_count,
                    b"x" * user_maximum,
                    metadata,
                )
                result = decode_carrier(
                    encoded,
                    IMAGE_MEDIA_CODE,
                    context,
                    PUBLIC_KEY,
                    RECEIVER_PRIVATE_KEY,
                )
                self.assertEqual(result.verdict, "Authentic")
                self.assertEqual(len(payload.user_payload), expected_user)
                self.assertTrue(np.array_equal(source, before))
                with self.assertRaisesRegex(ValueError, "user payload exceeds capacity"):
                    encode_carrier(
                        source,
                        IMAGE_MEDIA_CODE,
                        context,
                        PRIVATE_KEY,
                        RECEIVER_PUBLIC_KEY,
                        start_unit,
                        lsb_count,
                        b"x" * (user_maximum + 1),
                        metadata,
                    )
                self.assertTrue(np.array_equal(source, before))

    def test_user_payload_capacity_refuses_carrier_without_protocol(self) -> None:
        total_units = RSA_SIGNATURE_SIZE - 1
        with self.assertRaisesRegex(
            ValueError,
            "carrier cannot hold a packet.*total_units=255.*start_unit=0.*lsb_count=8.*minimum_units=",
        ):
            max_user_payload_length(total_units, 0, 0, 8, 0)

    def test_layout_rejects_start_inside_bootstrap_region(self) -> None:
        with self.assertRaisesRegex(ValueError, "bootstrap region.*lowest legal start_unit is 128"):
            build_embedding_layout(5000, 100, 1, 0, 128)

    def test_unsupported_image_formats_are_rejected(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            jpeg = directory / "cover.jpg"
            palette = directory / "palette.png"
            sixteen = directory / "sixteen.png"
            Image.new("RGB", (20, 20)).save(jpeg)
            Image.new("P", (20, 20)).save(palette)
            Image.fromarray(np.zeros((20, 20), dtype=np.uint16)).save(sixteen)
            with self.assertRaises(UnSupportedFileType):
                load_png_from_path(jpeg)
            with self.assertRaisesRegex(ValueError, "unsupported RGB PNG"):
                load_png_from_path(palette)
            with self.assertRaisesRegex(ValueError, "unsupported RGB PNG"):
                load_png_from_path(sixteen)
            self.assertEqual(verify_png(jpeg, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Cannot Verify")

    def test_pem_helpers_round_trip(self):
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            private_path = directory / "private.pem"
            protected_path = directory / "protected.pem"
            public_path = directory / "public.pem"
            save_rsa_private_key_pem(PRIVATE_KEY, private_path)
            save_rsa_private_key_pem(PRIVATE_KEY, protected_path, b"password")
            save_rsa_public_key_pem(PUBLIC_KEY, public_path)
            self.assertEqual(load_rsa_private_key_pem(private_path).public_key().public_numbers(), PUBLIC_KEY.public_numbers())
            self.assertEqual(load_rsa_private_key_pem(protected_path, b"password").public_key().public_numbers(), PUBLIC_KEY.public_numbers())
            self.assertEqual(load_rsa_public_key_pem(public_path).public_numbers(), PUBLIC_KEY.public_numbers())

            ec_path = directory / "ec.pem"
            ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
            ec_path.write_bytes(ec_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            with self.assertRaisesRegex(TypeError, "RSA public key"):
                load_rsa_public_key_pem(ec_path)


if __name__ == "__main__":
    unittest.main()
