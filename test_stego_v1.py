import struct
import unittest
import wave
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import stego_v1
from stego_v1 import *


PRIVATE_KEY, PUBLIC_KEY = generate_v1_rsa_keypair()
OTHER_PRIVATE_KEY, OTHER_PUBLIC_KEY = generate_v1_rsa_keypair()


def carrier(size=24000):
    return np.arange(size, dtype=np.uint8)


def payload_length(user_payload=b"hello", metadata=b"{}"):
    media_id_length = len("IMG-" + "0" * 32)
    return 1 + media_id_length + 8 + 16 + 32 + 4 + len(user_payload) + 4 + len(metadata)


def encode_image_carrier(source=None, start=17, k=3, user_payload=b"hello", metadata=b"{}"):
    if source is None:
        source = carrier()
    context = struct.pack(">II", source.size // 3, 1)
    return encode_v1_carrier(source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, start, k, user_payload, metadata), context


def embedded_bit_flip(encoded, start, k, bit_offset):
    result = encoded.copy()
    unit_offset, within = divmod(bit_offset, k)
    result[start + unit_offset] ^= np.uint8(1 << (k - 1 - within))
    return result


class TestMaskedStegoV1(unittest.TestCase):
    def test_constants_header_and_minimal_media_contexts(self):
        self.assertEqual(MEDIA_HASH_DOMAIN, b"INF2005-ACW1\x00MEDIA-HASH\x00")
        self.assertEqual(SIGNING_DOMAIN, b"INF2005-ACW1\x00SIGN\x00")
        self.assertEqual(PACKET_HEADER_FORMAT, ">16sBBBI")
        self.assertEqual(PACKET_HEADER_SIZE, 23)
        header = serialize_packet_header(3, IMAGE_MEDIA_CODE, 99)
        self.assertEqual(parse_packet_header(header), PacketHeader(1, 3, IMAGE_MEDIA_CODE, 99))
        self.assertEqual(encode_png_media_context((7, 11, 3)), struct.pack(">II", 11, 7))
        wav_data = WavPcmData(2, 2, 44100, 3, bytes(12))
        self.assertEqual(encode_wav_media_context(wav_data), struct.pack(">HBIQ", 2, 2, 44100, 3))

    def test_payload_binary_round_trip_and_utf8_metadata(self):
        record = V1PayloadRecord(
            "IMG-test",
            1_700_000_000,
            bytes(range(16)),
            bytes(range(32)),
            b"\x00\xff\x80binary\x00",
            "author: 张三".encode(),
        )
        encoded = serialize_v1_payload(record)
        self.assertEqual(parse_v1_payload(encoded), record)
        with self.assertRaisesRegex(ValueError, "metadata must contain valid UTF-8"):
            V1PayloadRecord("IMG-test", 1, bytes(16), bytes(32), b"", b"\xff")
        with self.assertRaisesRegex(ValueError, "trailing bytes"):
            parse_v1_payload(encoded + b"x")

    def test_masked_media_hash_has_exact_approved_preimage(self):
        source = np.array([0xFF, 0xA5, 0x5A, 0x00], dtype=np.uint8)
        expected_masked = source.copy()
        expected_masked[1:3] &= np.uint8(0xF8)
        preimage = (
            MEDIA_HASH_DOMAIN
            + struct.pack(">BBQQQ", IMAGE_MEDIA_CODE, 3, 4, 1, 2)
            + expected_masked.tobytes()
        )
        self.assertEqual(calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 3, 1, 2), stego_v1.hashlib.sha256(preimage).digest())
        self.assertTrue(np.array_equal(source, np.array([0xFF, 0xA5, 0x5A, 0x00], dtype=np.uint8)))

    def test_signing_input_has_exact_approved_bytes(self):
        layout = EmbeddingLayout(1000, 13, 300, 3, 5, 0)
        payload = b"abcde"
        expected = SIGNING_DOMAIN + struct.pack(">BBBQQQI", 1, IMAGE_MEDIA_CODE, 3, 1000, 13, 300, 5) + b"context" + payload
        self.assertEqual(encode_signing_input(IMAGE_MEDIA_CODE, b"context", layout, payload), expected)

    def test_all_lsb_counts_and_start_locations_round_trip(self):
        source = carrier(30000)
        context = struct.pack(">II", 10000, 1)
        cases = []
        for k in SUPPORTED_LSB_COUNTS:
            for start_kind in ("zero", "middle", "boundary"):
                footprint = ceil_unit_count((PACKET_HEADER_SIZE + payload_length() + RSA_SIGNATURE_SIZE) * 8, k)
                start = {"zero": 0, "middle": 211, "boundary": source.size - footprint}[start_kind]
                encoded, layout, payload = encode_v1_carrier(source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, start, k, b"hello", b"{}")
                result = decode_v1_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY)
                self.assertEqual(result.verdict, "Authentic", (k, start_kind, result.detail))
                self.assertEqual(result.payload, payload)
                self.assertEqual((result.start_unit, result.lsb_count), (start, k))
                cases.append((k, start))
        self.assertEqual(len(cases), 24)

    def test_empty_short_large_and_binary_user_payloads_and_metadata(self):
        values = (
            (b"", b""),
            (b"short", b"name=alice"),
            (bytes(range(256)) * 20, "说明".encode()),
            (b"\xff\x00\x80\xfe", b""),
        )
        for user_payload, metadata in values:
            with self.subTest(length=len(user_payload), metadata=metadata):
                (encoded, _, payload), context = encode_image_carrier(carrier(50000), user_payload=user_payload, metadata=metadata)
                result = decode_v1_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY)
                self.assertEqual(result.verdict, "Authentic")
                self.assertEqual(result.payload.user_payload, user_payload)
                self.assertEqual(result.payload.metadata, metadata)
                self.assertEqual(payload, result.payload)

    def test_exact_negative_verdicts_for_bit_changes(self):
        source = carrier(30000)
        (encoded, layout, payload), context = encode_image_carrier(source, start=31, k=3, user_payload=b"payload", metadata=b"meta")

        outside = encoded.copy()
        outside[layout.start_unit + layout.footprint] ^= np.uint8(1)
        self.assertEqual(decode_v1_carrier(outside, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Tampered")

        upper_inside = encoded.copy()
        upper_inside[layout.start_unit + 5] ^= np.uint8(1 << layout.lsb_count)
        self.assertEqual(decode_v1_carrier(upper_inside, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Tampered")

        user_offset = 1 + len(payload.media_id.encode()) + 8 + 16 + 32 + 4
        changed_payload = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, (PACKET_HEADER_SIZE + user_offset) * 8)
        self.assertEqual(decode_v1_carrier(changed_payload, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Signature Invalid")

        hash_offset = 1 + len(payload.media_id.encode()) + 8 + 16
        changed_hash = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, (PACKET_HEADER_SIZE + hash_offset) * 8)
        self.assertEqual(decode_v1_carrier(changed_hash, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Signature Invalid")

        signature_offset = (PACKET_HEADER_SIZE + layout.payload_length) * 8
        changed_signature = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, signature_offset)
        self.assertEqual(decode_v1_carrier(changed_signature, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Signature Invalid")

        self.assertEqual(decode_v1_carrier(encoded, IMAGE_MEDIA_CODE, context, OTHER_PUBLIC_KEY).verdict, "Signature Invalid")
        self.assertEqual(decode_v1_carrier(source, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Payload Missing")

    def test_deeper_candidate_failure_has_priority(self):
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=31, k=3)
        tampered = encoded.copy()
        tampered[layout.start_unit + layout.footprint] ^= np.uint8(1)
        shallow_start = tampered.size - ceil_unit_count(len(START_MAGIC) * 8, 1)
        tampered[shallow_start:] = write_lsb_bits(
            tampered[shallow_start:], bytes_to_bit_sequence(START_MAGIC), 1
        )
        candidates = scan_start_magic(tampered)
        self.assertIn(StartMagicCandidate(layout.start_unit, layout.lsb_count), candidates)
        self.assertIn(StartMagicCandidate(shallow_start, 1), candidates)
        self.assertEqual(decode_v1_carrier(tampered, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Tampered")

    def test_edited_header_k_is_cannot_verify(self):
        (encoded, layout, _), context = encode_image_carrier(start=17, k=3)
        edited_header = serialize_packet_header(4, IMAGE_MEDIA_CODE, layout.payload_length)
        edited = encoded.copy()
        units = ceil_unit_count(PACKET_HEADER_SIZE * 8, layout.lsb_count)
        edited[layout.start_unit:layout.start_unit + units] = write_lsb_bits(
            edited[layout.start_unit:layout.start_unit + units], bytes_to_bit_sequence(edited_header), layout.lsb_count
        )
        self.assertEqual(decode_v1_carrier(edited, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Cannot Verify")

    def test_relocated_packet_is_signature_invalid(self):
        source = carrier(30000)
        (encoded, layout, _), context = encode_image_carrier(source, start=50, k=3)
        bits = read_lsb_bits(encoded[layout.start_unit:layout.start_unit + layout.footprint], layout.footprint * layout.lsb_count, layout.lsb_count)
        relocated = source.copy()
        new_start = 5000
        relocated[new_start:new_start + layout.footprint] = write_lsb_bits(
            relocated[new_start:new_start + layout.footprint], bits, layout.lsb_count
        )
        # Moving the mask window also changes the media hash, but signature checking occurs first.
        self.assertEqual(decode_v1_carrier(relocated, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Signature Invalid")

    def test_declared_footprint_out_of_range_is_wrong_start_location(self):
        (encoded, layout, _), context = encode_image_carrier(start=17, k=3)
        oversized_header = serialize_packet_header(layout.lsb_count, IMAGE_MEDIA_CODE, 100000)
        edited = encoded.copy()
        units = ceil_unit_count(PACKET_HEADER_SIZE * 8, layout.lsb_count)
        edited[layout.start_unit:layout.start_unit + units] = write_lsb_bits(
            edited[layout.start_unit:layout.start_unit + units], bytes_to_bit_sequence(oversized_header), layout.lsb_count
        )
        self.assertEqual(decode_v1_carrier(edited, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Wrong Start Location")

    def test_nonzero_alignment_padding_is_cannot_verify(self):
        (encoded, layout, _), context = encode_image_carrier(start=17, k=5)
        self.assertGreater(layout.pad_bits, 0)
        changed = embedded_bit_flip(encoded, layout.start_unit, layout.lsb_count, layout.footprint * layout.lsb_count - 1)
        self.assertEqual(decode_v1_carrier(changed, IMAGE_MEDIA_CODE, context, PUBLIC_KEY).verdict, "Cannot Verify")

    def test_capacity_failure_does_not_modify_input(self):
        source = carrier(1000)
        before = source.copy()
        with self.assertRaisesRegex(ValueError, "footprint does not fit"):
            encode_v1_carrier(source, IMAGE_MEDIA_CODE, struct.pack(">II", 1, 1), PRIVATE_KEY, 0, 1, b"x" * 5000, b"")
        self.assertTrue(np.array_equal(source, before))

    def test_k8_hash_and_preservation_honesty(self):
        source = carrier(10000)
        (encoded, layout, _), context = encode_image_carrier(source, start=200, k=8)
        result = decode_v1_carrier(encoded, IMAGE_MEDIA_CODE, context, PUBLIC_KEY)
        self.assertEqual(result.verdict, "Authentic")
        expected = 8 * (source.size - layout.footprint)
        self.assertEqual(result.preserved_bits, expected)
        self.assertEqual(result.preserved_ratio, expected / (source.size * 8))

        inside_changed = source.copy()
        inside_changed[layout.start_unit] ^= np.uint8(0xFF)
        self.assertEqual(
            calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint),
            calculate_masked_media_hash(inside_changed, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint),
        )
        outside_changed = source.copy()
        outside_changed[0] ^= np.uint8(1)
        self.assertNotEqual(
            calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint),
            calculate_masked_media_hash(outside_changed, IMAGE_MEDIA_CODE, 8, layout.start_unit, layout.footprint),
        )

        exact_size = ceil_unit_count((PACKET_HEADER_SIZE + payload_length() + RSA_SIGNATURE_SIZE) * 8, 8)
        exact_source = carrier(exact_size)
        exact_context = struct.pack(">II", exact_size, 1)
        exact_encoded, exact_layout, _ = encode_v1_carrier(
            exact_source, IMAGE_MEDIA_CODE, exact_context, PRIVATE_KEY, 0, 8, b"hello", b"{}"
        )
        exact_result = decode_v1_carrier(exact_encoded, IMAGE_MEDIA_CODE, exact_context, PUBLIC_KEY)
        self.assertEqual(exact_layout.footprint, exact_size)
        self.assertEqual(exact_result.verdict, "Authentic")
        self.assertEqual(exact_result.preserved_bits, 0)
        self.assertEqual(exact_result.preserved_ratio, 0.0)

    def test_png_and_wav_file_round_trips(self):
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            png_input = directory / "input.png"
            png_output = directory / "output.png"
            image = np.arange(120 * 120 * 3, dtype=np.uint8).reshape((120, 120, 3))
            Image.fromarray(image, mode="RGB").save(png_input)
            encode_png_v1(png_input, png_output, PRIVATE_KEY, 101, 3, b"PNG bytes \xff", b"kind=image")
            png_result = verify_png_v1(png_output, PUBLIC_KEY)
            self.assertEqual(png_result.verdict, "Authentic")
            self.assertEqual(png_result.payload.user_payload, b"PNG bytes \xff")

            wav_input = directory / "input.wav"
            wav_output = directory / "output.wav"
            with wave.open(str(wav_input), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(1)
                wav_file.setframerate(8000)
                wav_file.writeframes(bytes(range(256)) * 80)
            encode_wav_v1(wav_input, wav_output, PRIVATE_KEY, 73, 5, b"WAV bytes", b"kind=audio")
            wav_result = verify_wav_v1(wav_output, PUBLIC_KEY)
            self.assertEqual(wav_result.verdict, "Authentic")
            self.assertEqual(wav_result.payload.metadata, b"kind=audio")

    def test_wav_tampering_outside_footprint_is_tampered(self):
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
            layout, _ = encode_wav_v1(wav_input, wav_output, PRIVATE_KEY, 73, 5, b"WAV bytes", b"kind=audio")
            wav_data = load_pcm_wav_from_path(wav_output)
            changed = wav_frame_bytes_to_carrier(wav_data.frame_bytes)
            changed[layout.start_unit + layout.footprint] ^= np.uint8(1)
            save_pcm_wav_to_path(wav_data_with_carrier(wav_data, changed), wav_tampered)
            self.assertEqual(verify_wav_v1(wav_tampered, PUBLIC_KEY).verdict, "Tampered")

    def test_unsupported_image_formats_are_rejected(self):
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
            self.assertEqual(verify_png_v1(jpeg, PUBLIC_KEY).verdict, "Cannot Verify")

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
