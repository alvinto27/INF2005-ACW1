import hashlib
import os
import struct
import time
import tracemalloc
import unittest
import wave
import zlib
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np
import stego
from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from stego import *
from stego.carrier import (
    DEFAULT_CHUNK_BYTES,
    ArrayCarrier,
    _packed_lsb_range_transform,
    lsb_range_transform,
)
from stego.core import (
    CarrierEncoding,
    decode_carrier,
    decode_carrier_source,
    encode_carrier,
    prepare_carrier_encoding,
)
from stego.layout import calculate_masked_media_hash
from stego.media import (
    _save_png_array_to_path,
    encode_png_media_context,
    encode_wav_media_context,
    load_png_from_path,
    rgb_array_to_carrier,
)
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


def reference_write_lsb_bits(
    carrier_units: np.ndarray, bit_sequence: np.ndarray, lsb_count: int
) -> np.ndarray:
    """Reference the original per-bit writer for exact-semantics tests."""
    result = carrier_units.copy()
    for bit_index, bit in enumerate(bit_sequence):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        mask = 1 << position
        result[unit_index] = np.uint8(
            (int(result[unit_index]) & ~mask) | (int(bit) << position)
        )
    return result


def reference_read_lsb_bits(
    carrier_units: np.ndarray, bit_length: int, lsb_count: int
) -> np.ndarray:
    """Reference the original per-bit reader for exact-semantics tests."""
    result = np.empty(bit_length, dtype=np.uint8)
    for bit_index in range(bit_length):
        unit_index, offset = divmod(bit_index, lsb_count)
        position = lsb_count - 1 - offset
        result[bit_index] = (int(carrier_units[unit_index]) >> position) & 1
    return result


class TestPackedBitHandling(unittest.TestCase):
    """Check vectorized bit operations and packed chunk transforms."""

    def test_decoder_reads_packet_in_bounded_chunks(self) -> None:
        """Packet reads stay bounded and split at awkward test chunk edges."""
        original = carrier(12000)
        context = struct.pack(">II", 4000, 1)
        encoding = prepare_carrier_encoding(
            ArrayCarrier(original, 113),
            IMAGE_MEDIA_CODE,
            context,
            PRIVATE_KEY,
            RECEIVER_PUBLIC_KEY,
            2048,
            3,
            b"chunked packet extraction " * 40,
            b"kind=chunk-test",
        )
        encoded = ArrayCarrier(original, 113).rewrite(encoding.embed_chunk)
        encoding.finish()
        tracked = ReadTrackingCarrier(encoded, 127)
        with patch("stego.core.DEFAULT_CHUNK_BYTES", 37):
            result = decode_carrier_source(
                tracked,
                IMAGE_MEDIA_CODE,
                context,
                PUBLIC_KEY,
                RECEIVER_PRIVATE_KEY,
            )
        self.assertEqual(result.verdict, "Authentic", result.detail)
        packet_reads = [
            count
            for start, count in tracked.read_ranges
            if encoding.layout.start_unit
            <= start
            < encoding.layout.start_unit + encoding.layout.footprint
        ]
        self.assertGreater(len(packet_reads), 1)
        self.assertEqual(sum(packet_reads), encoding.layout.footprint)
        self.assertLessEqual(max(packet_reads), 32)

    def test_vectorized_lsb_operations_match_per_bit_references(self) -> None:
        rng = np.random.default_rng(202503)
        units = rng.integers(0, 256, 40, dtype=np.uint8)
        for lsb_count in range(1, 9):
            lengths = {
                0,
                1,
                max(1, lsb_count - 1),
                lsb_count,
                lsb_count + 1,
                3 * lsb_count,
                3 * lsb_count + 1,
            }
            for bit_length in sorted(lengths):
                bits = rng.integers(0, 2, bit_length, dtype=np.uint8)
                with self.subTest(lsb_count=lsb_count, bit_length=bit_length):
                    self.assertTrue(
                        np.array_equal(
                            write_lsb_bits(units, bits, lsb_count),
                            reference_write_lsb_bits(units, bits, lsb_count),
                        )
                    )
                    self.assertTrue(
                        np.array_equal(
                            read_lsb_bits(units, bit_length, lsb_count),
                            reference_read_lsb_bits(units, bit_length, lsb_count),
                        )
                    )

    def test_packed_range_transform_is_independent_of_chunk_edges(self) -> None:
        rng = np.random.default_rng(202504)
        source = rng.integers(0, 256, 5000, dtype=np.uint8)
        region_start = 23
        payload = bytes(rng.integers(0, 256, 251, dtype=np.uint8))
        for lsb_count in range(1, 9):
            bit_length = ceil_unit_count(len(payload) * 8, lsb_count) * lsb_count
            padded_bits = np.zeros(bit_length, dtype=np.uint8)
            payload_bits = bytes_to_bit_sequence(payload)
            padded_bits[:payload_bits.size] = payload_bits
            expected = source.copy()
            region_units = ceil_unit_count(bit_length, lsb_count)
            expected[region_start:region_start + region_units] = reference_write_lsb_bits(
                expected[region_start:region_start + region_units],
                padded_bits,
                lsb_count,
            )
            transform = _packed_lsb_range_transform(
                region_start, payload, bit_length, lsb_count
            )
            for chunk_units in (1, 2, 3, 5, 7, 13, 31, 997):
                with self.subTest(lsb_count=lsb_count, chunk_units=chunk_units):
                    actual = ArrayCarrier(source, chunk_units).rewrite(transform)
                    self.assertTrue(np.array_equal(actual, expected))

    def test_packed_encoder_output_matches_reference_embedding(self) -> None:
        source_units = carrier(30000)
        context = struct.pack(">II", 10000, 1)
        encoding = prepare_carrier_encoding(
            ArrayCarrier(source_units, 137),
            IMAGE_MEDIA_CODE,
            context,
            PRIVATE_KEY,
            RECEIVER_PUBLIC_KEY,
            2048,
            5,
            b"byte-identical packed path",
            b"kind=test",
        )
        actual = ArrayCarrier(source_units, 137).rewrite(encoding.embed_chunk)
        reference = source_units.copy()
        envelope_bits = bytes_to_bit_sequence(encoding._envelope)
        reference[:encoding.layout.bootstrap_span] = reference_write_lsb_bits(
            reference[:encoding.layout.bootstrap_span],
            envelope_bits,
            BOOTSTRAP_LSB_COUNT,
        )
        packet_bit_length = encoding.layout.footprint * encoding.layout.lsb_count
        packet_bits = np.zeros(packet_bit_length, dtype=np.uint8)
        raw_packet_bits = bytes_to_bit_sequence(encoding._packet)
        packet_bits[:raw_packet_bits.size] = raw_packet_bits
        start = encoding.layout.start_unit
        end = start + encoding.layout.footprint
        reference[start:end] = reference_write_lsb_bits(
            reference[start:end], packet_bits, encoding.layout.lsb_count
        )
        self.assertTrue(np.array_equal(actual, reference))
        encoding.finish()
        result = decode_carrier_source(
            ArrayCarrier(actual, 113),
            IMAGE_MEDIA_CODE,
            context,
            PUBLIC_KEY,
            RECEIVER_PRIVATE_KEY,
        )
        self.assertEqual(result.verdict, "Authentic", result.detail)


class TestMaskedStego(unittest.TestCase):
    def test_constants_and_minimal_media_contexts(self) -> None:
        self.assertEqual(MEDIA_HASH_DOMAIN, b"INF2005-ACW1\x00MEDIA-HASH-V3\x00")
        self.assertEqual(PROTOCOL_VERSION, 3)
        self.assertEqual(SIGNING_DOMAIN, b"INF2005-ACW1\x00SIGN\x00")
        self.assertEqual(encode_png_media_context((7, 11, 3)), struct.pack(">IIB", 11, 7, 3))
        self.assertEqual(encode_png_media_context((7, 11, 4)), struct.pack(">IIB", 11, 7, 4))
        wav_info = WavPcmInfo(2, 2, 44100, 3)
        self.assertEqual(encode_wav_media_context(wav_info), struct.pack(">HBIQ", 2, 2, 44100, 3))

    def test_png_carrier_units_chunks_rewrite_and_context(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            input_path = directory / "input.png"
            output_path = directory / "identity.png"
            image_array = np.arange(37 * 29 * 3, dtype=np.uint8).reshape((37, 29, 3))
            Image.fromarray(image_array, mode="RGB").save(input_path)
            with Image.open(input_path) as image:
                reference_units = np.asarray(image, dtype=np.uint8).reshape(-1).copy()
            expected_context = struct.pack(">IIB", 29, 37, 3)
            for chunk_units in (1, 13, 2048, 4096):
                source = PngCarrier(input_path, chunk_units)
                self.assertEqual(source.media_code, IMAGE_MEDIA_CODE)
                self.assertEqual(source.media_context, expected_context)
                self.assertEqual(source.total_units, reference_units.size)
                self.assertTrue(np.array_equal(np.concatenate(list(source.iter_chunks())), reference_units))
                self.assertTrue(np.array_equal(source.read_units(17, 31), reference_units[17:48]))
            source = PngCarrier(input_path, 13)

            def identity_transform(chunk_start: int, units: np.ndarray) -> np.ndarray:
                return units

            source.rewrite_to_path(output_path, identity_transform)
            with Image.open(output_path) as image:
                rewritten_pixels = np.asarray(image, dtype=np.uint8).copy()
            self.assertTrue(np.array_equal(rewritten_pixels, image_array))

    def test_png_carrier_ranges_chunks_and_identity_bytes_match_reference(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            generator = np.random.default_rng(6206)
            for channels in (3, 4):
                mode = "RGB" if channels == 3 else "RGBA"
                image_array = generator.integers(
                    0, 256, (31, 29, channels), dtype=np.uint8
                )
                input_path = directory / f"input-{channels}.png"
                expected_path = directory / f"expected-{channels}.png"
                output_path = directory / f"identity-{channels}.png"
                Image.fromarray(image_array, mode=mode).save(input_path)
                reference_units = rgb_array_to_carrier(load_png_from_path(input_path))
                source = PngCarrier(input_path, 19)

                self.assertEqual(source.total_units, reference_units.size)
                self.assertFalse(source._pixels.flags.writeable)
                if channels == 4:
                    self.assertIsNotNone(source._alpha)
                    self.assertFalse(source._alpha.flags.writeable)
                    self.assertTrue(np.shares_memory(source._pixels, source._alpha))
                else:
                    self.assertIsNone(source._alpha)

                ranges = [(0, 0), (0, 1), (1, 7), (17, 19), (18, 24)]
                ranges.extend(
                    (start, min(37, reference_units.size - start))
                    for start in range(0, reference_units.size, 113)
                )
                for start, count in ranges:
                    actual = source.read_units(start, count)
                    self.assertTrue(np.array_equal(actual, reference_units[start:start + count]))
                    self.assertTrue(actual.flags.writeable)

                chunks = list(source.iter_chunks())
                self.assertTrue(np.array_equal(np.concatenate(chunks), reference_units))
                paired_chunks = list(source.iter_chunks_with_fixed_bytes())
                self.assertTrue(
                    np.array_equal(
                        np.concatenate([units for units, _ in paired_chunks]),
                        reference_units,
                    )
                )
                expected_fixed = (
                    b""
                    if channels == 3
                    else image_array[:, :, 3].tobytes()
                )
                self.assertEqual(
                    b"".join(fixed for _, fixed in paired_chunks), expected_fixed
                )

                def identity_transform(start: int, units: np.ndarray) -> np.ndarray:
                    return units

                _save_png_array_to_path(image_array, expected_path)
                source.rewrite_to_path(output_path, identity_transform)
                self.assertEqual(output_path.read_bytes(), expected_path.read_bytes())

    def test_png_carrier_load_and_rewrite_memory_is_bounded(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            input_path = directory / "input.png"
            output_path = directory / "identity.png"
            image_array = np.zeros((2400, 2400, 4), dtype=np.uint8)
            image_array[:, :, 0] = np.arange(2400, dtype=np.uint8)[None, :]
            image_array[:, :, 1] = np.arange(2400, dtype=np.uint8)[:, None]
            image_array[:, :, 3] = 255
            Image.fromarray(image_array, mode="RGBA").save(input_path)
            decoded_size = image_array.nbytes
            del image_array

            def identity_transform(start: int, units: np.ndarray) -> np.ndarray:
                return units

            tracemalloc.start()
            source = PngCarrier(input_path)
            source.rewrite_to_path(output_path, identity_transform)
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            memory_limit = int(2.5 * decoded_size + 2 * 1024 * 1024)
            self.assertLess(
                peak_bytes,
                memory_limit,
                f"traced peak={peak_bytes / 1024 / 1024:.2f} MiB; "
                f"limit={memory_limit / 1024 / 1024:.2f} MiB",
            )

    def test_public_api_excludes_array_and_removed_wav_helpers(self) -> None:
        removed_names = {
            "ArrayCarrier", "encode_carrier", "decode_carrier",
            "calculate_masked_media_hash", "rgb_array_to_carrier",
            "carrier_to_rgb_array", "load_png_from_path", "save_rgb_png_to_path",
            "encode_png_media_context", "encode_wav_media_context",
            "WavPcmData", "load_pcm_wav_from_path", "wav_frame_bytes_to_carrier",
            "wav_data_with_carrier", "save_pcm_wav_to_path", "MAX_WAV_FRAME_BYTES",
        }
        self.assertFalse(removed_names.intersection(stego.__all__))
        self.assertFalse(any(hasattr(stego, name) for name in removed_names))
        self.assertIn("PngCarrier", stego.__all__)
        self.assertIn("WavCarrier", stego.__all__)
        self.assertIn("lsb_range_transform", stego.__all__)

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
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00\x00\x00\x00\x02"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + hashlib.sha256(expected_masked.tobytes()).digest()
            + hashlib.sha256(b"").digest()
        )
        self.assertEqual(calculate_masked_media_hash(source, IMAGE_MEDIA_CODE, 3, 1, 2, 0), hashlib.sha256(preimage).digest())
        self.assertTrue(np.array_equal(source, np.array([0xFF, 0xA5, 0x5A, 0x00], dtype=np.uint8)))

    def test_signing_input_has_exact_approved_bytes(self):
        layout = EmbeddingLayout(1000, 13, 300, 3, 5, 0, 0)
        payload = b"abcde"
        expected = (
            SIGNING_DOMAIN
            + struct.pack(">BBB", 3, IMAGE_MEDIA_CODE, 3)
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
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x04"
            + b"\x00\x00\x00\x00\x00\x00\x00\x02"
            + b"\x00\x00\x00\x00\x00\x00\x00\x02"
            + hashlib.sha256(expected_masked.tobytes()).digest()
            + hashlib.sha256(b"").digest()
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
        fields = BootstrapFields(3, 3, 13, 37, bytes(range(32)), bytes(range(12)))
        expected_aad = b"\x03\x03" + (13).to_bytes(8, "big") + (37).to_bytes(8, "big")
        serialized = serialize_bootstrap(fields)
        self.assertEqual(len(serialized), 62)
        self.assertEqual(parse_bootstrap(serialized), fields)
        self.assertEqual(encode_bootstrap_aad(fields), expected_aad)

    def test_bootstrap_span_and_oaep_envelope_limit(self) -> None:
        fields = BootstrapFields(3, 3, 13, 37, bytes(range(32)), bytes(range(12)))
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
        fields = BootstrapFields(3, 3, 13, 37, bytes(range(32)), bytes(range(12)))
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
            {"version": 2},
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
                if "version" in changes:
                    self.assertEqual(result.detail, "unsupported bootstrap version")
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

    def test_rgba_png_round_trip_preserves_alpha_and_hashes_it(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            png_input = directory / "rgba-input.png"
            png_output = directory / "rgba-output.png"
            png_tampered = directory / "rgba-tampered.png"
            rgba = np.random.default_rng(12).integers(0, 256, (100, 100, 4), dtype=np.uint8)
            rgba[:, :, 3] = np.arange(10000, dtype=np.uint8).reshape((100, 100))
            rgba[0, 0, 3] = 0
            Image.fromarray(rgba, mode="RGBA").save(png_input)
            source = PngCarrier(png_input, 7)
            self.assertEqual(source.channel_count, 4)
            self.assertEqual(source.fixed_byte_count, 10000)
            encode_png(png_input, png_output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"rgba", b"")
            with Image.open(png_output) as image:
                encoded = np.asarray(image, dtype=np.uint8).copy()
            self.assertTrue(np.array_equal(encoded[:, :, 3], rgba[:, :, 3]))
            self.assertEqual(verify_png(png_output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Authentic")
            encoded[40, 50, 3] ^= np.uint8(1)
            Image.fromarray(encoded, mode="RGBA").save(png_tampered)
            self.assertEqual(verify_png(png_tampered, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Tampered")

    def test_png_format_errors_remain_specific(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            unsupported_images = (
                ("palette", Image.new("P", (8, 8)), "PNG must be RGB or RGBA; palette and grayscale images are not supported"),
                ("grayscale", Image.new("L", (8, 8)), "PNG must be RGB or RGBA; palette and grayscale images are not supported"),
                ("gray-alpha", Image.new("LA", (8, 8)), "PNG must be RGB or RGBA; palette and grayscale images are not supported"),
                ("sixteen-bit-gray", Image.fromarray(np.zeros((8, 8), dtype=np.uint16)), "PNG must be RGB or RGBA; palette and grayscale images are not supported"),
            )
            for name, image, message in unsupported_images:
                with self.subTest(name=name):
                    path = directory / f"{name}.png"
                    image.save(path)
                    with self.assertRaisesRegex(ValueError, message):
                        PngCarrier(path)
                    result = verify_png(path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                    self.assertEqual((result.verdict, result.detail), ("Cannot Verify", message))

            rgb16_path = directory / "sixteen-bit-rgb.png"
            write_rgb16_png(rgb16_path)
            with self.assertRaisesRegex(ValueError, "PNG must use 8-bit RGB or RGBA samples"):
                PngCarrier(rgb16_path)
            rgb16_result = verify_png(rgb16_path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(
                (rgb16_result.verdict, rgb16_result.detail),
                ("Cannot Verify", "PNG must use 8-bit RGB or RGBA samples"),
            )

            animated_path = directory / "animated.png"
            frame = Image.new("RGBA", (8, 8), (0, 0, 0, 255))
            second_frame = Image.new("RGBA", (8, 8), (255, 0, 0, 255))
            frame.save(animated_path, save_all=True, append_images=[second_frame], duration=50)
            with self.assertRaisesRegex(ValueError, "animated PNG images are not supported"):
                PngCarrier(animated_path)
            animated_result = verify_png(animated_path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(
                (animated_result.verdict, animated_result.detail),
                ("Cannot Verify", "animated PNG images are not supported"),
            )

            non_png_path = directory / "not-png.jpg"
            Image.new("RGB", (8, 8)).save(non_png_path)
            with self.assertRaisesRegex(UnSupportedFileType, "unsupported file type: JPEG"):
                PngCarrier(non_png_path)
            non_png_result = verify_png(non_png_path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(non_png_result.verdict, "Cannot Verify")
            self.assertEqual(non_png_result.detail, "unsupported file type: JPEG")

    def test_version_2_png_bootstrap_is_cannot_verify_not_tampered(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            input_path = directory / "input.png"
            v3_path = directory / "v3.png"
            v2_path = directory / "v2-bootstrap.png"
            Image.fromarray(np.zeros((100, 100, 3), dtype=np.uint8), mode="RGB").save(input_path)
            encode_png(input_path, v3_path, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"version", b"")
            with Image.open(v3_path) as image:
                rgb = np.asarray(image, dtype=np.uint8).copy()
            units = rgb.reshape(-1).copy()
            fields = bootstrap_fields_from_carrier(units)
            envelope = raw_bootstrap(2, fields.lsb_count, fields.start_unit, fields.ciphertext_length, fields.session_key, fields.aead_nonce)
            span = bootstrap_span(RECEIVER_PRIVATE_KEY)
            units[:span] = write_lsb_bits(units[:span], bytes_to_bit_sequence(envelope), BOOTSTRAP_LSB_COUNT)
            Image.fromarray(units.reshape(rgb.shape), mode="RGB").save(v2_path)
            result = verify_png(v2_path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Cannot Verify")
            self.assertEqual(result.detail, "unsupported bootstrap version")

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
            changed_unit = layout.start_unit + layout.footprint

            def flip_changed_unit(chunk_start: int, units: np.ndarray) -> np.ndarray:
                changed = units.copy()
                if chunk_start <= changed_unit < chunk_start + units.size:
                    changed[changed_unit - chunk_start] ^= np.uint8(1)
                return changed

            WavCarrier(wav_output).rewrite_to_path(wav_tampered, flip_changed_unit)
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
                original_info, original_frame_bytes = reference_wav_data(wav_input)
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
                        stego_info, stego_frame_bytes = reference_wav_data(wav_output)
                        self.assertEqual(stego_info, original_info)
                        original_samples = decode_pcm_samples(original_frame_bytes, sample_width)
                        stego_samples = decode_pcm_samples(stego_frame_bytes, sample_width)
                        max_delta = max(
                            abs(before - after)
                            for before, after in zip(original_samples, stego_samples)
                        )
                        self.assertLessEqual(max_delta, (1 << lsb_count) - 1)
                        self.assertTrue(
                            all(
                                before == after
                                for index, (before, after) in enumerate(
                                    zip(original_frame_bytes, stego_frame_bytes)
                                )
                                if index % sample_width != 0
                            )
                        )
                    tampered_path = directory / f"width-{sample_width}-high-byte-tampered.wav"
                    tampered_data = bytearray(reference_wav_data(wav_output)[1])
                    tampered_data[3 * sample_width + 1] ^= 1
                    with wave.open(str(tampered_path), "wb") as wav_file:
                        wav_file.setnchannels(original_info.channels)
                        wav_file.setsampwidth(original_info.sample_width)
                        wav_file.setframerate(original_info.frame_rate)
                        wav_file.writeframes(tampered_data)
                    self.assertEqual(
                        verify_wav(tampered_path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict,
                        "Tampered",
                    )

    def test_multibyte_wav_capacity_uses_sample_count(self) -> None:
        sample_width = 2
        sample_count = 6000
        lsb_count = 3
        with TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "capacity.wav"
            write_pcm_wav(path, 1, sample_width, sample_count)
            source = WavCarrier(path)
            carrier_units = reference_wav_units(path)
            context = source.media_context
            span = bootstrap_span(RECEIVER_PUBLIC_KEY)
            record_overhead = serialized_record_length(MEDIA_ID_SIZE, 0, 0)
            maximum = max_user_payload_length(source.total_units, span, span, lsb_count, record_overhead)
            self.assertGreater(maximum, 0)
            before = carrier_units.copy()
            encoded, layout, payload = encode_carrier(
                carrier_units, AUDIO_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY,
                span, lsb_count, b"x" * maximum, b"",
            )
            self.assertEqual(layout.total_units, sample_count)
            self.assertEqual(encoded.size, sample_count)
            self.assertEqual(len(payload.user_payload), maximum)
            with self.assertRaisesRegex(ValueError, "user payload exceeds capacity"):
                encode_carrier(
                    carrier_units, AUDIO_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY,
                    span, lsb_count, b"x" * (maximum + 1), b"",
                )
            self.assertTrue(np.array_equal(carrier_units, before))

    def test_wav_carrier_reads_sample_stride(self) -> None:
        with TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "stride.wav"
            write_pcm_wav(path, 1, 3, 4)
            source = WavCarrier(path, chunk_bytes=3)
            expected = reference_wav_units(path)
            self.assertEqual(expected.size, 4)
            self.assertEqual(source.read_units(0, source.total_units).tolist(), expected.tolist())
            self.assertTrue(all(chunk.size <= 1 for chunk in source.iter_chunks()))
        for sample_width in (0, 5):
            with self.subTest(sample_width=sample_width):
                with self.assertRaises(ValueError):
                    WavPcmInfo(1, sample_width, 8000, 1)

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
                PngCarrier(jpeg)
            with self.assertRaisesRegex(ValueError, "PNG must be RGB or RGBA; palette and grayscale images are not supported"):
                PngCarrier(palette)
            with self.assertRaisesRegex(ValueError, "PNG must be RGB or RGBA; palette and grayscale images are not supported"):
                PngCarrier(sixteen)
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


def reference_v3_media_hash(unit_bytes: bytes, fixed_bytes: bytes, media_code: int, lsb_count: int, start_unit: int, footprint: int, bootstrap_span: int) -> bytes:
    """Calculate a v3 hash from raw streams without production hash helpers."""
    masked = bytearray(unit_bytes)
    masked[0:bootstrap_span] = bytes(value & 0xFE for value in masked[0:bootstrap_span])
    mask = (~((1 << lsb_count) - 1)) & 0xFF
    masked[start_unit:start_unit + footprint] = bytes(
        value & mask for value in masked[start_unit:start_unit + footprint]
    )
    preimage = (
        b"INF2005-ACW1\x00MEDIA-HASH-V3\x00"
        + struct.pack(">BB", media_code, lsb_count)
        + len(unit_bytes).to_bytes(8, "big")
        + len(fixed_bytes).to_bytes(8, "big")
        + start_unit.to_bytes(8, "big")
        + footprint.to_bytes(8, "big")
        + bootstrap_span.to_bytes(8, "big")
        + hashlib.sha256(masked).digest()
        + hashlib.sha256(fixed_bytes).digest()
    )
    return hashlib.sha256(preimage).digest()


def reference_masked_media_hash(carrier_units: np.ndarray, media_code: int, lsb_count: int, start_unit: int, footprint: int, bootstrap_span: int) -> bytes:
    """Calculate the array reference through the independent raw-byte oracle."""
    return reference_v3_media_hash(
        carrier_units.tobytes(), b"", media_code, lsb_count, start_unit,
        footprint, bootstrap_span,
    )


def streamed_hash(source: CarrierSource, media_code: int, lsb_count: int, start_unit: int, footprint: int, bootstrap_span: int) -> bytes:
    """Hash paired source chunks using the production streaming hasher."""
    hasher = MaskedMediaHasher(
        media_code, lsb_count, source.total_units, start_unit, footprint,
        bootstrap_span, source.fixed_byte_count,
    )
    for units, fixed_bytes in source.iter_chunks_with_fixed_bytes():
        hasher.update(units, fixed_bytes)
    return hasher.digest()


def random_units(size: int, seed: int = 7) -> np.ndarray:
    return np.random.default_rng(seed).integers(0, 256, size, dtype=np.uint8)


def write_rgb16_png(path: Path) -> None:
    """Write a minimal valid 16-bit RGB PNG for format-error coverage."""
    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        payload = chunk_type + data
        return len(data).to_bytes(4, "big") + payload + zlib.crc32(payload).to_bytes(4, "big")

    header = struct.pack(">IIBBBBB", 1, 1, 16, 2, 0, 0, 0)
    image_data = zlib.compress(b"\x00" + bytes(6))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", image_data)
        + chunk(b"IEND", b"")
    )


def write_pcm_wav(path: Path, channels: int, sample_width: int, frame_count: int, seed: int = 3) -> None:
    frame_bytes = random_units(frame_count * channels * sample_width, seed).tobytes()
    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(channels)
        wav_file.setsampwidth(sample_width)
        wav_file.setframerate(8000)
        wav_file.writeframes(frame_bytes)


def reference_wav_data(path: Path) -> tuple[WavPcmInfo, bytes]:
    """Read WAV header and frames directly as a small test-local reference."""
    with wave.open(str(path), "rb") as wav_file:
        info = WavPcmInfo(
            wav_file.getnchannels(),
            wav_file.getsampwidth(),
            wav_file.getframerate(),
            wav_file.getnframes(),
        )
        return info, wav_file.readframes(info.frame_count)


def reference_wav_units(path: Path) -> np.ndarray:
    """Extract each sample's least-significant byte with the wave module oracle."""
    info, frame_bytes = reference_wav_data(path)
    return np.frombuffer(frame_bytes, dtype=np.uint8)[::info.sample_width].copy()


class ShortCarrier(ArrayCarrier):
    """Declare every unit but yield one unit fewer."""

    def iter_chunks(self) -> Iterator[np.ndarray]:
        chunks = list(super().iter_chunks())
        chunks[-1] = chunks[-1][:-1]
        yield from chunks


class LongCarrier(ArrayCarrier):
    """Declare every unit but yield one unit more."""

    def iter_chunks(self) -> Iterator[np.ndarray]:
        yield from super().iter_chunks()
        yield np.zeros(1, dtype=np.uint8)


class ReadTrackingCarrier(ArrayCarrier):
    """Record bounded ranges requested by a decoder."""

    def __init__(self, carrier_units: np.ndarray, chunk_units: int = DEFAULT_CHUNK_BYTES) -> None:
        super().__init__(carrier_units, chunk_units)
        self.read_ranges: list[tuple[int, int]] = []

    def read_units(self, start_unit: int, count: int) -> np.ndarray:
        self.read_ranges.append((start_unit, count))
        return super().read_units(start_unit, count)


class TestChunkedCarrier(unittest.TestCase):
    SPAN = bootstrap_span(RECEIVER_PUBLIC_KEY)

    def test_four_mib_payload_k8_performance_and_encode_memory(self) -> None:
        """A packed 4 MiB WAV packet stays within normal time and memory limits."""
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            input_path = directory / "large-input.wav"
            output_path = directory / "large-output.wav"
            payload = bytes(range(256)) * (4 * 1024 * 1024 // 256)
            frame_count = len(payload) + 8192
            with wave.open(str(input_path), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(1)
                wav_file.setframerate(8000)
                remaining = frame_count
                block = bytes(1024 * 1024)
                while remaining:
                    frames = min(remaining, len(block))
                    wav_file.writeframesraw(block[:frames])
                    remaining -= frames
                wav_file.writeframes(b"")

            tracemalloc.start()
            started = time.perf_counter()
            encode_wav(
                input_path,
                output_path,
                PRIVATE_KEY,
                RECEIVER_PUBLIC_KEY,
                2048,
                8,
                payload,
                b"kind=performance",
            )
            encode_seconds = time.perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            started = time.perf_counter()
            result = verify_wav(output_path, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            verify_seconds = time.perf_counter() - started
            self.assertEqual(result.verdict, "Authentic", result.detail)
            self.assertEqual(result.payload.user_payload, payload)
            self.assertLess(
                encode_seconds + verify_seconds,
                10.0,
                f"encode={encode_seconds:.3f}s verify={verify_seconds:.3f}s",
            )
            memory_limit = 4 * len(payload) + 16 * 1024 * 1024
            self.assertLess(
                peak_bytes,
                memory_limit,
                f"encode peak={peak_bytes / 1024 / 1024:.2f} MiB; "
                f"limit={memory_limit / 1024 / 1024:.2f} MiB",
            )

    def test_wav_carrier_media_properties(self) -> None:
        with TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "media-context.wav"
            write_pcm_wav(path, 2, 2, 3001)
            source = WavCarrier(path, 64)
            info = read_pcm_wav_info(path)
            self.assertEqual(source.media_code, AUDIO_MEDIA_CODE)
            self.assertEqual(
                source.media_context,
                struct.pack(">HBIQ", info.channels, info.sample_width, info.frame_rate, info.frame_count),
            )

    def test_v3_raw_reference_hash_matches_png_and_wav_chunk_streams(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            cases: list[tuple[str, Path, bytes, bytes, int]] = []
            for channels in (3, 4):
                image = np.random.default_rng(100 + channels).integers(
                    0, 256, (90, 91, channels), dtype=np.uint8
                )
                path = directory / f"channels-{channels}.png"
                Image.fromarray(image, mode="RGB" if channels == 3 else "RGBA").save(path)
                with Image.open(path) as decoded:
                    raw_pixels = np.asarray(decoded, dtype=np.uint8).copy()
                unit_bytes = raw_pixels[:, :, :3].tobytes()
                fixed_bytes = b"" if channels == 3 else raw_pixels[:, :, 3].tobytes()
                cases.append((f"png-{channels}", path, unit_bytes, fixed_bytes, IMAGE_MEDIA_CODE))

            for channels, sample_width in ((1, 1), (2, 2), (1, 3), (2, 4)):
                path = directory / f"wav-{channels}-{sample_width}.wav"
                write_pcm_wav(path, channels, sample_width, 6000 // channels, seed=channels + sample_width)
                info, raw_samples = reference_wav_data(path)
                matrix = np.frombuffer(raw_samples, dtype=np.uint8).reshape((-1, info.sample_width))
                cases.append((
                    f"wav-{channels}-{sample_width}", path, matrix[:, 0].tobytes(),
                    matrix[:, 1:].tobytes(), AUDIO_MEDIA_CODE,
                ))

            for name, path, unit_bytes, fixed_bytes, media_code in cases:
                start_unit = self.SPAN + 19
                footprint = 1000
                expected = reference_v3_media_hash(
                    unit_bytes, fixed_bytes, media_code, 3, start_unit, footprint, self.SPAN
                )
                with self.subTest(name=name):
                    for chunk_size in (1, 7, 17, 1024):
                        if name.startswith("png"):
                            source = PngCarrier(path, chunk_size)
                        else:
                            source = WavCarrier(path, chunk_size)
                        self.assertEqual(source.fixed_byte_count, len(fixed_bytes))
                        self.assertEqual(
                            streamed_hash(source, media_code, 3, start_unit, footprint, self.SPAN),
                            expected,
                        )

    def test_lsb_range_transform_crosses_chunk_edges(self) -> None:
        source = random_units(12000)
        bit_sequence = np.random.default_rng(19).integers(0, 2, 179, dtype=np.uint8)
        region_start = 2077
        for lsb_count in (1, 3, 8):
            touched_units = ceil_unit_count(bit_sequence.size, lsb_count)
            expected = source.copy()
            expected[region_start:region_start + touched_units] = write_lsb_bits(
                expected[region_start:region_start + touched_units], bit_sequence, lsb_count
            )
            for chunk_units in (13, 64, 997, 2048):
                with self.subTest(lsb_count=lsb_count, chunk_units=chunk_units):
                    transformed = ArrayCarrier(source, chunk_units).rewrite(
                        lsb_range_transform(region_start, bit_sequence, lsb_count)
                    )
                    self.assertTrue(np.array_equal(transformed, expected))

    def test_streamed_hash_equals_whole_array_reference(self) -> None:
        cases = (
            (0, 0, 0),
            (5000, 2048, 0),
            (5000, 2048, 1),
            (5000, 2048, 2952),
            (24000, 3001, 17),
        )
        for total, start, footprint in cases:
            for lsb_count in (1, 3, 8):
                with self.subTest(total=total, start=start, footprint=footprint, lsb_count=lsb_count):
                    source = random_units(total)
                    span = min(start, self.SPAN)
                    expected = reference_masked_media_hash(source, AUDIO_MEDIA_CODE, lsb_count, start, footprint, span)
                    self.assertEqual(calculate_masked_media_hash(source, AUDIO_MEDIA_CODE, lsb_count, start, footprint, span), expected)
                    self.assertEqual(streamed_hash(ArrayCarrier(source, 997), AUDIO_MEDIA_CODE, lsb_count, start, footprint, span), expected)

    def test_chunk_size_does_not_change_digest(self) -> None:
        source = random_units(12000)
        expected = reference_masked_media_hash(source, IMAGE_MEDIA_CODE, 3, 4000, 3000, self.SPAN)
        for chunk_units in (1, 2, 7, 64, 2047, 2048, 2049, 4096, 12000, 50000):
            with self.subTest(chunk_units=chunk_units):
                self.assertEqual(
                    streamed_hash(ArrayCarrier(source, chunk_units), IMAGE_MEDIA_CODE, 3, 4000, 3000, self.SPAN),
                    expected,
                )

    def test_masks_cross_chunk_edges(self) -> None:
        source = random_units(12000)
        start, footprint = 4000, 3000
        cases = {
            "bootstrap crosses one edge": 1000,
            "packet crosses one edge": 4500,
            "packet spans many chunks": 250,
        }
        for name, chunk_units in cases.items():
            for lsb_count in (1, 3, 8):
                with self.subTest(case=name, lsb_count=lsb_count):
                    carrier_source = ArrayCarrier(source, chunk_units)
                    edges = set(range(chunk_units, source.size, chunk_units))
                    if name.startswith("bootstrap"):
                        self.assertTrue(any(0 < edge < self.SPAN for edge in edges))
                    elif name.startswith("packet crosses"):
                        self.assertEqual(sum(start < edge < start + footprint for edge in edges), 1)
                    else:
                        self.assertGreater(sum(start < edge < start + footprint for edge in edges), 5)
                    baseline = streamed_hash(carrier_source, IMAGE_MEDIA_CODE, lsb_count, start, footprint, self.SPAN)
                    self.assertEqual(baseline, reference_masked_media_hash(source, IMAGE_MEDIA_CODE, lsb_count, start, footprint, self.SPAN))
                    for edge in sorted(edges)[:3]:
                        for unit in (edge - 1, edge):
                            masked_bits = 1 if unit < self.SPAN else lsb_count if start <= unit < start + footprint else 0
                            if masked_bits:
                                inside = source.copy()
                                inside[unit] ^= np.uint8((1 << masked_bits) - 1)
                                self.assertEqual(streamed_hash(ArrayCarrier(inside, chunk_units), IMAGE_MEDIA_CODE, lsb_count, start, footprint, self.SPAN), baseline)
                            if masked_bits < 8:
                                outside = source.copy()
                                outside[unit] ^= np.uint8(1 << masked_bits)
                                self.assertNotEqual(streamed_hash(ArrayCarrier(outside, chunk_units), IMAGE_MEDIA_CODE, lsb_count, start, footprint, self.SPAN), baseline)

    def test_alignment_padding_units_are_masked(self) -> None:
        source = carrier(10000)
        (encoded, layout, _), context = encode_image_carrier(source, start=2048, k=5, user_payload=b"x")
        self.assertGreater(layout.pad_bits, 0)
        last_unit = layout.start_unit + layout.footprint - 1
        changed = source.copy()
        changed[last_unit] ^= np.uint8(0b11111)
        for chunk_units in (1, 13, last_unit - 1, last_unit, last_unit + 1):
            with self.subTest(chunk_units=chunk_units):
                self.assertEqual(
                    streamed_hash(ArrayCarrier(changed, chunk_units), IMAGE_MEDIA_CODE, 5, layout.start_unit, layout.footprint, layout.bootstrap_span),
                    streamed_hash(ArrayCarrier(source, chunk_units), IMAGE_MEDIA_CODE, 5, layout.start_unit, layout.footprint, layout.bootstrap_span),
                )

    def test_hasher_rejects_wrong_unit_counts(self) -> None:
        hasher = MaskedMediaHasher(IMAGE_MEDIA_CODE, 3, 10, 4, 2, 2)
        hasher.update(np.zeros(9, dtype=np.uint8))
        with self.assertRaisesRegex(ValueError, "fewer units than total_units.*consumed_units=9.*total_units=10"):
            hasher.digest()
        with self.assertRaisesRegex(ValueError, "more units than total_units.*consumed_units=11"):
            hasher.update(np.zeros(2, dtype=np.uint8))

    def test_hasher_rejects_wrong_fixed_byte_counts(self) -> None:
        hasher = MaskedMediaHasher(IMAGE_MEDIA_CODE, 3, 10, 4, 2, 2, 2)
        hasher.update(np.zeros(10, dtype=np.uint8), b"x")
        self.assertEqual(hasher.consumed_fixed_bytes, 1)
        with self.assertRaisesRegex(ValueError, "fewer fixed bytes than fixed_byte_count"):
            hasher.digest()

        hasher = MaskedMediaHasher(IMAGE_MEDIA_CODE, 3, 10, 4, 2, 2, 1)
        with self.assertRaisesRegex(ValueError, "more fixed bytes than fixed_byte_count"):
            hasher.update(np.zeros(10, dtype=np.uint8), b"xy")

    def test_short_and_long_carrier_streams_cannot_verify(self) -> None:
        (encoded, layout, _), context = encode_image_carrier(carrier(10000))
        self.assertEqual(decode_carrier_source(ArrayCarrier(encoded, 999), IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Authentic")
        for source_type, detail in ((ShortCarrier, "fewer units"), (LongCarrier, "more units")):
            with self.subTest(source=source_type.__name__):
                result = decode_carrier_source(source_type(encoded, 999), IMAGE_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                self.assertEqual(result.verdict, "Cannot Verify")
                self.assertIn(detail, result.detail)
                with self.assertRaisesRegex(ValueError, detail):
                    encode_carrier_source_from(source_type(carrier(10000), 999))

    def test_carrier_ranges_are_checked(self) -> None:
        source = ArrayCarrier(carrier(10), 4)
        self.assertEqual(source.read_units(8, 2).tolist(), [8, 9])
        self.assertEqual(source.read_units(10, 0).size, 0)
        for start_unit, count in ((9, 2), (11, 0)):
            with self.subTest(start_unit=start_unit, count=count):
                with self.assertRaisesRegex(CarrierAccessError, "out of bounds"):
                    source.read_units(start_unit, count)
        with self.assertRaises(ValueError):
            ArrayCarrier(carrier(10), 0)

    def test_embedding_requires_chunks_in_order(self) -> None:
        encoding = encode_carrier_source_from(ArrayCarrier(carrier(10000)))
        with self.assertRaisesRegex(ValueError, "in order"):
            encoding.embed_chunk(5, np.zeros(5, dtype=np.uint8))

    def test_array_input_change_between_passes_is_detected(self) -> None:
        source = carrier(10000)
        encoding = encode_carrier_source_from(ArrayCarrier(source))
        source[9000] ^= np.uint8(0x80)
        with self.assertRaisesRegex(ValueError, "carrier changed between encoding passes"):
            ArrayCarrier(source).rewrite(encoding.embed_chunk)
            encoding.finish()

    def test_wav_units_hash_and_ranges_match_legacy_loader(self) -> None:
        formats = ((1, 1), (1, 2), (2, 2), (2, 3), (1, 4), (3, 4))
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            for channels, sample_width in formats:
                with self.subTest(channels=channels, sample_width=sample_width):
                    path = directory / f"c{channels}-w{sample_width}.wav"
                    write_pcm_wav(path, channels, sample_width, 3001)
                    expected = reference_wav_units(path)
                    info, raw_samples = reference_wav_data(path)
                    raw_matrix = np.frombuffer(raw_samples, dtype=np.uint8).reshape((-1, info.sample_width))
                    fixed_bytes = raw_matrix[:, 1:].tobytes()
                    expected_hash = reference_v3_media_hash(
                        expected.tobytes(), fixed_bytes, AUDIO_MEDIA_CODE, 3, 2100, 500, 2048
                    )
                    for chunk_bytes in (1, 7 * channels * sample_width, 4096, 1 << 20):
                        source = WavCarrier(path, chunk_bytes)
                        self.assertEqual(source.total_units, expected.size)
                        chunks = list(source.iter_chunks())
                        self.assertTrue(all(chunk.size % channels == 0 for chunk in chunks))
                        self.assertTrue(np.array_equal(np.concatenate(chunks), expected))
                        for start_unit, count in ((0, 1), (1, channels * 5 + 1), (expected.size - 3, 3), (17, 0)):
                            self.assertTrue(np.array_equal(source.read_units(start_unit, count), expected[start_unit:start_unit + count]))
                        with self.assertRaises(CarrierAccessError):
                            source.read_units(expected.size - 1, 2)
                        self.assertEqual(
                            streamed_hash(source, AUDIO_MEDIA_CODE, 3, 2100, 500, 2048),
                            expected_hash,
                        )
                    info = read_pcm_wav_info(path)
                    source = WavCarrier(path)
                    self.assertEqual(source.media_context, encode_wav_media_context(info))

    def test_unchanged_chunked_wav_output_is_byte_identical(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            for channels, sample_width in ((1, 1), (2, 2), (2, 3), (1, 4)):
                with self.subTest(channels=channels, sample_width=sample_width):
                    path = directory / "input.wav"
                    write_pcm_wav(path, channels, sample_width, 2500)
                    rewritten = directory / "rewritten.wav"
                    WavCarrier(path, 333).rewrite_to_path(rewritten, lambda start, units: units)
                    self.assertEqual(rewritten.read_bytes(), path.read_bytes())

    def test_wav_formats_round_trip_across_chunk_boundaries(self) -> None:
        formats = ((1, 1), (1, 2), (2, 2), (2, 3), (1, 4))
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            for channels, sample_width in formats:
                path = directory / f"c{channels}-w{sample_width}.wav"
                write_pcm_wav(path, channels, sample_width, 12000 // channels)
                original_info, original_frame_bytes = reference_wav_data(path)
                bytes_per_frame = channels * sample_width
                for lsb_count in (1, 3, 8):
                    for chunk_frames in (500 // channels, 97):
                        with self.subTest(channels=channels, sample_width=sample_width, lsb_count=lsb_count, chunk_frames=chunk_frames):
                            source = WavCarrier(path, chunk_frames * bytes_per_frame)
                            chunk_units = source.frames_per_chunk * channels
                            context = source.media_context
                            payload = f"c={channels};w={sample_width};k={lsb_count};".encode("ascii").ljust(700, b"p")
                            encoding = prepare_carrier_encoding(source, AUDIO_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, self.SPAN + 3, lsb_count, payload, b"chunked")
                            layout = encoding.layout
                            edges = range(chunk_units, source.total_units, chunk_units)
                            self.assertTrue(any(0 < edge < layout.bootstrap_span for edge in edges))
                            self.assertGreaterEqual(sum(layout.start_unit < edge < layout.start_unit + layout.footprint for edge in edges), 1)
                            output = directory / "output.wav"
                            source.rewrite_to_path(output, encoding.embed_chunk, encoding.update_fixed_bytes)
                            encoding.finish()
                            result = decode_carrier_source(WavCarrier(output, chunk_frames * bytes_per_frame), AUDIO_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                            self.assertEqual(result.verdict, "Authentic", result.detail)
                            self.assertEqual(result.payload, encoding.payload)
                            self.assertEqual(verify_wav(output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Authentic")
                            stego_info, stego_frame_bytes = reference_wav_data(output)
                            self.assertEqual(stego_info, original_info)
                            before = np.frombuffer(original_frame_bytes, dtype=np.uint8).reshape(-1, sample_width)
                            after = np.frombuffer(stego_frame_bytes, dtype=np.uint8).reshape(-1, sample_width)
                            self.assertTrue(np.array_equal(before[:, 1:], after[:, 1:]))
                            changed = np.flatnonzero(before[:, 0] != after[:, 0])
                            self.assertTrue(np.all((changed < layout.bootstrap_span) | ((changed >= layout.start_unit) & (changed < layout.start_unit + layout.footprint))))
                            self.assertTrue(np.all((before[:layout.bootstrap_span, 0] ^ after[:layout.bootstrap_span, 0]) <= 1))
                            stego_units = np.frombuffer(stego_frame_bytes, dtype=np.uint8)[::sample_width].copy()
                            self.assertEqual(stego_units.size, layout.total_units)
                            stego_matrix = np.frombuffer(stego_frame_bytes, dtype=np.uint8).reshape((-1, sample_width))
                            fixed_bytes = stego_matrix[:, 1:].tobytes()
                            self.assertEqual(
                                reference_v3_media_hash(
                                    stego_units.tobytes(), fixed_bytes, AUDIO_MEDIA_CODE,
                                    lsb_count, layout.start_unit, layout.footprint,
                                    layout.bootstrap_span,
                                ),
                                encoding.payload.media_hash,
                            )

    def test_truncated_wav_is_cannot_verify_before_protocol_reads(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = directory / "input.wav"
            output = directory / "output.wav"
            write_pcm_wav(path, 2, 2, 4000)
            encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"truncate me", b"")
            truncated = directory / "truncated.wav"
            truncated.write_bytes(output.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "shorter than its declared frame count"):
                read_pcm_wav_info(truncated)
            with patch("stego.core.decode_carrier_source", wraps=decode_carrier_source) as decode:
                result = verify_wav(truncated, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Cannot Verify")
            self.assertIn("shorter than its declared frame count", result.detail)
            decode.assert_not_called()
            with self.assertRaisesRegex(ValueError, "shorter than its declared frame count"):
                encode_wav(truncated, directory / "never.wav", PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"x", b"")
            self.assertFalse((directory / "never.wav").exists())

    def test_mid_stream_read_failures_are_cannot_verify(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = directory / "input.wav"
            output = directory / "output.wav"
            write_pcm_wav(path, 1, 2, 12000)
            encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"mid-stream", b"")
            context = encode_wav_media_context(read_pcm_wav_info(output))

            source = WavCarrier(output, 1024)
            with open(output, "r+b") as handle:
                handle.truncate(os.path.getsize(output) - 64)
            result = decode_carrier_source(source, AUDIO_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Cannot Verify")
            self.assertIn("masked media hash", result.detail)
            self.assertIn("ended before its declared frame count", result.detail)

            encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"mid-stream", b"")
            real_readframes = wave.Wave_read.readframes
            calls = []

            def failing_readframes(wav_file: wave.Wave_read, frame_count: int) -> bytes:
                calls.append(frame_count)
                if len(calls) == 4:
                    raise OSError("simulated device error")
                return real_readframes(wav_file, frame_count)

            source = WavCarrier(output, 1024)
            with patch.object(wave.Wave_read, "readframes", failing_readframes):
                result = decode_carrier_source(source, AUDIO_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Cannot Verify")
            self.assertIn("could not read WAV frame data", result.detail)

            source = WavCarrier(output, 1024)
            write_pcm_wav(output, 2, 2, 6000)
            result = decode_carrier_source(source, AUDIO_MEDIA_CODE, context, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
            self.assertEqual(result.verdict, "Cannot Verify")
            self.assertIn("header changed", result.detail)

    def test_wav_input_change_between_passes_is_detected(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = directory / "input.wav"
            output = directory / "output.wav"
            write_pcm_wav(path, 1, 2, 8000)

            source = WavCarrier(path, 4096)
            context = source.media_context
            encoding = prepare_carrier_encoding(source, AUDIO_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"x", b"")
            flip_carrier_byte_of_last_sample(path, 2)
            source.rewrite_to_path(output, encoding.embed_chunk, encoding.update_fixed_bytes)
            with self.assertRaisesRegex(ValueError, "carrier changed between encoding passes"):
                encoding.finish()

            write_pcm_wav(path, 1, 2, 8000)
            real_prepare = prepare_carrier_encoding

            def prepare_then_change_input(*args: object) -> CarrierEncoding:
                prepared = real_prepare(*args)
                flip_carrier_byte_of_last_sample(path, 2)
                return prepared

            output.unlink()
            with patch("stego.core.prepare_carrier_encoding", prepare_then_change_input):
                with self.assertRaisesRegex(ValueError, "carrier changed between encoding passes"):
                    encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"x", b"")
            self.assertFalse(output.exists())

    def test_streamed_wav_round_trip(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = directory / "input.wav"
            output = directory / "output.wav"
            write_pcm_wav(path, 2, 2, 5000)
            encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"streamed", b"")
            self.assertEqual(verify_wav(output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY).verdict, "Authentic")

    def test_wav_carrier_memory_does_not_grow_with_carrier_size(self) -> None:
        peaks = {}
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            for megabytes in (2, 16):
                path = directory / f"{megabytes}.wav"
                output = directory / f"{megabytes}-out.wav"
                write_large_pcm_wav(path, megabytes * 1024 * 1024)
                tracemalloc.start()
                try:
                    encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"bounded", b"")
                    result = verify_wav(output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                    peaks[megabytes] = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertEqual(result.verdict, "Authentic")
        self.assertLess(peaks[16], 8 * 1024 * 1024)
        self.assertLess(peaks[16], peaks[2] * 2)

    @unittest.skipUnless(os.environ.get("STEGO_LARGE_WAV_TEST") == "1", "set STEGO_LARGE_WAV_TEST=1 to run the >64 MiB WAV test")
    def test_wav_larger_than_legacy_cap_round_trips(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = directory / "large.wav"
            output = directory / "large-out.wav"
            write_large_pcm_wav(path, 72 * 1024 * 1024)
            tracemalloc.start()
            try:
                layout, payload = encode_wav(path, output, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"beyond the cap", b"")
                result = verify_wav(output, PUBLIC_KEY, RECEIVER_PRIVATE_KEY)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertEqual(result.verdict, "Authentic", result.detail)
            self.assertEqual(result.payload, payload)
            self.assertEqual(layout.total_units, 36 * 1024 * 1024)
            self.assertLess(peak, 16 * 1024 * 1024)


def encode_carrier_source_from(source: CarrierSource) -> CarrierEncoding:
    context = struct.pack(">II", source.total_units // 3, 1)
    return prepare_carrier_encoding(source, IMAGE_MEDIA_CODE, context, PRIVATE_KEY, RECEIVER_PUBLIC_KEY, 2048, 3, b"hello", b"{}")


def flip_carrier_byte_of_last_sample(path: Path, sample_width: int) -> None:
    """Flip the top bit of the last sample's least-significant byte, which is a hashed carrier bit."""
    with open(path, "r+b") as handle:
        handle.seek(-sample_width, os.SEEK_END)
        value = handle.read(1)[0]
        handle.seek(-sample_width, os.SEEK_END)
        handle.write(bytes((value ^ 0x80,)))


def write_large_pcm_wav(path: Path, frame_byte_count: int) -> None:
    """Write 16-bit stereo PCM in blocks, without holding the whole file in memory."""
    block = random_units(1024 * 1024).tobytes()
    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(2)
        wav_file.setsampwidth(2)
        wav_file.setframerate(44100)
        wav_file.setnframes(frame_byte_count // 4)
        for _ in range(frame_byte_count // len(block)):
            wav_file.writeframesraw(block)


if __name__ == "__main__":
    unittest.main()
