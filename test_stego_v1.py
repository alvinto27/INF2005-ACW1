import base64
import hashlib
import json
import os
import re
import struct
import unittest
import wave
from dataclasses import FrozenInstanceError
from pathlib import Path
from stat import S_IMODE, S_IRUSR, S_IWUSR
from tempfile import TemporaryDirectory

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import stego_v1
from stego_v1 import *
from stego_v1 import (
    _ENCRYPTED_PRIVATE_KEY_BEGIN,
    _ENCRYPTED_PRIVATE_KEY_END,
    _find_magic_start_mask,
    _validate_lsb_count,
    _validate_uint64,
    _validate_v1_layout,
)

# Shared fixtures formerly created by earlier notebook cells.
_v1_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_v1_public_key = _v1_private_key.public_key()
_v1_der = serialize_rsa_public_key(_v1_public_key)

_signing_private, _signing_public = generate_v1_rsa_keypair()
_unrelated_private, _unrelated_public = generate_v1_rsa_keypair()
_non_rsa_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
_rsa_1024_public_key = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
_rsa_exponent_3_public_key = rsa.generate_private_key(public_exponent=3, key_size=2048).public_key()
_invalid_ec_private = ec.generate_private_key(ec.SECP256R1())
_invalid_ec_public = _invalid_ec_private.public_key()
_invalid_1024_private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
_invalid_1024_public = _invalid_1024_private.public_key()
_invalid_3_private = rsa.generate_private_key(public_exponent=3, key_size=2048)
_invalid_3_public = _invalid_3_private.public_key()

_private_password = b"correct horse battery staple"
_wav_mono_bytes = bytes((0, 1, 127, 128, 254, 255))
_wav_stereo_bytes = bytes(range(16))

_trusted_a = TrustedKeyRecord(_v1_der, "zeta")
_trusted_b = TrustedKeyRecord(serialize_rsa_public_key(_signing_public), "alpha")
_trusted_records = normalize_trusted_key_records((_trusted_a, _trusted_b))


class TestStegoV1(unittest.TestCase):

    def test_focused_checks_for_the_version_1_constants_and_carrier_primitives_only(self):
        # Focused checks for the version-1 constants and carrier primitives only.
        assert PROTOCOL_VERSION == 1
        assert START_MAGIC == bytes.fromhex("d9df721b281169d4335290e30fdb48b1")
        assert SUPPORTED_LSB_COUNTS == tuple(range(1, 9))
        assert HASH_ALGORITHM == "SHA-256"
        assert RSA_ALGORITHM == "RSA-2048"
        assert RSA_SIGNATURE_ALGORITHM == "RSA-PSS"
        assert RSA_MGF_ALGORITHM == "MGF1-SHA-256"
        assert RSA_PSS_SALT_LENGTH == 32
        assert RSA_SIGNATURE_SIZE == 256
        assert PNG_CARRIER_MODE == "RGB"
        assert RGB_CHANNEL_COUNT == 3
        assert PNG_CARRIER_ORDER.startswith("row-major")
        assert SELECTED_LSB_BIT_ORDER.startswith("MSB")

        _sample_rgb = np.arange(18, dtype=np.uint8).reshape(2, 3, RGB_CHANNEL_COUNT)
        _sample_carrier = rgb_array_to_carrier(_sample_rgb)
        assert _sample_carrier.shape == (2 * 3 * RGB_CHANNEL_COUNT,)
        assert _sample_carrier.size == 18
        assert _sample_carrier.dtype == np.uint8
        assert np.array_equal(_sample_carrier, np.arange(18, dtype=np.uint8))
        _sample_carrier[0] = 255
        assert _sample_rgb[0, 0, 0] == 0
        _rebuilt_rgb = carrier_to_rgb_array(_sample_carrier, _sample_rgb.shape)
        assert _rebuilt_rgb.shape == _sample_rgb.shape
        assert _rebuilt_rgb.dtype == np.uint8
        assert np.array_equal(_rebuilt_rgb.reshape(-1), _sample_carrier)


        with TemporaryDirectory() as temporary_directory:
            rgb_path = Path(temporary_directory) / "rgb.png"
            Image.fromarray(_sample_rgb, mode="RGB").save(rgb_path)
            assert np.array_equal(load_png_from_path(rgb_path), _sample_rgb)

            rgba_path = Path(temporary_directory) / "rgba.png"
            Image.fromarray(np.zeros((2, 3, 4), dtype=np.uint8), mode="RGBA").save(rgba_path)
            try:
                load_png_from_path(rgba_path)
            except ValueError:
                pass
            else:
                raise AssertionError("RGBA PNG must be rejected")

    def test_focused_checks_for_standalone_msb_first_byte_and_lsb_carrier_primitives(self):
        # Focused checks for standalone MSB-first byte and LSB carrier primitives.
        assert np.array_equal(
            bytes_to_bit_sequence(b"\xa5"),
            np.array([1, 0, 1, 0, 0, 1, 0, 1], dtype=np.uint8),
        )
        assert bit_sequence_to_bytes(
            np.array([1, 0, 1, 0, 0, 1, 0, 1], dtype=np.uint8)
        ) == b"\xa5"
        assert bytes_to_bit_sequence(b"").size == 0
        assert bit_sequence_to_bytes(np.empty(0, dtype=np.uint8)) == b""

        _carrier_source = np.array([0xA5] * 16, dtype=np.uint8)
        _payload_bits = np.array([1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1], dtype=np.uint8)
        for _k in SUPPORTED_LSB_COUNTS:
            _written = write_lsb_bits(_carrier_source, _payload_bits, _k)
            assert np.array_equal(_carrier_source, np.array([0xA5] * 16, dtype=np.uint8))
            assert np.array_equal(read_lsb_bits(_written, _payload_bits.size, _k), _payload_bits)

        _known_order = write_lsb_bits(np.array([0xE0], dtype=np.uint8), np.array([1, 0, 1], dtype=np.uint8), 3)
        assert _known_order[0] == 0xE5

        _partial_source = np.array([0xA5, 0x5A], dtype=np.uint8)
        _partial_bits = np.array([1, 0, 1, 0, 1, 1], dtype=np.uint8)
        _partial_written = write_lsb_bits(_partial_source, _partial_bits, 4)
        assert np.array_equal(_partial_written, np.array([0xAA, 0x5E], dtype=np.uint8))
        assert _partial_source.tolist() == [0xA5, 0x5A]

        _exact_source = np.array([0x12, 0x34], dtype=np.uint8)
        _exact_bits = np.zeros(8, dtype=np.uint8)
        _exact_written = write_lsb_bits(_exact_source, _exact_bits, 4)
        assert read_lsb_bits(_exact_written, 8, 4).size == 8
        assert np.array_equal(write_lsb_bits(_exact_source, np.empty(0, dtype=np.uint8), 4), _exact_source)

        for _invalid_k in (0, 9, True, False, 1.5, "1"):
            try:
                _validate_lsb_count(_invalid_k)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid lsb_count was accepted")

        for _invalid_bits in (
            np.array([0, 2], dtype=np.uint8),
            np.array([0, 1], dtype=np.int8),
            np.array([[0, 1]], dtype=np.uint8),
        ):
            try:
                bit_sequence_to_bytes(_invalid_bits)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid bit sequence was accepted")

        for _invalid_carrier in (
            [0, 1],
            np.array([0, 1], dtype=np.int16),
            np.array([[0, 1]], dtype=np.uint8),
        ):
            try:
                write_lsb_bits(_invalid_carrier, _payload_bits, 1)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid carrier array was accepted")

        try:
            write_lsb_bits(np.zeros(1, dtype=np.uint8), np.zeros(2, dtype=np.uint8), 1)
        except ValueError:
            pass
        else:
            raise AssertionError("over-capacity write was accepted")
        try:
            read_lsb_bits(np.zeros(1, dtype=np.uint8), 2, 1)
        except ValueError:
            pass
        else:
            raise AssertionError("over-capacity read was accepted")

    def test_focused_checks_for_immutable_v1_region_layout_and_capacity_calculations(self):
        # Focused checks for immutable v1 region layout and capacity calculations.
        _expected_padding = {1: 0, 2: 0, 3: 1, 4: 0, 5: 2, 6: 4, 7: 3, 8: 0}
        for _k in SUPPORTED_LSB_COUNTS:
            assert signature_padding_count(_k) == _expected_padding[_k]
            assert ceil_unit_count(SIGNATURE_BIT_LENGTH, _k) == (2048 + _k - 1) // _k

        assert ceil_unit_count(1, 3) == 1
        assert ceil_unit_count(3, 3) == 1
        assert ceil_unit_count(4, 3) == 2
        assert ceil_unit_count(0, 3) == 0

        _layout_k3 = build_region_layout(1100, 4, 3, 7)
        assert _layout_k3.region2_unit_count == 2
        assert _layout_k3.region2_range == (7, 9)
        assert _layout_k3.region3_range == (9, 692)
        assert _layout_k3.signature_padding_bits == 1
        assert _layout_k3.region3_bit_length == 2049

        _required_units = ceil_unit_count(17, 4) + ceil_unit_count(2048, 4)
        _layout_start_zero = build_region_layout(_required_units, 17, 4, 0)
        _layout_start_middle = build_region_layout(_required_units + 10, 17, 4, 5)
        _layout_start_last = build_region_layout(_required_units + 10, 17, 4, 10)
        for _layout in (_layout_start_zero, _layout_start_middle, _layout_start_last):
            assert _layout.region2_range[1] == _layout.region3_range[0]
            assert _layout.region3_range[1] <= _layout.carrier_unit_count

        _one_unit_over = _required_units - 1
        try:
            build_region_layout(_one_unit_over, 17, 4, 0)
        except ValueError:
            pass
        else:
            raise AssertionError("one-unit-over layout was accepted")
        try:
            build_region_layout(_required_units + 5, 17, 4, 6)
        except ValueError:
            pass
        else:
            raise AssertionError("late start was allowed to wrap or use earlier units")

        _partition_layout = build_region_layout(_required_units + 10, 17, 4, 5)
        _partition_indices = []
        for _range_start, _range_end in _partition_layout.region1_ranges:
            _partition_indices.extend(range(_range_start, _range_end))
        _partition_indices.extend(range(*_partition_layout.region2_range))
        _partition_indices.extend(range(*_partition_layout.region3_range))
        assert len(_partition_indices) == _partition_layout.carrier_unit_count
        assert sorted(_partition_indices) == list(range(_partition_layout.carrier_unit_count))
        assert _partition_layout.region1_ranges == ((0, 5), (_partition_layout.region3_range[1], _partition_layout.carrier_unit_count))

        try:
            _partition_layout.start_unit = 0
        except Exception:
            pass
        else:
            raise AssertionError("frozen layout was mutable")
        try:
            _partition_layout.region1_ranges[0] = (0, 0)
        except TypeError:
            pass
        else:
            raise AssertionError("layout ranges were mutable")

        for _invalid_layout_args in (
            (0, 17, 4, 0),
            (10, 0, 4, 0),
            (10, -1, 4, 0),
            (10, 17, 0, 0),
            (10, 17, 4, -1),
            (10, 17, 4, 11),
            (10, 17, True, 0),
            (10, 17, 4, 0.5),
        ):
            try:
                build_region_layout(*_invalid_layout_args)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid layout input was accepted")

        for _invalid_formula_args in ((-1, 1), (1, True), (1, 1.5)):
            try:
                ceil_unit_count(*_invalid_formula_args)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid ceiling input was accepted")

    def test_focused_checks_for_deterministic_region_1_and_region_3_hash_inputs(self):
        # Focused checks for deterministic Region 1 and Region 3 hash inputs.
        _region1_units = np.array([0x01, 0xA2], dtype=np.uint8)
        _expected_region1_preimage = (
            REGION1_HASH_DOMAIN + (2).to_bytes(8, "big") + b"\x01\xA2"
        )
        assert encode_region1_hash_preimage(_region1_units) == _expected_region1_preimage
        assert encode_region1_hash_preimage(np.empty(0, dtype=np.uint8)) == REGION1_HASH_DOMAIN + (0).to_bytes(8, "big")
        assert len(calculate_region1_hash(_region1_units)) == SHA256_DIGEST_SIZE
        assert calculate_region1_hash(_region1_units) == calculate_region1_hash(_region1_units.copy())
        assert calculate_region1_hash(np.array([0xA2, 0x01], dtype=np.uint8)) != calculate_region1_hash(_region1_units)
        assert encode_region1_hash_preimage(_region1_units) != encode_region3_hash_preimage(_region1_units, 8)

        _region3_units = np.array([0b10110101], dtype=np.uint8)
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 1), np.array([1, 0, 1, 1, 0, 1, 0], dtype=np.uint8))
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 2), np.array([1, 0, 1, 1, 0, 1], dtype=np.uint8))
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 3), np.array([1, 0, 1, 1, 0], dtype=np.uint8))
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 4), np.array([1, 0, 1, 1], dtype=np.uint8))
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 5), np.array([1, 0, 1], dtype=np.uint8))
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 6), np.array([1, 0], dtype=np.uint8))
        assert np.array_equal(collect_region3_upper_bits(_region3_units, 7), np.array([1], dtype=np.uint8))
        assert collect_region3_upper_bits(_region3_units, 8).size == 0
        assert pack_region3_upper_bits(np.array([1, 0, 1, 1, 0], dtype=np.uint8)) == b"\xB0"
        _expected_region3_preimage = (
            REGION3_HASH_DOMAIN + bytes([3]) + (1).to_bytes(8, "big") + (5).to_bytes(8, "big") + b"\xB0"
        )
        assert encode_region3_hash_preimage(_region3_units, 3) == _expected_region3_preimage
        assert len(calculate_region3_hash(_region3_units, 3)) == SHA256_DIGEST_SIZE

        _region3_source_copy = _region3_units.copy()
        _collected_copy = collect_region3_upper_bits(_region3_units, 3)
        _collected_copy[0] = 0
        assert np.array_equal(_region3_units, _region3_source_copy)
        assert encode_region3_hash_preimage(np.array([1, 2], dtype=np.uint8), 8) == (
            REGION3_HASH_DOMAIN + bytes([8]) + (2).to_bytes(8, "big") + (0).to_bytes(8, "big")
        )

        for _invalid_units in (
            [1, 2],
            np.array([1, 2], dtype=np.int16),
            np.array([[1, 2]], dtype=np.uint8),
        ):
            for _hash_function in (encode_region1_hash_preimage, calculate_region1_hash):
                try:
                    _hash_function(_invalid_units)
                except (TypeError, ValueError):
                    pass
                else:
                    raise AssertionError("invalid Region 1 units were accepted")

        for _invalid_k in (0, 9, True, 1.5, "3"):
            try:
                collect_region3_upper_bits(_region3_units, _invalid_k)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid Region 3 k was accepted")

        for _invalid_bits in (
            [0, 1],
            np.array([0, 2], dtype=np.uint8),
            np.array([0, 1], dtype=np.int8),
            np.array([[0, 1]], dtype=np.uint8),
        ):
            try:
                pack_region3_upper_bits(_invalid_bits)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid hash bit sequence was accepted")

        for _invalid_uint64 in (-1, UINT64_MAX + 1, True, 1.5):
            try:
                _validate_uint64(_invalid_uint64, "test value")
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid uint64 value was accepted")

    def test_focused_checks_for_the_fixed_v1_region_2_bootstrap_and_framing(self):
        # Focused checks for the fixed v1 Region 2 bootstrap and framing.
        assert REGION2_HEADER_SIZE == 8
        assert REGION2_PREFIX_SIZE == 24
        assert MAX_PAYLOAD_LENGTH == 16 * 1024 * 1024
        _known_header = serialize_region2_header(3, 5)
        assert _known_header == struct.pack(">BBHI", 1, 3, 8, 5)
        assert _known_header[0] == 1
        assert _known_header[1] == 3
        assert _known_header[2:4] == b"\x00\x08"
        assert _known_header[4:8] == b"\x00\x00\x00\x05"
        _known_stream = build_region2_stream(b"abc", 3)
        assert _known_stream[:16] == START_MAGIC
        assert _known_stream[16:24] == serialize_region2_header(3, 3)
        assert _known_stream[24:] == b"abc"

        for _k in SUPPORTED_LSB_COUNTS:
            _payload = b"opaque\x00payload"
            _stream = build_region2_stream(_payload, _k)
            _header, _parsed_payload = parse_region2_stream(_stream)
            assert _header.lsb_count == _k
            assert _parsed_payload == _payload
            assert calculate_region2_bit_length(len(_payload), _k) == len(_stream) * 8

        assert calculate_region2_bit_length(0, 1) == REGION2_PREFIX_SIZE * 8
        assert calculate_region2_bit_length(MAX_PAYLOAD_LENGTH, 8) == (REGION2_PREFIX_SIZE + MAX_PAYLOAD_LENGTH) * 8
        assert validate_payload_length(MAX_PAYLOAD_LENGTH) == MAX_PAYLOAD_LENGTH
        assert build_region2_stream(START_MAGIC + b"inside-payload", 1)[24 + len(START_MAGIC):].startswith(b"inside-payload")

        _parsed_header, _parsed_payload = parse_region2_stream(_known_stream)
        try:
            _parsed_header.lsb_count = 1
        except Exception:
            pass
        else:
            raise AssertionError("parsed header was mutable")
        assert isinstance(_parsed_payload, bytes)

        _wrong_magic = b"\x00" + _known_stream[1:]
        try:
            parse_region2_stream(_wrong_magic)
        except ValueError:
            pass
        else:
            raise AssertionError("wrong magic was accepted")

        for _bad_header in (
            struct.pack(">BBHI", 2, 3, 8, 3),
            struct.pack(">BBHI", 1, 0, 8, 3),
            struct.pack(">BBHI", 1, 3, 7, 3),
        ):
            try:
                parse_region2_header(_bad_header)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("unsupported header field was accepted")

        _declared_mismatch = START_MAGIC + struct.pack(">BBHI", 1, 3, 8, 4) + b"abc"
        for _bad_stream in (_known_stream[:-1], _known_stream + b"trailing", _declared_mismatch):
            try:
                parse_region2_stream(_bad_stream)
            except ValueError:
                pass
            else:
                raise AssertionError("malformed stream was accepted")

        for _invalid_payload in (bytearray(b"x"), memoryview(b"x"), "x"):
            try:
                validate_payload_bytes(_invalid_payload)
            except TypeError:
                pass
            else:
                raise AssertionError("non-bytes payload was accepted")

        for _invalid_length in (-1, MAX_PAYLOAD_LENGTH + 1, True, 1.5, "1"):
            try:
                validate_payload_length(_invalid_length)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid payload length was accepted")

        for _invalid_stream in (bytearray(_known_stream), memoryview(_known_stream), "stream"):
            try:
                parse_region2_stream(_invalid_stream)
            except TypeError:
                pass
            else:
                raise AssertionError("non-bytes stream was accepted")

    def test_focused_checks_for_vectorized_carrier_unit_aligned_start_magic_discovery(self):
        # Focused checks for vectorized, carrier-unit-aligned start-magic discovery.
        assert MAX_MAGIC_CANDIDATES == 64
        assert len(bytes_to_bit_sequence(START_MAGIC)) == 128

        _magic_bits = bytes_to_bit_sequence(START_MAGIC)
        # Builds a test carrier containing start magic.
        def make_magic_carrier(_background, _start, _k):
            _units = ceil_unit_count(_magic_bits.size, _k)
            _segment = write_lsb_bits(
                np.full(_units, _background, dtype=np.uint8),
                _magic_bits,
                _k,
            )
            _carrier = np.full(150, _background, dtype=np.uint8)
            _carrier[_start:_start + _units] = _segment
            return _carrier

        for _k in SUPPORTED_LSB_COUNTS:
            _units = ceil_unit_count(128, _k)
            for _start in (0, 5, 150 - _units):
                _found = scan_start_magic_for_lsb(make_magic_carrier(0xA5, _start, _k), _k)
                assert _found == (StartMagicCandidate(_start, _k),)

        assert scan_start_magic_for_lsb(np.zeros(150, dtype=np.uint8), 1) == ()
        _corrupt = make_magic_carrier(0xA5, 4, 3)
        _corrupt[4] ^= np.uint8(1 << 2)
        assert scan_start_magic_for_lsb(_corrupt, 3) == ()

        _partial_units = ceil_unit_count(128, 3)
        _partial_carrier = np.full(150, 0xFF, dtype=np.uint8)
        _partial_carrier[9:9 + _partial_units] = write_lsb_bits(
            np.full(_partial_units, 0xFF, dtype=np.uint8), _magic_bits, 3
        )
        _partial_carrier[9 + _partial_units - 1] ^= np.uint8(1)
        assert scan_start_magic_for_lsb(_partial_carrier, 3) == (StartMagicCandidate(9, 3),)

        _upper_ignored = np.full(150, 0xE0, dtype=np.uint8)
        _upper_units = ceil_unit_count(128, 3)
        _upper_ignored[11:11 + _upper_units] = write_lsb_bits(
            np.full(_upper_units, 0xE0, dtype=np.uint8), _magic_bits, 3
        )
        _upper_ignored[11] ^= np.uint8(0x80)
        assert scan_start_magic_for_lsb(_upper_ignored, 3) == (StartMagicCandidate(11, 3),)

        _multiple = np.full(300, 0xFF, dtype=np.uint8)
        for _start, _k in ((140, 3), (2, 1), (200, 8)):
            _units = ceil_unit_count(128, _k)
            _multiple[_start:_start + _units] = write_lsb_bits(
                np.full(_units, 0xFF, dtype=np.uint8), _magic_bits, _k
            )
        _expected_multiple = tuple(sorted((StartMagicCandidate(140, 3), StartMagicCandidate(2, 1), StartMagicCandidate(200, 8)), key=lambda candidate: (candidate.start_unit, candidate.lsb_count)))
        assert scan_start_magic(_multiple) == _expected_multiple
        try:
            scan_start_magic(_multiple, max_candidates=2)
        except ValueError:
            pass
        else:
            raise AssertionError("candidate limit was not enforced")

        _dense_repeated = np.tile(np.frombuffer(START_MAGIC, dtype=np.uint8), 8)
        _dense_mask, _dense_count = _find_magic_start_mask(_dense_repeated, 8)
        assert _dense_count >= 8
        _original_flatnonzero = np.flatnonzero
        # Detects premature candidate materialization in a test.
        def _unexpected_flatnonzero(_matches):
            raise AssertionError("flatnonzero was called before candidate-limit rejection")
        np.flatnonzero = _unexpected_flatnonzero
        try:
            scan_start_magic_for_lsb(_dense_repeated, 8, max_candidates=1)
        except ValueError:
            pass
        else:
            raise AssertionError("dense candidate limit was not enforced")
        finally:
            np.flatnonzero = _original_flatnonzero

        for _small_carrier in (np.empty(0, dtype=np.uint8), np.zeros(127, dtype=np.uint8)):
            assert scan_start_magic(_small_carrier) == ()

        _source_copy = _multiple.copy()
        scan_start_magic(_multiple)
        assert np.array_equal(_multiple, _source_copy)

        for _invalid_carrier in (
            [0, 1],
            np.array([0, 1], dtype=np.int16),
            np.array([[0, 1]], dtype=np.uint8),
        ):
            try:
                scan_start_magic(_invalid_carrier)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid carrier was accepted")

        for _invalid_limit in (0, -1, True, 1.5, "1"):
            try:
                scan_start_magic(np.zeros(150, dtype=np.uint8), _invalid_limit)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid candidate limit was accepted")

    def test_focused_checks_for_canonical_rsa_2048_public_key_encoding_and_fingerprints(self):
        # Focused checks for canonical RSA-2048 public-key encoding and fingerprints.
        assert isinstance(_v1_der, bytes)
        assert len(_v1_der) <= MAX_PUBLIC_KEY_DER_LENGTH
        assert serialize_rsa_public_key(parse_rsa_public_key_der(_v1_der)) == _v1_der
        assert validate_rsa_public_key(_v1_public_key) is _v1_public_key

        _v1_fingerprint = fingerprint_rsa_public_key(_v1_public_key)
        assert len(_v1_fingerprint) == 32
        assert _v1_fingerprint == hashlib.sha256(_v1_der).digest()
        assert _v1_fingerprint == fingerprint_rsa_public_key(parse_rsa_public_key_der(_v1_der))
        _display_fingerprint = display_rsa_public_key_fingerprint(_v1_public_key)
        assert _display_fingerprint.startswith("SHA256:")
        assert _display_fingerprint == "SHA256:" + base64.b64encode(_v1_fingerprint).decode("ascii").rstrip("=")
        assert not _display_fingerprint.endswith("=")

        for _invalid_key in (_non_rsa_public_key, _rsa_1024_public_key, _rsa_exponent_3_public_key):
            try:
                serialize_rsa_public_key(_invalid_key)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("unsupported RSA public key was accepted")

        for _invalid_object in (_v1_private_key, _v1_der, None, 123):
            for _key_function in (validate_rsa_public_key, serialize_rsa_public_key, fingerprint_rsa_public_key, display_rsa_public_key_fingerprint):
                try:
                    _key_function(_invalid_object)
                except (TypeError, ValueError):
                    pass
                else:
                    raise AssertionError("wrong key object type was accepted")

        for _invalid_der in (
            b"",
            b"not-der",
            _v1_der + b"\x00",
            b"\x00" * (MAX_PUBLIC_KEY_DER_LENGTH + 1),
            bytearray(_v1_der),
            memoryview(_v1_der),
        ):
            try:
                parse_rsa_public_key_der(_invalid_der)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("malformed or non-bytes DER was accepted")

    def test_focused_checks_for_v1_rsa_key_generation_rsa_pss_signing_and_verification(self):
        # Focused checks for v1 RSA key generation, RSA-PSS signing, and verification.
        assert validate_rsa_private_key(_signing_private) is _signing_private
        assert validate_rsa_public_key(_signing_public) is _signing_public
        assert rsa_private_key_matches_public_key(_signing_private, _signing_public)

        for _input in (b"", b"exact opaque signing input"):
            _signature_a = sign_v1_bytes(_input, _signing_private)
            _signature_b = sign_v1_bytes(_input, _signing_private)
            assert isinstance(_signature_a, bytes)
            assert len(_signature_a) == RSA_SIGNATURE_SIZE == 256
            assert verify_v1_signature(_input, _signature_a, _signing_public)
            assert verify_v1_signature(_input, _signature_b, _signing_public)

        _altered_input = b"exact opaque signing inpuT"
        _valid_signature = sign_v1_bytes(b"exact opaque signing input", _signing_private)
        _altered_signature = bytearray(_valid_signature)
        _altered_signature[0] ^= 1
        assert not verify_v1_signature(_altered_input, _valid_signature, _signing_public)
        assert not verify_v1_signature(b"exact opaque signing input", bytes(_altered_signature), _signing_public)
        assert not verify_v1_signature(b"exact opaque signing input", _valid_signature, _unrelated_public)
        assert not verify_v1_signature(b"exact opaque signing input", _valid_signature[:-1], _signing_public)
        assert not verify_v1_signature(b"exact opaque signing input", _valid_signature + b"x", _signing_public)

        for _not_bytes in (bytearray(b"x"), memoryview(b"x"), "x"):
            try:
                sign_v1_bytes(_not_bytes, _signing_private)
            except TypeError:
                pass
            else:
                raise AssertionError("non-bytes signing input was accepted")
            try:
                verify_v1_signature(_not_bytes, _valid_signature, _signing_public)
            except TypeError:
                pass
            else:
                raise AssertionError("non-bytes verification input was accepted")
            try:
                verify_v1_signature(b"x", _not_bytes, _signing_public)
            except TypeError:
                pass
            else:
                raise AssertionError("non-bytes signature was accepted")

        for _invalid_private in (_signing_public, _invalid_ec_public, _invalid_1024_private, _invalid_3_private):
            try:
                validate_rsa_private_key(_invalid_private)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid private key was accepted")
        for _invalid_public in (_signing_private, _invalid_ec_public, _invalid_1024_public, _invalid_3_public):
            try:
                validate_rsa_public_key(_invalid_public)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid public key was accepted")
        assert not rsa_private_key_matches_public_key(_signing_private, _unrelated_public)

        _max_length_signature = _signing_private.sign(
            b"fixed pss compatibility",
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        _fixed_signature = sign_v1_bytes(b"fixed pss compatibility", _signing_private)
        assert verify_v1_signature(b"fixed pss compatibility", _fixed_signature, _signing_public)
        assert not verify_v1_signature(b"fixed pss compatibility", _max_length_signature, _signing_public)

    def test_focused_checks_for_media_neutral_region_2_signing_input_serialization(self):
        # Focused checks for media-neutral Region 2 signing-input serialization.
        assert REGION2_SIGNING_CONTEXT_FORMAT == ">BBIBQQQQQQHB"
        assert REGION2_SIGNING_CONTEXT_SIZE == struct.calcsize(REGION2_SIGNING_CONTEXT_FORMAT)
        assert IMAGE_MEDIA_CODE == 1
        assert AUDIO_MEDIA_CODE == 2
        assert SUPPORTED_MEDIA_CODES == (IMAGE_MEDIA_CODE, AUDIO_MEDIA_CODE)
        assert RGB_CHANNEL_COUNT == 3

        _sign_layout = build_region_layout(540, 13, 4, 7)
        _sign_values = np.array([0x10, 0x20, 0x30, 0x40], dtype=np.uint8)
        _png_context = encode_png_media_context((1, 180, RGB_CHANNEL_COUNT), _sign_layout.carrier_unit_count)
        assert _png_context == PNG_RGB8_CONTEXT_DOMAIN + struct.pack(">II", 180, 1)
        assert _png_context == b"PNG-RGB8\x00" + bytes.fromhex("000000b400000001")

        _image_input = encode_region2_signing_input(
            IMAGE_MEDIA_CODE, _png_context, _sign_layout, _sign_values
        )
        _expected_context = struct.pack(
            ">BBIBQQQQQQHB", 1, 1, len(_png_context), 4, 540, 7, 13, 4, 11, 512, 2048, 0
        )
        _expected_image_input = (
            REGION2_SIGNING_DOMAIN
            + _expected_context
            + _png_context
            + b"\x10\x20\x30\x40"
        )
        assert _image_input == _expected_image_input
        assert len(_image_input) == (
            len(REGION2_SIGNING_DOMAIN)
            + REGION2_SIGNING_CONTEXT_SIZE
            + len(_png_context)
            + _sign_values.size
        )
        _decoded_context = struct.unpack(
            REGION2_SIGNING_CONTEXT_FORMAT,
            _image_input[len(REGION2_SIGNING_DOMAIN):
                         len(REGION2_SIGNING_DOMAIN) + REGION2_SIGNING_CONTEXT_SIZE],
        )
        assert _decoded_context[1] == IMAGE_MEDIA_CODE
        assert _decoded_context[2] == len(_png_context)
        assert _decoded_context[4] == 540
        assert _decoded_context[4] == _sign_layout.carrier_unit_count

        _audio_context = b"opaque-audio-context"
        _audio_input = encode_region2_signing_input(
            AUDIO_MEDIA_CODE, _audio_context, _sign_layout, _sign_values
        )
        assert _audio_input.startswith(
            REGION2_SIGNING_DOMAIN
            + struct.pack(">BBIB", PROTOCOL_VERSION, AUDIO_MEDIA_CODE, len(_audio_context), 4)
        )
        assert _audio_input != _image_input
        assert encode_region2_signing_input(
            IMAGE_MEDIA_CODE, b"changed-context", _sign_layout, _sign_values
        ) != _image_input
        assert encode_region2_signing_input(
            AUDIO_MEDIA_CODE, _audio_context, _sign_layout, _sign_values
        ) != _image_input
        _shared_signing_names = encode_region2_signing_input.__code__.co_names
        assert not any(
            name in _shared_signing_names
            for name in (
                "PNG_CARRIER_MODE", "PNG_CARRIER_ORDER", "RGB_CHANNEL_COUNT",
                "PNG_RGB8_CONTEXT_DOMAIN", "width", "height", "image_shape",
            )
        )

        for _bad_media_type in (0, 3, True, 1.5, "1"):
            try:
                encode_region2_signing_input(_bad_media_type, b"context", _sign_layout, _sign_values)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid media type was accepted")

        for _bad_context in (bytearray(b"context"), "context", None, b"x" * (MAX_MEDIA_CONTEXT_LENGTH + 1)):
            try:
                encode_region2_signing_input(IMAGE_MEDIA_CODE, _bad_context, _sign_layout, _sign_values)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid media context was accepted")

        assert encode_png_media_context((1, 180, RGB_CHANNEL_COUNT), 540) == _png_context
        for _bad_shape, _bad_count in (((1, 180, 4), 540), ((1, 180), 540), ((0, 180, 3), 540), ((1, 180, 3), 541)):
            try:
                encode_png_media_context(_bad_shape, _bad_count)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid PNG context input was accepted")

    def test_focused_checks_for_the_minimal_canonical_version_1_payload_record(self):

        # Focused checks for the minimal canonical version-1 payload record.
        assert V1_PAYLOAD_FIELDS == {
            "media_type", "media_context", "public_key_der", "unembedded_carrier_hash",
            "reserved_upper_bits_hash", "media_id", "timestamp", "nonce", "message", "metadata",
        }
        assert MAX_MEDIA_CONTEXT_LENGTH == 4096
        assert V1_NONCE_SIZE == 16
        assert MAX_PUBLIC_KEY_DER_LENGTH == 512
        assert MAX_MESSAGE_LENGTH == 15 * 1024 * 1024

        _payload_context = b"\x00\xff"
        _payload_hash = bytes(range(SHA256_DIGEST_SIZE))
        _reserved_hash = b"\xff" * SHA256_DIGEST_SIZE
        _payload_nonce = bytes(range(V1_NONCE_SIZE))
        _payload_record = V1PayloadRecord(
            media_type=IMAGE_MEDIA_CODE,
            media_context=_payload_context,
            public_key_der=_v1_der,
            unembedded_carrier_hash=_payload_hash,
            reserved_upper_bits_hash=_reserved_hash,
            media_id="é",
            timestamp="2024-02-29T12:34:56Z",
            nonce=_payload_nonce,
            message="Hi 🌍",
            metadata=(("z", "last"), ("a", "first")),
        )
        _payload_bytes = serialize_v1_payload(_payload_record)
        _expected_der_b64 = base64.b64encode(_v1_der).decode("ascii")
        _expected_known_payload = (
            '{"media_context":"AP8=","media_id":"é","media_type":1,'
            '"message":"Hi 🌍","metadata":{"a":"first","z":"last"},'
            '"nonce":"000102030405060708090a0b0c0d0e0f",'
            '"public_key_der":"' + _expected_der_b64 + '",'
            '"reserved_upper_bits_hash":"' + ("ff" * SHA256_DIGEST_SIZE) + '",'
            '"timestamp":"2024-02-29T12:34:56Z",'
            '"unembedded_carrier_hash":"' + bytes(range(SHA256_DIGEST_SIZE)).hex() + '"}'
        ).encode("utf-8")
        assert _payload_bytes == _expected_known_payload
        assert "é".encode("utf-8") in _payload_bytes and b"\\u00e9" not in _payload_bytes
        assert parse_v1_payload(_payload_bytes) == _payload_record
        assert parse_v1_payload(_payload_bytes).metadata == (("a", "first"), ("z", "last"))
        assert isinstance(parse_v1_payload(_payload_bytes).media_context, bytes)
        assert len(parse_v1_payload(_payload_bytes).media_context) == 2
        assert len(parse_v1_payload(_payload_bytes).unembedded_carrier_hash) == SHA256_DIGEST_SIZE
        assert len(parse_v1_payload(_payload_bytes).reserved_upper_bits_hash) == SHA256_DIGEST_SIZE
        assert len(parse_v1_payload(_payload_bytes).nonce) == V1_NONCE_SIZE

        try:
            _payload_record.message = "changed"
        except FrozenInstanceError:
            pass
        else:
            raise AssertionError("payload record was mutable")
        try:
            _payload_record.metadata += (("new", "value"),)
        except FrozenInstanceError:
            pass
        else:
            raise AssertionError("payload metadata field was mutable")

        _audio_record = V1PayloadRecord(
            media_type=AUDIO_MEDIA_CODE,
            media_context=b"future-wav-context",
            public_key_der=_v1_der,
            unembedded_carrier_hash=_payload_hash,
            reserved_upper_bits_hash=_reserved_hash,
            media_id="audio",
            timestamp="2024-01-01T00:00:00Z",
            nonce=_payload_nonce,
            message="message",
            metadata=(),
        )
        assert parse_v1_payload(serialize_v1_payload(_audio_record)).media_type == AUDIO_MEDIA_CODE


        # Builds canonical payload test bytes.
        def _payload_document_bytes(document, sort_keys=True):
            return json.dumps(
                document, sort_keys=sort_keys, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")


        # Builds a payload test document.
        def _payload_document():
            return json.loads(_payload_bytes.decode("utf-8"))


        # Asserts that a payload variant is rejected.
        def _assert_payload_rejected(payload, label):
            try:
                parse_v1_payload(payload)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError(f"{label} was accepted")

        for _duplicate in (
            b'{"media_type":1,"media_type":1}',
            b'{"media_type":1,"media_context":"","public_key_der":"",'
            b'"unembedded_carrier_hash":"0000000000000000000000000000000000000000000000000000000000000000",'
            b'"reserved_upper_bits_hash":"0000000000000000000000000000000000000000000000000000000000000000",'
            b'"media_id":"x","timestamp":"2024-01-01T00:00:00Z","nonce":"00000000000000000000000000000000",'
            b'"message":"","metadata":{},"message":""}',
        ):
            _assert_payload_rejected(_duplicate, "duplicate key")
        _missing = _payload_document(); del _missing["message"]
        _extra = _payload_document(); _extra["extra"] = 1
        _assert_payload_rejected(_payload_document_bytes(_missing), "missing field")
        _assert_payload_rejected(_payload_document_bytes(_extra), "extra field")

        _bool_media = _payload_document(); _bool_media["media_type"] = True
        _assert_payload_rejected(_payload_document_bytes(_bool_media), "bool media type")

        for _field, _value in (
            ("media_context", "AP8"),
            ("media_context", "!!!!"),
            ("public_key_der", "AP8"),
            ("public_key_der", "!!!!"),
        ):
            _bad = _payload_document(); _bad[_field] = _value
            _assert_payload_rejected(_payload_document_bytes(_bad), "malformed or noncanonical Base64")
        for _field, _value in (
            ("unembedded_carrier_hash", _payload_hash.hex().upper()),
            ("unembedded_carrier_hash", "00"),
            ("reserved_upper_bits_hash", "gg" * 32),
            ("nonce", "00" * (V1_NONCE_SIZE - 1)),
        ):
            _bad = _payload_document(); _bad[_field] = _value
            _assert_payload_rejected(_payload_document_bytes(_bad), "malformed or noncanonical hex")

        _noncanonical_order = dict(reversed(list(_payload_document().items())))
        _assert_payload_rejected(_payload_document_bytes(_noncanonical_order, sort_keys=False), "noncanonical key order")
        _assert_payload_rejected(_payload_bytes.replace("é".encode("utf-8"), b"\\u00e9"), "noncanonical JSON escape")
        _assert_payload_rejected(_payload_bytes.replace(b":1,", b": 1,", 1), "noncanonical JSON whitespace")
        _assert_payload_rejected(b"[]", "non-object JSON")
        _assert_payload_rejected(b"{\xff", "malformed UTF-8")

        for _bad_timestamp in ("2023-02-29T12:34:56Z", "2024-01-01T12:34:56+00:00", "2024-1-01T12:34:56Z"):
            _bad = _payload_document(); _bad["timestamp"] = _bad_timestamp
            _assert_payload_rejected(_payload_document_bytes(_bad), "invalid timestamp")
        for _field in ("media_id", "metadata"):
            _bad = _payload_document()
            _bad[_field] = "bad\nvalue" if _field == "media_id" else {"bad\nkey": "value"}
            _assert_payload_rejected(_payload_document_bytes(_bad), "control character")

        for _bad_record in (
            dict(media_type=IMAGE_MEDIA_CODE, media_context=b"", public_key_der=_v1_der, unembedded_carrier_hash=_payload_hash, reserved_upper_bits_hash=_reserved_hash, media_id="", timestamp="2024-01-01T00:00:00Z", nonce=_payload_nonce, message="", metadata=()),
            dict(media_type=IMAGE_MEDIA_CODE, media_context=b"x" * (MAX_MEDIA_CONTEXT_LENGTH + 1), public_key_der=_v1_der, unembedded_carrier_hash=_payload_hash, reserved_upper_bits_hash=_reserved_hash, media_id="x", timestamp="2024-01-01T00:00:00Z", nonce=_payload_nonce, message="", metadata=()),
            dict(media_type=IMAGE_MEDIA_CODE, media_context=b"", public_key_der=_v1_der, unembedded_carrier_hash=_payload_hash, reserved_upper_bits_hash=_reserved_hash, media_id="x", timestamp="2024-01-01T00:00:00Z", nonce=_payload_nonce, message="", metadata=(("", "value"),)),
            dict(media_type=IMAGE_MEDIA_CODE, media_context=b"", public_key_der=_v1_der, unembedded_carrier_hash=_payload_hash, reserved_upper_bits_hash=_reserved_hash, media_id="x", timestamp="2024-01-01T00:00:00Z", nonce=_payload_nonce, message="", metadata=(("key", "bad\tvalue"),)),
        ):
            try:
                V1PayloadRecord(**_bad_record)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid payload record was accepted")

        for _bad_metadata in (
            (("duplicate", "one"), ("duplicate", "two")),
            tuple((f"key{index}", "value") for index in range(33)),
            (("k", 1),),
            ("not-a-pair",),
        ):
            try:
                V1PayloadRecord(IMAGE_MEDIA_CODE, b"", _v1_der, _payload_hash, _reserved_hash, "x", "2024-01-01T00:00:00Z", _payload_nonce, "", _bad_metadata)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid metadata was accepted")

        _bad_der = _payload_document(); _bad_der["public_key_der"] = base64.b64encode(_v1_der + b"\x00").decode("ascii")
        _assert_payload_rejected(_payload_document_bytes(_bad_der), "noncanonical DER")

        _original_payload_limit = MAX_PAYLOAD_LENGTH
        try:
            stego_v1.MAX_PAYLOAD_LENGTH = len(_payload_bytes) - 1
            try:
                serialize_v1_payload(_payload_record)
            except ValueError:
                pass
            else:
                raise AssertionError("serialized payload bound was not enforced")
        finally:
            stego_v1.MAX_PAYLOAD_LENGTH = _original_payload_limit

    def test_focused_checks_for_automatic_v1_payload_record_creation(self):
        # Focused checks for automatic v1 payload-record creation.
        _factory_hash = bytes(range(SHA256_DIGEST_SIZE))
        _factory_reserved = b"\xaa" * SHA256_DIGEST_SIZE
        _factory_context = b"factory context"
        _factory_metadata = (("z", "last"), ("a", "first"))
        for _media_type, _prefix in ((IMAGE_MEDIA_CODE, "IMG"), (AUDIO_MEDIA_CODE, "AUD")):
            _factory_record = create_v1_payload_record(
                _media_type,
                _factory_context,
                _signing_public,
                _factory_hash,
                _factory_reserved,
                "generated 🌍 message",
                _factory_metadata,
            )
            assert _factory_record.media_type == _media_type
            assert _factory_record.media_id.startswith(_prefix + "-")
            assert re.fullmatch(_prefix + r"-[0-9a-f]{32}", _factory_record.media_id)
            assert len(_factory_record.media_id) == len(_prefix) + 1 + V1_MEDIA_ID_RANDOM_SIZE * 2
            assert V1_TIMESTAMP_PATTERN.fullmatch(_factory_record.timestamp)
            assert _factory_record.timestamp.endswith("Z")
            assert len(_factory_record.nonce) == V1_NONCE_SIZE
            assert _factory_record.media_context == _factory_context
            assert _factory_record.public_key_der == serialize_rsa_public_key(_signing_public)
            assert _factory_record.unembedded_carrier_hash == _factory_hash
            assert _factory_record.reserved_upper_bits_hash == _factory_reserved
            assert _factory_record.message == "generated 🌍 message"
            assert _factory_record.metadata == (("a", "first"), ("z", "last"))
            assert parse_v1_payload(serialize_v1_payload(_factory_record)) == _factory_record

        _factory_record_a = create_v1_payload_record(
            IMAGE_MEDIA_CODE, b"ctx", _signing_public, _factory_hash, _factory_reserved, "m", {}
        )
        _factory_record_b = create_v1_payload_record(
            IMAGE_MEDIA_CODE, b"ctx", _signing_public, _factory_hash, _factory_reserved, "m", {}
        )
        for _record in (_factory_record_a, _factory_record_b):
            assert isinstance(_record, V1PayloadRecord)
            assert V1_TIMESTAMP_PATTERN.fullmatch(_record.timestamp)
            assert len(_record.nonce) == V1_NONCE_SIZE

        for _bad_factory_args in (
            (0, b"ctx", _signing_public, _factory_hash, _factory_reserved, "m", {}),
            (IMAGE_MEDIA_CODE, b"x" * (MAX_MEDIA_CONTEXT_LENGTH + 1), _signing_public, _factory_hash, _factory_reserved, "m", {}),
            (IMAGE_MEDIA_CODE, b"ctx", _non_rsa_public_key, _factory_hash, _factory_reserved, "m", {}),
            (IMAGE_MEDIA_CODE, b"ctx", _signing_public, b"short", _factory_reserved, "m", {}),
            (IMAGE_MEDIA_CODE, b"ctx", _signing_public, _factory_hash, _factory_reserved, "m" * (MAX_MESSAGE_LENGTH + 1), {}),
            (IMAGE_MEDIA_CODE, b"ctx", _signing_public, _factory_hash, _factory_reserved, "m", {"bad": 1}),
        ):
            try:
                create_v1_payload_record(*_bad_factory_args)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid factory input was accepted")

    def test_focused_checks_for_shared_region_selection_and_region_hashes(self):
        # Focused checks for shared region selection and region hashes.
        assert callable(_validate_v1_layout)

        _region_carrier = np.arange(300, dtype=np.uint8)
        _two_region_layout = build_region_layout(300, 13, 8, 5)
        _region1 = select_region1_units(_region_carrier, _two_region_layout)
        _region2 = select_region2_units(_region_carrier, _two_region_layout)
        _region3 = select_region3_units(_region_carrier, _two_region_layout)
        assert np.array_equal(_region1, np.concatenate((_region_carrier[0:5], _region_carrier[263:300])))
        assert np.array_equal(_region2, _region_carrier[5:7])
        assert np.array_equal(_region3, _region_carrier[7:263])
        assert _region1.dtype == np.uint8 and _region2.dtype == np.uint8 and _region3.dtype == np.uint8
        for _selected in (_region1, _region2, _region3):
            _selected[:] = 0
        assert np.array_equal(_region_carrier, np.arange(300, dtype=np.uint8))

        _prefix_layout = build_region_layout(263, 13, 8, 5)
        assert np.array_equal(select_region1_units(_region_carrier[:263], _prefix_layout), _region_carrier[:5])
        _suffix_layout = build_region_layout(300, 13, 8, 0)
        assert np.array_equal(select_region1_units(_region_carrier, _suffix_layout), _region_carrier[258:])
        _empty_layout = build_region_layout(258, 13, 8, 0)
        _empty_region = select_region1_units(_region_carrier[:258], _empty_layout)
        assert _empty_region.shape == (0,) and _empty_region.dtype == np.uint8

        for _layout in (_two_region_layout, _prefix_layout, _suffix_layout, _empty_layout):
            _expected_r1 = select_region1_units(_region_carrier[:_layout.carrier_unit_count], _layout)
            _expected_r3 = select_region3_units(_region_carrier[:_layout.carrier_unit_count], _layout)
            assert calculate_layout_hashes(_region_carrier[:_layout.carrier_unit_count], _layout) == (
                calculate_region1_hash(_expected_r1),
                calculate_region3_hash(_expected_r3, _layout.lsb_count),
            )

        _k3_carrier = np.arange(700, dtype=np.uint8)
        _k3_layout = build_region_layout(700, 13, 3, 5)
        _k3_hashes = calculate_layout_hashes(_k3_carrier, _k3_layout)
        _k3_region1_changed = _k3_carrier.copy()
        _k3_region1_changed[0] ^= 0x01
        assert calculate_layout_hashes(_k3_region1_changed, _k3_layout)[0] != _k3_hashes[0]
        assert calculate_layout_hashes(_k3_region1_changed, _k3_layout)[1] == _k3_hashes[1]
        _k3_region3_changed = _k3_carrier.copy()
        _k3_region3_changed[_k3_layout.region3_range[0]] ^= 0x80
        assert calculate_layout_hashes(_k3_region3_changed, _k3_layout)[0] == _k3_hashes[0]
        assert calculate_layout_hashes(_k3_region3_changed, _k3_layout)[1] != _k3_hashes[1]
        _k3_region2_changed = _k3_carrier.copy()
        _k3_region2_changed[_k3_layout.region2_range[0]] ^= 0x01
        assert calculate_layout_hashes(_k3_region2_changed, _k3_layout) == _k3_hashes

        _k8_hashes = calculate_layout_hashes(_region_carrier, _two_region_layout)
        assert _k8_hashes == (
            calculate_region1_hash(select_region1_units(_region_carrier, _two_region_layout)),
            calculate_region3_hash(select_region3_units(_region_carrier, _two_region_layout), 8),
        )

        for _bad_carrier in (
            _region_carrier[:-1],
            _region_carrier.astype(np.uint16),
            _region_carrier.reshape(30, 10),
            list(_region_carrier),
        ):
            try:
                select_region1_units(_bad_carrier, _two_region_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid carrier was accepted")

        _forged_layout = RegionLayout(
            lsb_count=8, start_unit=5, carrier_unit_count=300, region2_bit_length=13,
            signature_bit_length=2048, signature_padding_bits=0, region3_bit_length=2048,
            region2_unit_count=2, region3_unit_count=256, region2_range=(5, 7),
            region3_range=(7, 263), region1_ranges=((0, 5), (264, 300)),
        )
        for _selector in (select_region1_units, select_region2_units, select_region3_units, calculate_layout_hashes):
            try:
                _selector(_region_carrier, _forged_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("forged layout was accepted")

    def test_focused_checks_for_standalone_region_2_stream_embedding_and_extraction(self):
        # Focused checks for standalone Region 2 stream embedding and extraction.
        _region2_payload = b"opaque region2 payload"
        _region2_carrier = np.arange(3000, dtype=np.uint8)

        for _k in SUPPORTED_LSB_COUNTS:
            _stream = START_MAGIC + serialize_region2_header(_k, len(_region2_payload)) + _region2_payload
            _layout = build_region_layout(_region2_carrier.size, len(_stream) * 8, _k, 0)
            _embedded = embed_region2_stream(_region2_carrier, _layout, _stream)
            assert np.array_equal(extract_region2_stream(_embedded, _layout), _stream)
            assert np.array_equal(_region2_carrier, np.arange(3000, dtype=np.uint8))
            assert np.array_equal(_embedded[:_layout.region2_range[0]], _region2_carrier[:_layout.region2_range[0]])
            assert np.array_equal(_embedded[_layout.region3_range[0]:], _region2_carrier[_layout.region3_range[0]:])
            _region2_before = _region2_carrier[_layout.region2_range[0]:_layout.region2_range[1]]
            _region2_after = _embedded[_layout.region2_range[0]:_layout.region2_range[1]]
            _lsb_mask = (1 << _k) - 1
            assert np.array_equal(_region2_after & (0xFF ^ _lsb_mask), _region2_before & (0xFF ^ _lsb_mask))

        for _k in SUPPORTED_LSB_COUNTS:
            _stream = START_MAGIC + serialize_region2_header(_k, len(_region2_payload)) + _region2_payload
            _region2_units = (len(_stream) * 8 + _k - 1) // _k
            _region3_units = (SIGNATURE_BIT_LENGTH + _k - 1) // _k
            _last_start = _region2_carrier.size - _region2_units - _region3_units
            for _start in (0, _last_start // 2, _last_start):
                _layout = build_region_layout(_region2_carrier.size, len(_stream) * 8, _k, _start)
                _embedded = embed_region2_stream(_region2_carrier, _layout, _stream)
                assert extract_region2_stream(_embedded, _layout) == _stream
                assert np.array_equal(_embedded[:_start], _region2_carrier[:_start])
                assert np.array_equal(_embedded[_layout.region3_range[1]:], _region2_carrier[_layout.region3_range[1]:])

        _empty_stream = build_region2_stream(b"", 3)
        _empty_layout = build_region_layout(3000, len(_empty_stream) * 8, 3, 17)
        assert len(_empty_stream) == REGION2_PREFIX_SIZE
        assert extract_region2_stream(embed_region2_stream(_region2_carrier, _empty_layout, _empty_stream), _empty_layout) == _empty_stream

        _partial_stream = START_MAGIC + serialize_region2_header(3, 1) + b"X"
        _partial_layout = build_region_layout(3000, len(_partial_stream) * 8, 3, 11)
        _partial_source = _region2_carrier.copy()
        _partial_result = embed_region2_stream(_partial_source, _partial_layout, _partial_stream)
        assert extract_region2_stream(_partial_result, _partial_layout) == _partial_stream
        _partial_start, _partial_end = _partial_layout.region2_range
        _partial_last_before = int(_partial_source[_partial_end - 1])
        _partial_last_after = int(_partial_result[_partial_end - 1])
        assert (_partial_last_after & 0x01) == (_partial_last_before & 0x01)
        assert (_partial_last_after & 0x06) != (_partial_last_before & 0x06)
        assert (_partial_last_after & 0xF8) == (_partial_last_before & 0xF8)

        for _bad_stream in (_partial_stream[:-1], bytearray(_partial_stream), "not bytes"):
            try:
                embed_region2_stream(_region2_carrier, _partial_layout, _bad_stream)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid or mismatched Region 2 stream was accepted")
        _bad_length_layout = build_region_layout(3000, len(_partial_stream) * 8 + 8, 3, 11)
        try:
            embed_region2_stream(_region2_carrier, _bad_length_layout, _partial_stream)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError("mismatched Region 2 stream and layout were accepted")

        for _bad_carrier in (
            list(_region2_carrier),
            _region2_carrier.astype(np.uint16),
            _region2_carrier.reshape(30, 100),
            _region2_carrier[:-1],
        ):
            try:
                extract_region2_stream(_bad_carrier, _partial_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid carrier was accepted")
        for _bad_layout in (None, _region2_carrier):
            try:
                extract_region2_stream(_region2_carrier, _bad_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid layout was accepted")

        _forged_region2_layout = RegionLayout(
            lsb_count=3, start_unit=11, carrier_unit_count=3000, region2_bit_length=len(_partial_stream) * 8,
            signature_bit_length=2048, signature_padding_bits=1, region3_bit_length=2049,
            region2_unit_count=(len(_partial_stream) * 8 + 2) // 3, region3_unit_count=683,
            region2_range=(10, 10 + ((len(_partial_stream) * 8 + 2) // 3)),
            region3_range=(10 + ((len(_partial_stream) * 8 + 2) // 3), 10 + ((len(_partial_stream) * 8 + 2) // 3) + 683),
            region1_ranges=((0, 10), (10 + ((len(_partial_stream) * 8 + 2) // 3) + 683, 3000)),
        )
        for _operation in (embed_region2_stream, extract_region2_stream):
            try:
                if _operation is embed_region2_stream:
                    _operation(_region2_carrier, _forged_region2_layout, _partial_stream)
                else:
                    _operation(_region2_carrier, _forged_region2_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("forged Region 2 layout was accepted")

    def test_focused_checks_for_standalone_region_3_signature_storage_and_padding(self):
        # Focused checks for standalone Region 3 signature storage and padding.
        _signature = bytes(range(256))
        _signature_changed = bytes((value ^ 0x80) for value in _signature)
        _signature_carrier = np.arange(3000, dtype=np.uint8)

        for _k in SUPPORTED_LSB_COUNTS:
            _padding = signature_padding_count(_k)
            _encoded_bits = encode_region3_signature_bits(_signature, _k)
            assert _encoded_bits.dtype == np.uint8
            assert _encoded_bits.size == SIGNATURE_BIT_LENGTH + _padding
            assert np.array_equal(_encoded_bits[:SIGNATURE_BIT_LENGTH], bytes_to_bit_sequence(_signature))
            assert np.all(_encoded_bits[SIGNATURE_BIT_LENGTH:] == 0)
            assert decode_region3_signature_bits(_encoded_bits, _k) == _signature

        assert {k: signature_padding_count(k) for k in (1, 2, 3, 4, 5, 6, 7, 8)} == {
            1: 0, 2: 0, 3: 1, 4: 0, 5: 2, 6: 4, 7: 3, 8: 0,
        }
        for _k in (3, 5, 6, 7):
            _nonzero_padding = encode_region3_signature_bits(_signature, _k)
            _nonzero_padding[SIGNATURE_BIT_LENGTH] = 1
            try:
                decode_region3_signature_bits(_nonzero_padding, _k)
            except ValueError:
                pass
            else:
                raise AssertionError("nonzero signature padding was accepted")

        for _bad_signature in (_signature[:-1], _signature + b"x", bytearray(_signature), "signature"):
            try:
                encode_region3_signature_bits(_bad_signature, 3)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid signature length/type was accepted")

        for _bad_bits in (
            np.zeros(2049, dtype=np.uint16),
            np.zeros(2048, dtype=np.uint8),
            np.zeros(2050, dtype=np.uint8),
            np.full(2049, 2, dtype=np.uint8),
            [0] * 2049,
        ):
            try:
                decode_region3_signature_bits(_bad_bits, 3)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid Region 3 bit sequence was accepted")

        for _k in SUPPORTED_LSB_COUNTS:
            _region3_units = (SIGNATURE_BIT_LENGTH + _k - 1) // _k
            _region2_units = 1
            _last_start = _signature_carrier.size - _region2_units - _region3_units
            for _start in (0, _last_start // 2, _last_start):
                _layout = build_region_layout(_signature_carrier.size, 1, _k, _start)
                _embedded = embed_region3_signature(_signature_carrier, _layout, _signature)
                assert extract_region3_signature(_embedded, _layout) == _signature
                assert np.array_equal(_signature_carrier, np.arange(3000, dtype=np.uint8))
                assert np.array_equal(_embedded[:_layout.region2_range[1]], _signature_carrier[:_layout.region2_range[1]])
                assert np.array_equal(_embedded[_layout.region3_range[1]:], _signature_carrier[_layout.region3_range[1]:])
                _before = _signature_carrier[_layout.region3_range[0]:_layout.region3_range[1]]
                _after = _embedded[_layout.region3_range[0]:_layout.region3_range[1]]
                _mask = 0xFF ^ ((1 << _k) - 1)
                assert np.array_equal(_after & _mask, _before & _mask)

        _k3_layout = build_region_layout(_signature_carrier.size, 1, 3, 17)
        _first_result = embed_region3_signature(_signature_carrier, _k3_layout, _signature)
        _second_result = embed_region3_signature(_signature_carrier, _k3_layout, _signature_changed)
        assert extract_region3_signature(_first_result, _k3_layout) == _signature
        assert extract_region3_signature(_second_result, _k3_layout) == _signature_changed
        assert _first_result.tobytes() != _second_result.tobytes()

        for _bad_carrier in (
            list(_signature_carrier),
            _signature_carrier.astype(np.uint16),
            _signature_carrier.reshape(30, 100),
            _signature_carrier[:-1],
        ):
            try:
                extract_region3_signature(_bad_carrier, _k3_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid carrier was accepted")
        for _bad_layout in (None, _signature_carrier):
            try:
                extract_region3_signature(_signature_carrier, _bad_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid layout was accepted")

        _forged_region3_layout = RegionLayout(
            lsb_count=3, start_unit=17, carrier_unit_count=3000, region2_bit_length=1,
            signature_bit_length=2048, signature_padding_bits=1, region3_bit_length=2049,
            region2_unit_count=1, region3_unit_count=683,
            region2_range=(17, 18), region3_range=(16, 699),
            region1_ranges=((0, 16), (699, 3000)),
        )
        for _operation in (embed_region3_signature, extract_region3_signature):
            try:
                if _operation is embed_region3_signature:
                    _operation(_signature_carrier, _forged_region3_layout, _signature)
                else:
                    _operation(_signature_carrier, _forged_region3_layout)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("forged Region 3 layout was accepted")

    def test_focused_checks_for_bounded_region_2_candidate_resolution(self):
        # Focused checks for bounded Region 2 candidate resolution.
        # Builds a test carrier with a Region 2 prefix.
        def _carrier_with_region2_prefix(carrier_size, start_unit, lsb_count, payload_length, background=0xA5):
            prefix = START_MAGIC + serialize_region2_header(lsb_count, payload_length)
            prefix_units = ceil_unit_count(len(prefix) * 8, lsb_count)
            carrier = np.full(carrier_size, background, dtype=np.uint8)
            carrier[start_unit:start_unit + prefix_units] = write_lsb_bits(
                carrier[start_unit:start_unit + prefix_units],
                bytes_to_bit_sequence(prefix),
                lsb_count,
            )
            return carrier

        for _k in SUPPORTED_LSB_COUNTS:
            for _payload_length in (0, 13):
                _carrier_size = 3000
                _region2_units = ceil_unit_count(
                    calculate_region2_bit_length(_payload_length, _k), _k
                )
                _region3_units = ceil_unit_count(SIGNATURE_BIT_LENGTH, _k)
                _last_start = _carrier_size - _region2_units - _region3_units
                for _start in (0, _last_start // 2, _last_start):
                    _carrier = _carrier_with_region2_prefix(_carrier_size, _start, _k, _payload_length)
                    _source_copy = _carrier.copy()
                    _region2_bits = calculate_region2_bit_length(_payload_length, _k)
                    _layout = build_region_layout(_carrier_size, _region2_bits, _k, _start)
                    _resolved = resolve_region2_candidate(_carrier, StartMagicCandidate(_start, _k))
                    assert _resolved.candidate == StartMagicCandidate(_start, _k)
                    assert _resolved.header == Region2Header(1, _k, REGION2_HEADER_SIZE, _payload_length)
                    assert _resolved.layout == _layout
                    assert np.array_equal(_carrier, _source_copy)

        _k3 = 3
        _k3_payload_length = 13
        _k3_carrier = _carrier_with_region2_prefix(3000, 29, _k3, _k3_payload_length)
        _k3_resolved = resolve_region2_candidate(_k3_carrier, StartMagicCandidate(29, _k3))
        assert _k3_resolved.header.payload_length == _k3_payload_length
        assert _k3_resolved.layout.region2_bit_length == (REGION2_PREFIX_SIZE + _k3_payload_length) * 8
        assert ceil_unit_count(128, _k3) == 43
        assert ceil_unit_count(REGION2_PREFIX_SIZE * 8, _k3) == 64

        _truncated = _carrier_with_region2_prefix(3000, 0, 3, 0)[:63]
        try:
            resolve_region2_candidate(_truncated, StartMagicCandidate(0, 3))
        except ValueError:
            pass
        else:
            raise AssertionError("truncated Region 2 prefix was accepted")

        _bad_magic = _carrier_with_region2_prefix(3000, 0, 3, 0)
        _bad_magic[0] ^= np.uint8(1 << 2)
        try:
            resolve_region2_candidate(_bad_magic, StartMagicCandidate(0, 3))
        except ValueError:
            pass
        else:
            raise AssertionError("wrong start magic was accepted")

        for _bad_header in (
            struct.pack(REGION2_HEADER_FORMAT, 2, 3, REGION2_HEADER_SIZE, 0),
            serialize_region2_header(4, 0),
            struct.pack(REGION2_HEADER_FORMAT, 3, 3, REGION2_HEADER_SIZE - 1, 0),
        ):
            _bad_prefix_carrier = np.full(3000, 0xA5, dtype=np.uint8)
            _bad_prefix_carrier[:64] = write_lsb_bits(
                _bad_prefix_carrier[:64], bytes_to_bit_sequence(START_MAGIC + _bad_header), 3
            )
            try:
                resolve_region2_candidate(_bad_prefix_carrier, StartMagicCandidate(0, 3))
            except ValueError:
                pass
            else:
                raise AssertionError("malformed or mismatched header was accepted")

        _overflow_header = START_MAGIC + serialize_region2_header(3, MAX_PAYLOAD_LENGTH)
        _overflow_carrier = np.full(3000, 0xA5, dtype=np.uint8)
        _overflow_carrier[:64] = write_lsb_bits(
            _overflow_carrier[:64], bytes_to_bit_sequence(_overflow_header), 3
        )
        try:
            resolve_region2_candidate(_overflow_carrier, StartMagicCandidate(0, 3))
        except ValueError:
            pass
        else:
            raise AssertionError("Region 2/3 overflow was accepted")

        for _bad_candidate in (
            None,
            (0, 3),
            StartMagicCandidate(-1, 3),
            StartMagicCandidate(3000, 3),
            StartMagicCandidate(0, 0),
            StartMagicCandidate(0, 9),
            StartMagicCandidate(True, 3),
        ):
            try:
                resolve_region2_candidate(_carrier, _bad_candidate)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid candidate was accepted")

    def test_focused_checks_for_the_required_rgb_png_adapter_primitives(self):
        # Focused checks for the required RGB PNG adapter primitives.
        _png_adapter_shape = (2, 5, RGB_CHANNEL_COUNT)
        _png_adapter_array = np.arange(30, dtype=np.uint8).reshape(_png_adapter_shape)
        _png_adapter_count = _png_adapter_array.size
        _png_adapter_context = encode_png_media_context(_png_adapter_shape, _png_adapter_count)
        assert validate_png_media_context(
            _png_adapter_context, _png_adapter_shape, _png_adapter_count
        ) == _png_adapter_context
        assert validate_png_media_context(
            bytes(bytearray(_png_adapter_context)), _png_adapter_shape, _png_adapter_count
        ) == _png_adapter_context

        for _bad_context, _bad_shape, _bad_count in (
            (_png_adapter_context[:-1], _png_adapter_shape, _png_adapter_count),
            (_png_adapter_context + b"x", _png_adapter_shape, _png_adapter_count),
            (b"PNG-RGB7\x00" + _png_adapter_context[len(PNG_RGB8_CONTEXT_DOMAIN):], _png_adapter_shape, _png_adapter_count),
            (_png_adapter_context, (2, 6, RGB_CHANNEL_COUNT), _png_adapter_count),
            (_png_adapter_context, _png_adapter_shape, _png_adapter_count + 1),
            (bytearray(_png_adapter_context), _png_adapter_shape, _png_adapter_count),
            (_png_adapter_context, (2, 5), _png_adapter_count),
        ):
            try:
                validate_png_media_context(_bad_context, _bad_shape, _bad_count)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid PNG media context was accepted")

        _png_source_copy = _png_adapter_array.copy()
        with TemporaryDirectory() as _png_directory:
            _nested_directory = Path(_png_directory) / "nested"
            _nested_directory.mkdir()
            _nested_path = _nested_directory / "saved.png"
            save_rgb_png_to_path(_png_adapter_array, _nested_path)
            _reloaded_png = load_png_from_path(_nested_path)
            assert np.array_equal(_reloaded_png, _png_adapter_array)
            assert np.array_equal(rgb_array_to_carrier(_reloaded_png), rgb_array_to_carrier(_png_adapter_array))
            assert np.array_equal(_png_adapter_array, _png_source_copy)

            _missing_parent_path = Path(_png_directory) / "missing" / "saved.png"
            try:
                save_rgb_png_to_path(_png_adapter_array, _missing_parent_path)
            except ValueError:
                pass
            else:
                raise AssertionError("missing output parent was accepted")

            _directory_output_path = Path(_png_directory) / "existing-directory"
            _directory_output_path.mkdir()
            try:
                save_rgb_png_to_path(_png_adapter_array, _directory_output_path)
            except ValueError:
                pass
            else:
                raise AssertionError("unwritable directory output was accepted")

        for _bad_array in (
            list(_png_adapter_array),
            _png_adapter_array.astype(np.uint16),
            _png_adapter_array.reshape(5, 6),
            np.zeros((2, 5, 4), dtype=np.uint8),
        ):
            try:
                save_rgb_png_to_path(_bad_array, "unused.png")
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid RGB array was accepted")
        for _bad_path in (None, 123, ["output.png"]):
            try:
                save_rgb_png_to_path(_png_adapter_array, _bad_path)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid output path was accepted")

    def test_focused_checks_for_standalone_uncompressed_pcm_wav_loading_and_carrier_conversion(self):
        # Focused checks for standalone uncompressed PCM WAV loading and carrier conversion.

        with TemporaryDirectory() as _wav_directory:
            _wav_mono_path = Path(_wav_directory) / "mono.wav"
            with wave.open(str(_wav_mono_path), "wb") as _wav_file:
                _wav_file.setnchannels(1)
                _wav_file.setsampwidth(1)
                _wav_file.setframerate(8000)
                _wav_file.writeframes(_wav_mono_bytes)
            _mono = load_pcm_wav_from_path(_wav_mono_path)
            assert _mono == WavPcmData(1, 1, 8000, 6, _wav_mono_bytes)

            _wav_stereo_path = Path(_wav_directory) / "stereo.wav"
            with wave.open(str(_wav_stereo_path), "wb") as _wav_file:
                _wav_file.setnchannels(2)
                _wav_file.setsampwidth(2)
                _wav_file.setframerate(44100)
                _wav_file.writeframes(_wav_stereo_bytes)
            _stereo = load_pcm_wav_from_path(_wav_stereo_path)
            assert _stereo.channels == 2
            assert _stereo.sample_width == 2
            assert _stereo.frame_rate == 44100
            assert _stereo.frame_count == 4
            assert _stereo.frame_bytes == _wav_stereo_bytes

            _carrier = wav_frame_bytes_to_carrier(_wav_stereo_bytes)
            assert _carrier.dtype == np.uint8 and _carrier.ndim == 1
            assert np.array_equal(_carrier, np.arange(16, dtype=np.uint8))
            _carrier[0] = 255
            assert _wav_stereo_bytes[0] == 0
            _carrier_copy = wav_frame_bytes_to_carrier(_wav_stereo_bytes)
            assert carrier_to_wav_frame_bytes(_carrier_copy) == _wav_stereo_bytes
            _carrier_copy[0] = 42
            assert carrier_to_wav_frame_bytes(_carrier_copy) != _wav_stereo_bytes

            _zero_path = Path(_wav_directory) / "zero.wav"
            with wave.open(str(_zero_path), "wb") as _wav_file:
                _wav_file.setnchannels(1)
                _wav_file.setsampwidth(4)
                _wav_file.setframerate(22050)
                _wav_file.writeframes(b"")
            _zero = load_pcm_wav_from_path(_zero_path)
            assert _zero.frame_count == 0 and _zero.frame_bytes == b""
            assert wav_frame_bytes_to_carrier(b"").shape == (0,)
            assert carrier_to_wav_frame_bytes(np.empty(0, dtype=np.uint8)) == b""

            _bad_non_wav = Path(_wav_directory) / "not-wav.bin"
            _bad_non_wav.write_bytes(b"not a wav")
            _truncated = Path(_wav_directory) / "truncated.wav"
            _truncated.write_bytes(_wav_mono_path.read_bytes()[:-2])
            for _bad_file in (_bad_non_wav, _truncated):
                try:
                    load_pcm_wav_from_path(_bad_file)
                except ValueError:
                    pass
                else:
                    raise AssertionError("malformed WAV was accepted")

            _missing_parent = Path(_wav_directory) / "missing" / "file.wav"
            try:
                load_pcm_wav_from_path(_missing_parent)
            except ValueError:
                pass
            else:
                raise AssertionError("missing WAV path was accepted")

        for _bad_path in (None, 123, ["file.wav"]):
            try:
                load_pcm_wav_from_path(_bad_path)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid WAV path was accepted")

        for _bad_record in (
            (0, 1, 8000, 0, b""),
            (1, 0, 8000, 0, b""),
            (1, 5, 8000, 0, b""),
            (1, 1, 0, 0, b""),
            (1, 1, 8000, -1, b""),
            (1, 1, 8000, 1, b""),
            (1, 1, 8000, 1, bytearray(b"\x00")),
        ):
            try:
                WavPcmData(*_bad_record)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid WAV record was accepted")

        for _bad_frame_bytes in (bytearray(b"x"), "x", None):
            try:
                wav_frame_bytes_to_carrier(_bad_frame_bytes)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid WAV frame bytes were accepted")
        for _bad_carrier in (list(range(2)), np.array([1, 2], dtype=np.uint16), np.array([[1, 2]], dtype=np.uint8)):
            try:
                carrier_to_wav_frame_bytes(_bad_carrier)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid WAV carrier was accepted")

        _wav_overbound_frames = MAX_WAV_FRAME_BYTES // 4 + 1
        _wav_overbound_data_size = _wav_overbound_frames * 4
        _wav_overbound_header = (
            b"RIFF" + struct.pack("<I", 36 + _wav_overbound_data_size) + b"WAVE"
            + b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 32000, 4, 32)
            + b"data" + struct.pack("<I", _wav_overbound_data_size)
        )
        with TemporaryDirectory() as _overbound_directory:
            _overbound_path = Path(_overbound_directory) / "overbound.wav"
            _overbound_path.write_bytes(_wav_overbound_header)
            _original_readframes = wave.Wave_read.readframes
            # Detects over-bound WAV frame reads in a test.
            def _unexpected_readframes(_self, _nframes):
                raise AssertionError("over-bound WAV called readframes")
            wave.Wave_read.readframes = _unexpected_readframes
            try:
                load_pcm_wav_from_path(_overbound_path)
            except ValueError:
                pass
            finally:
                wave.Wave_read.readframes = _original_readframes

    def test_focused_checks_for_canonical_wav_context_reconstruction_and_saving(self):
        # Focused checks for canonical WAV context, reconstruction, and saving.
        _mono_data = WavPcmData(1, 1, 8000, 6, _wav_mono_bytes)
        _stereo_data = WavPcmData(2, 2, 44100, 4, _wav_stereo_bytes)
        _mono_context = encode_wav_media_context(_mono_data, len(_wav_mono_bytes))
        _stereo_context = encode_wav_media_context(_stereo_data, len(_wav_stereo_bytes))
        assert _mono_context == WAV_PCM_CONTEXT_DOMAIN + struct.pack(">HBIQ", 1, 1, 8000, 6)
        assert _stereo_context == WAV_PCM_CONTEXT_DOMAIN + struct.pack(">HBIQ", 2, 2, 44100, 4)
        assert len(_mono_context) == len(_stereo_context) == len(WAV_PCM_CONTEXT_DOMAIN) + WAV_PCM_CONTEXT_SIZE
        assert validate_wav_media_context(_mono_context, _mono_data, 6) == _mono_context
        assert validate_wav_media_context(_stereo_context, _stereo_data, 16) == _stereo_context

        for _bad_context, _bad_data, _bad_count in (
            (_mono_context[:-1], _mono_data, 6),
            (_mono_context + b"x", _mono_data, 6),
            (b"WAV-PCM7\x00" + _mono_context[len(WAV_PCM_CONTEXT_DOMAIN):], _mono_data, 6),
            (WAV_PCM_CONTEXT_DOMAIN + struct.pack(">HBIQ", 2, 1, 8000, 6), _mono_data, 6),
            (bytearray(_mono_context), _mono_data, 6),
            (_mono_context, _mono_data, 5),
            (_mono_context, _stereo_data, 6),
        ):
            try:
                validate_wav_media_context(_bad_context, _bad_data, _bad_count)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid WAV media context was accepted")

        _mono_carrier = wav_frame_bytes_to_carrier(_wav_mono_bytes)
        _mono_replaced_carrier = _mono_carrier.copy()
        _mono_replaced_carrier[0] ^= np.uint8(0xFF)
        _replaced_mono = wav_data_with_carrier(_mono_data, _mono_replaced_carrier)
        assert _replaced_mono.channels == _mono_data.channels
        assert _replaced_mono.sample_width == _mono_data.sample_width
        assert _replaced_mono.frame_rate == _mono_data.frame_rate
        assert _replaced_mono.frame_count == _mono_data.frame_count
        assert _replaced_mono.frame_bytes == carrier_to_wav_frame_bytes(_mono_replaced_carrier)
        assert _mono_data.frame_bytes == _wav_mono_bytes
        _mono_replaced_carrier[0] ^= np.uint8(0xFF)
        assert _replaced_mono.frame_bytes != _mono_replaced_carrier.tobytes()

        for _bad_wav_data, _bad_carrier in (
            (None, _mono_carrier),
            (_mono_data, _mono_carrier[:-1]),
            (_mono_data, list(_mono_carrier)),
            (_mono_data, _mono_carrier.astype(np.uint16)),
        ):
            try:
                wav_data_with_carrier(_bad_wav_data, _bad_carrier)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid WAV carrier replacement was accepted")

        for _bad_wav_data, _count in (
            (None, 0),
            (WavPcmData(65536, 1, 8000, 0, b""), 0),
            (WavPcmData(1, 1, 1 << 32, 0, b""), 0),
        ):
            try:
                encode_wav_media_context(_bad_wav_data, _count)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid WAV context parameters were accepted")

        with TemporaryDirectory() as _context_directory:
            for _wav_data, _name in ((_mono_data, "saved-mono.wav"), (_stereo_data, "saved-stereo.wav")):
                _output = Path(_context_directory) / _name
                save_pcm_wav_to_path(_wav_data, _output)
                _reloaded = load_pcm_wav_from_path(_output)
                assert _reloaded == _wav_data
                assert np.array_equal(
                    wav_frame_bytes_to_carrier(_reloaded.frame_bytes),
                    wav_frame_bytes_to_carrier(_wav_data.frame_bytes),
                )
            _missing_parent = Path(_context_directory) / "missing" / "saved.wav"
            try:
                save_pcm_wav_to_path(_mono_data, _missing_parent)
            except ValueError:
                pass
            else:
                raise AssertionError("missing WAV output parent was accepted")
            _directory_output = Path(_context_directory) / "directory"
            _directory_output.mkdir()
            try:
                save_pcm_wav_to_path(_mono_data, _directory_output)
            except ValueError:
                pass
            else:
                raise AssertionError("directory WAV output was accepted")

        for _bad_output in (None, 123, ["output.wav"]):
            try:
                save_pcm_wav_to_path(_mono_data, _bad_output)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid WAV output path was accepted")

    def test_focused_checks_for_encrypted_v1_rsa_private_key_serialization_and_parsing(self):
        # Focused checks for encrypted v1 RSA private-key serialization and parsing.
        _encrypted_private_pem = serialize_encrypted_rsa_private_key(_signing_private, _private_password)
        assert _encrypted_private_pem.startswith(_ENCRYPTED_PRIVATE_KEY_BEGIN)
        assert _encrypted_private_pem.endswith(b"-----END ENCRYPTED PRIVATE KEY-----\n")
        assert b"BEGIN PRIVATE KEY" not in _encrypted_private_pem
        assert len(_encrypted_private_pem) <= MAX_ENCRYPTED_PRIVATE_KEY_PEM_LENGTH
        _parsed_private = parse_encrypted_rsa_private_key(_encrypted_private_pem, _private_password)
        assert isinstance(_parsed_private, rsa.RSAPrivateKey)
        assert _parsed_private.public_key().public_numbers() == _signing_private.public_key().public_numbers()
        _private_numbers_before = _signing_private.private_numbers()
        assert parse_encrypted_rsa_private_key(_encrypted_private_pem, bytes(_private_password)).private_numbers() == _private_numbers_before

        for _bad_password in (b"", bytearray(b"password"), memoryview(b"password"), "password", b"x" * (MAX_PRIVATE_KEY_PASSWORD_LENGTH + 1)):
            for _key_operation in (serialize_encrypted_rsa_private_key, parse_encrypted_rsa_private_key):
                try:
                    if _key_operation is serialize_encrypted_rsa_private_key:
                        _key_operation(_signing_private, _bad_password)
                    else:
                        _key_operation(_encrypted_private_pem, _bad_password)
                except (TypeError, ValueError):
                    pass
                else:
                    raise AssertionError("invalid private-key password was accepted")

        for _bad_pem in (
            b"",
            b"not pem",
            _encrypted_private_pem + b"trailing",
            _encrypted_private_pem + b"\n",
            bytearray(_encrypted_private_pem),
            memoryview(_encrypted_private_pem),
            b"x" * (MAX_ENCRYPTED_PRIVATE_KEY_PEM_LENGTH + 1),
        ):
            try:
                parse_encrypted_rsa_private_key(_bad_pem, _private_password)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("malformed or non-bytes PEM was accepted")
        try:
            parse_encrypted_rsa_private_key(_encrypted_private_pem, b"wrong password")
        except ValueError:
            pass
        else:
            raise AssertionError("wrong private-key password was accepted")

        _unencrypted_pem = _signing_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            parse_encrypted_rsa_private_key(_unencrypted_pem, _private_password)
        except ValueError:
            pass
        else:
            raise AssertionError("unencrypted private key was accepted")

        for _invalid_key in (_invalid_ec_private, _invalid_1024_private, _invalid_3_private):
            _invalid_pem = _invalid_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(_private_password),
            )
            try:
                parse_encrypted_rsa_private_key(_invalid_pem, _private_password)
            except ValueError:
                pass
            else:
                raise AssertionError("unsupported encrypted private key was accepted")
        for _invalid_key in (_signing_public, _invalid_ec_public, _invalid_1024_public, _invalid_3_private.public_key()):
            try:
                serialize_encrypted_rsa_private_key(_invalid_key, _private_password)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("unsupported private-key object was accepted")
        for _bad_pem_type in (None, 123):
            try:
                parse_encrypted_rsa_private_key(_bad_pem_type, _private_password)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid PEM type was accepted")
        assert _signing_private.private_numbers() == _private_numbers_before

    def test_focused_checks_for_immutable_trusted_key_records_and_canonical_trust_store_bytes(self):
        # Focused checks for immutable trusted-key records and canonical trust-store bytes.
        assert serialize_trust_store(()) == b"{\"keys\":[],\"version\":1}"
        assert parse_trust_store(serialize_trust_store(())) == ()
        assert MAX_TRUSTED_KEY_RECORDS == 64
        assert MAX_TRUST_STORE_LENGTH == 128 * 1024
        assert TRUST_STORE_VERSION == 1

        assert _trusted_records == tuple(sorted((_trusted_a, _trusted_b), key=lambda record: record.public_key_der))
        _store_bytes = serialize_trust_store((_trusted_a, _trusted_b))
        _expected_store = json.dumps(
            {
                "keys": [
                    {
                        "label": record.label,
                        "public_key_der": base64.b64encode(record.public_key_der).decode("ascii"),
                    }
                    for record in _trusted_records
                ],
                "version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        assert _store_bytes == _expected_store
        assert parse_trust_store(_store_bytes) == _trusted_records
        assert serialize_trust_store(tuple(reversed(_trusted_records))) == _store_bytes

        assert lookup_trusted_key(_signing_public, _trusted_records) == _trusted_b
        assert lookup_trusted_key(_unrelated_public, _trusted_records) is None
        assert fingerprint_rsa_public_key(parse_rsa_public_key_der(_trusted_b.public_key_der)) == hashlib.sha256(_trusted_b.public_key_der).digest()

        _added = add_trusted_key((), _signing_public, "signer")
        assert _added == (TrustedKeyRecord(_trusted_b.public_key_der, "signer"),)
        try:
            add_trusted_key(_added, _signing_public, "replacement")
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate trusted key was replaced")
        _added_source = _added
        _added_result = add_trusted_key(_added_source, _unrelated_public, "other")
        assert _added_source == _added
        assert remove_trusted_key(_added_result, _unrelated_public) == _added
        try:
            remove_trusted_key(_added, _unrelated_public)
        except ValueError:
            pass
        else:
            raise AssertionError("missing trusted key was not reported")

        assert normalize_trusted_key_records((TrustedKeyRecord(_v1_der, ""), TrustedKeyRecord(_trusted_b.public_key_der, "")))
        for _bad_records in (None, "records", [None], ["record"], 123):
            try:
                normalize_trusted_key_records(_bad_records)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid trust record iterable was accepted")

        try:
            normalize_trusted_key_records((_trusted_a, TrustedKeyRecord(_v1_der, "other")))
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate trusted key was accepted")
        try:
            normalize_trusted_key_records((_trusted_a, TrustedKeyRecord(_trusted_b.public_key_der, "zeta")))
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate nonempty label was accepted")

        for _bad_label in (123, bytearray(b"label"), "bad\nlabel", "x" * 129):
            try:
                TrustedKeyRecord(_v1_der, _bad_label)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid trusted-key label was accepted")
        try:
            TrustedKeyRecord(_v1_der + b"x", "label")
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError("noncanonical trusted-key DER was accepted")

        for _invalid_key in (_signing_private, _invalid_ec_public, _rsa_1024_public_key, _rsa_exponent_3_public_key):
            try:
                lookup_trusted_key(_invalid_key, ())
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("unsupported lookup key was accepted")

        try:
            normalize_trusted_key_records(tuple(TrustedKeyRecord(_v1_der, "") for _ in range(MAX_TRUSTED_KEY_RECORDS + 1)))
        except ValueError:
            pass
        else:
            raise AssertionError("trust record limit was not enforced")

        _store_document = json.loads(_store_bytes.decode("utf-8"))
        # Builds canonical trust-store test bytes.
        def _store_document_bytes(document, sort_keys=True, separators=(",", ":")):
            return json.dumps(document, sort_keys=sort_keys, separators=separators, ensure_ascii=False, allow_nan=False).encode("utf-8")

        _duplicate_store = b'{"keys":[],"keys":[],"version":1}'
        for _bad_store in (
            b"",
            b"[]",
            b"{\xff",
            b'{"keys":[],"version":1,"extra":0}',
            b'{"keys":[]}',
            b'{"keys":[],"version":true}',
            _duplicate_store,
            _store_bytes.replace(b'"version":1', b'"version": 1', 1),
        ):
            try:
                parse_trust_store(_bad_store)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("malformed or noncanonical trust store was accepted")

        _noncanonical_order = dict(reversed(list(_store_document.items())))
        try:
            parse_trust_store(_store_document_bytes(_noncanonical_order, sort_keys=False))
        except ValueError:
            pass
        else:
            raise AssertionError("noncanonical trust-store key order was accepted")

        for _field, _value in (("public_key_der", "AP8"), ("public_key_der", "!!!!")):
            _bad = dict(_store_document)
            _bad["keys"] = [dict(_store_document["keys"][0], **{_field: _value})]
            try:
                parse_trust_store(_store_document_bytes(_bad))
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("malformed trust-store Base64 was accepted")

        _bad_der_document = dict(_store_document)
        _bad_der_document["keys"] = [dict(_store_document["keys"][0], public_key_der=base64.b64encode(_v1_der + b"x").decode("ascii"))]
        try:
            parse_trust_store(_store_document_bytes(_bad_der_document))
        except ValueError:
            pass
        else:
            raise AssertionError("noncanonical trust-store DER was accepted")

        _bad_key_fields = dict(_store_document)
        _bad_key_fields["keys"] = [dict(_store_document["keys"][0], extra=1)]
        try:
            parse_trust_store(_store_document_bytes(_bad_key_fields))
        except ValueError:
            pass
        else:
            raise AssertionError("extra trusted-key field was accepted")

        for _invalid_key in (_invalid_ec_public, _rsa_1024_public_key, _rsa_exponent_3_public_key):
            _invalid_der = _invalid_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            try:
                parse_trust_store(_store_document_bytes({"keys": [{"label": "bad", "public_key_der": base64.b64encode(_invalid_der).decode("ascii")}], "version": 1}))
            except ValueError:
                pass
            else:
                raise AssertionError("unsupported trusted key was accepted")

        _original_store_limit = MAX_TRUST_STORE_LENGTH
        try:
            stego_v1.MAX_TRUST_STORE_LENGTH = len(_store_bytes) - 1
            try:
                serialize_trust_store(_trusted_records)
            except ValueError:
                pass
            else:
                raise AssertionError("trust-store serialized size limit was not enforced")
        finally:
            stego_v1.MAX_TRUST_STORE_LENGTH = _original_store_limit

    def test_focused_checks_for_encrypted_private_key_path_persistence(self):
        # Focused checks for encrypted private-key path persistence.

        with TemporaryDirectory() as _key_directory:
            _key_path = Path(_key_directory) / "signing-key.pem"
            assert save_new_encrypted_rsa_private_key_to_path(_signing_private, _private_password, _key_path) is None
            _saved_pem = _key_path.read_bytes()
            assert _saved_pem.startswith(_ENCRYPTED_PRIVATE_KEY_BEGIN)
            assert parse_encrypted_rsa_private_key(_saved_pem, _private_password).public_key().public_numbers() == _signing_public.public_numbers()
            _loaded_private = load_encrypted_rsa_private_key_from_path(_key_path, _private_password)
            assert _loaded_private.public_key().public_numbers() == _signing_public.public_numbers()
            try:
                load_encrypted_rsa_private_key_from_path(_key_path, b"wrong password")
            except ValueError:
                pass
            else:
                raise AssertionError("wrong path-load password was accepted")
            if os.name == "posix":
                assert S_IMODE(_key_path.stat().st_mode) == (S_IRUSR | S_IWUSR)

            _before_existing = _key_path.read_bytes()
            try:
                save_new_encrypted_rsa_private_key_to_path(_signing_private, b"another password", _key_path)
            except ValueError:
                pass
            else:
                raise AssertionError("existing private-key target was overwritten")
            assert _key_path.read_bytes() == _before_existing

            _missing_source = Path(_key_directory) / "missing.pem"
            _directory_source = Path(_key_directory) / "source-directory"
            _directory_source.mkdir()
            for _bad_source in (_missing_source, _directory_source):
                try:
                    load_encrypted_rsa_private_key_from_path(_bad_source, _private_password)
                except ValueError:
                    pass
                else:
                    raise AssertionError("invalid private-key source was accepted")

            _missing_parent = Path(_key_directory) / "missing" / "new.pem"
            try:
                save_new_encrypted_rsa_private_key_to_path(_signing_private, _private_password, _missing_parent)
            except ValueError:
                pass
            else:
                raise AssertionError("missing private-key parent was accepted")

            _directory_target = Path(_key_directory) / "target-directory"
            _directory_target.mkdir()
            try:
                save_new_encrypted_rsa_private_key_to_path(_signing_private, _private_password, _directory_target)
            except ValueError:
                pass
            else:
                raise AssertionError("directory private-key target was accepted")

            _write_failure_path = Path(_key_directory) / "write-failure.pem"
            _original_fdopen = os.fdopen
            # Simulates a private-key file-open failure.
            def _unexpected_fdopen(*_args, **_kwargs):
                raise OSError("simulated close/write failure")
            os.fdopen = _unexpected_fdopen
            try:
                try:
                    save_new_encrypted_rsa_private_key_to_path(_signing_private, _private_password, _write_failure_path)
                except ValueError:
                    pass
                else:
                    raise AssertionError("simulated write failure was accepted")
            finally:
                os.fdopen = _original_fdopen
            assert not _write_failure_path.exists()

            _oversized_path = Path(_key_directory) / "oversized.pem"
            _oversized_path.write_bytes(b"x" * (MAX_ENCRYPTED_PRIVATE_KEY_PEM_LENGTH + 1))
            _original_parser = parse_encrypted_rsa_private_key
            # Detects parsing of an oversized private-key file.
            def _unexpected_parse(*_args, **_kwargs):
                raise AssertionError("oversized PEM reached the parser")
            stego_v1.parse_encrypted_rsa_private_key = _unexpected_parse
            try:
                try:
                    load_encrypted_rsa_private_key_from_path(_oversized_path, _private_password)
                except ValueError:
                    pass
                else:
                    raise AssertionError("oversized private-key PEM was accepted")
            finally:
                stego_v1.parse_encrypted_rsa_private_key = _original_parser

        for _bad_path in (None, 123, ["key.pem"]):
            try:
                load_encrypted_rsa_private_key_from_path(_bad_path, _private_password)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid private-key source path was accepted")
            try:
                save_new_encrypted_rsa_private_key_to_path(_signing_private, _private_password, _bad_path)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid private-key target path was accepted")
        for _bad_password in (b"", bytearray(b"password"), "password"):
            try:
                load_encrypted_rsa_private_key_from_path("missing.pem", _bad_password)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid path-load password was accepted")
        try:
            save_new_encrypted_rsa_private_key_to_path(_signing_public, _private_password, "unused.pem")
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError("invalid private key was accepted for persistence")

    def test_focused_checks_for_bounded_trust_store_loading_and_atomic_saving(self):
        # Focused checks for bounded trust-store loading and atomic saving.
        with TemporaryDirectory() as _trust_directory:
            _trust_directory = Path(_trust_directory)
            _empty_store_path = _trust_directory / "empty.json"
            assert save_trust_store_to_path((), _empty_store_path) is None
            assert _empty_store_path.read_bytes() == b"{\"keys\":[],\"version\":1}"
            assert load_trust_store_from_path(_empty_store_path) == ()

            _store_path = _trust_directory / "trusted.json"
            _source_records = tuple(_trusted_records)
            save_trust_store_to_path(_source_records, _store_path)
            _saved_store_bytes = _store_path.read_bytes()
            assert _saved_store_bytes == serialize_trust_store(_source_records)
            assert load_trust_store_from_path(_store_path) == _source_records
            assert _source_records == tuple(_trusted_records)
            if os.name == "posix":
                assert S_IMODE(_store_path.stat().st_mode) == (S_IRUSR | S_IWUSR)

            _replacement_records = (_trusted_b,)
            save_trust_store_to_path(_replacement_records, _store_path)
            assert load_trust_store_from_path(_store_path) == _replacement_records

            _missing_source = _trust_directory / "missing.json"
            _directory_source = _trust_directory / "source-directory"
            _directory_source.mkdir()
            for _bad_source in (_missing_source, _directory_source):
                try:
                    load_trust_store_from_path(_bad_source)
                except ValueError:
                    pass
                else:
                    raise AssertionError("invalid trust-store source was accepted")

            _missing_parent = _trust_directory / "missing" / "store.json"
            try:
                save_trust_store_to_path(_source_records, _missing_parent)
            except ValueError:
                pass
            else:
                raise AssertionError("missing trust-store parent was accepted")

            _directory_target = _trust_directory / "directory-target"
            _directory_target.mkdir()
            try:
                save_trust_store_to_path(_source_records, _directory_target)
            except ValueError:
                pass
            else:
                raise AssertionError("directory trust-store target was accepted")

            _malformed_path = _trust_directory / "malformed.json"
            _malformed_path.write_bytes(b"not json")
            try:
                load_trust_store_from_path(_malformed_path)
            except ValueError:
                pass
            else:
                raise AssertionError("malformed trust store was accepted")

            _oversized_path = _trust_directory / "oversized.json"
            _oversized_path.write_bytes(b"x" * (MAX_TRUST_STORE_LENGTH + 1))
            _original_parser = parse_trust_store
            # Detects parsing of an oversized trust store.
            def _unexpected_trust_parser(*_args, **_kwargs):
                raise AssertionError("oversized trust store reached parser")
            stego_v1.parse_trust_store = _unexpected_trust_parser
            try:
                try:
                    load_trust_store_from_path(_oversized_path)
                except ValueError:
                    pass
                else:
                    raise AssertionError("oversized trust store was accepted")
            finally:
                stego_v1.parse_trust_store = _original_parser

            _existing_before_failure = _store_path.read_bytes()
            _original_fdopen = os.fdopen
            # Simulates a trust-store write failure.
            def _unexpected_trust_fdopen(*_args, **_kwargs):
                raise OSError("simulated trust-store write failure")
            os.fdopen = _unexpected_trust_fdopen
            try:
                try:
                    save_trust_store_to_path(_source_records, _store_path)
                except ValueError:
                    pass
                else:
                    raise AssertionError("simulated trust-store write failure was accepted")
            finally:
                os.fdopen = _original_fdopen
            assert _store_path.read_bytes() == _existing_before_failure
            assert not list(_trust_directory.glob(".trust-store-*.tmp"))

            _original_replace = os.replace
            # Simulates a trust-store replacement failure.
            def _unexpected_trust_replace(*_args, **_kwargs):
                raise OSError("simulated trust-store replace failure")
            os.replace = _unexpected_trust_replace
            try:
                try:
                    save_trust_store_to_path(_source_records, _store_path)
                except ValueError:
                    pass
                else:
                    raise AssertionError("simulated trust-store replace failure was accepted")
            finally:
                os.replace = _original_replace
            assert _store_path.read_bytes() == _existing_before_failure
            assert not list(_trust_directory.glob(".trust-store-*.tmp"))

        for _bad_path in (None, 123, ["store.json"]):
            try:
                load_trust_store_from_path(_bad_path)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid trust-store source path was accepted")
            try:
                save_trust_store_to_path((), _bad_path)
            except TypeError:
                pass
            else:
                raise AssertionError("invalid trust-store target path was accepted")
        for _bad_records in (None, [None], "records"):
            try:
                save_trust_store_to_path(_bad_records, "store.json")
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid trust records were accepted")

    def test_focused_checks_for_media_neutral_v1_carrier_encoding_orchestration(self):
        # Focused checks for media-neutral v1 carrier encoding orchestration.
        _encode_source = np.arange(10000, dtype=np.uint8)
        _encode_message = "standalone encoder message"
        _encode_metadata = {"purpose": "test", "source": "opaque"}
        _encode_contexts = (
            (IMAGE_MEDIA_CODE, b"opaque image context"),
            (AUDIO_MEDIA_CODE, b"\x00opaque audio context\xff"),
        )

        for _media_type, _media_context in _encode_contexts:
            for _lsb_count in (1, 3, 8):
                _original_carrier = _encode_source.copy()
                _captured_provisional = []
                _original_factory = create_v1_payload_record
                # Captures a provisional payload in an encoder test.
                def _capture_factory(*_args, **_kwargs):
                    _record = _original_factory(*_args, **_kwargs)
                    _captured_provisional.append(_record)
                    return _record
                stego_v1.create_v1_payload_record = _capture_factory
                try:
                    _encoded_carrier, _layout, _encoded_payload = encode_v1_carrier(
                        _original_carrier,
                        _media_type,
                        _media_context,
                        _signing_private,
                        11,
                        _lsb_count,
                        _encode_message,
                        _encode_metadata,
                    )
                finally:
                    stego_v1.create_v1_payload_record = _original_factory

                assert _captured_provisional and len(_captured_provisional) == 1
                _provisional = _captured_provisional[0]
                assert _encoded_payload.media_type == _provisional.media_type
                assert _encoded_payload.media_context == _provisional.media_context
                assert _encoded_payload.public_key_der == _provisional.public_key_der
                assert _encoded_payload.media_id == _provisional.media_id
                assert _encoded_payload.timestamp == _provisional.timestamp
                assert _encoded_payload.nonce == _provisional.nonce
                assert _encoded_payload.message == _provisional.message
                assert _encoded_payload.metadata == _provisional.metadata

                assert np.array_equal(_original_carrier, _encode_source)
                _region2_stream = extract_region2_stream(_encoded_carrier, _layout)
                _header, _payload_bytes = parse_region2_stream(_region2_stream)
                assert parse_v1_payload(_payload_bytes) == _encoded_payload
                assert _region2_stream == build_region2_stream(
                    serialize_v1_payload(_encoded_payload), _lsb_count
                )

                _region2_values = select_region2_units(_encoded_carrier, _layout)
                _signing_input = encode_region2_signing_input(
                    _media_type, _media_context, _layout, _region2_values
                )
                _signature = extract_region3_signature(_encoded_carrier, _layout)
                assert verify_v1_signature(
                    _signing_input, _signature, _signing_public
                )
                assert calculate_layout_hashes(_encoded_carrier, _layout) == (
                    _encoded_payload.unembedded_carrier_hash,
                    _encoded_payload.reserved_upper_bits_hash,
                )

                _changed_indices = np.flatnonzero(_encoded_carrier != _original_carrier)
                _allowed_indices = set(range(*_layout.region2_range)) | set(range(*_layout.region3_range))
                assert set(_changed_indices.tolist()) <= _allowed_indices
                _lsb_mask = (1 << _lsb_count) - 1
                assert all(
                    (int(_original_carrier[_index]) ^ int(_encoded_carrier[_index])) & ~_lsb_mask == 0
                    for _index in _changed_indices
                )

        # Generic input and boundary failures are rejected without media-specific validation.
        for _bad_carrier in (
            [1, 2],
            np.array([1, 2], dtype=np.uint16),
            np.array([[1, 2]], dtype=np.uint8),
        ):
            try:
                encode_v1_carrier(_bad_carrier, IMAGE_MEDIA_CODE, b"ctx", _signing_private, 0, 3, "m", {})
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid carrier was accepted")
        for _bad_media_type in (0, True, 3):
            try:
                encode_v1_carrier(_encode_source, _bad_media_type, b"ctx", _signing_private, 0, 3, "m", {})
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid media type was accepted")
        for _bad_context in (bytearray(b"ctx"), b"x" * (MAX_MEDIA_CONTEXT_LENGTH + 1)):
            try:
                encode_v1_carrier(_encode_source, IMAGE_MEDIA_CODE, _bad_context, _signing_private, 0, 3, "m", {})
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid media context was accepted")
        for _bad_key in (_signing_public, None):
            try:
                encode_v1_carrier(_encode_source, IMAGE_MEDIA_CODE, b"ctx", _bad_key, 0, 3, "m", {})
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid private key was accepted")
        for _bad_start in (-1, 10000, True):
            try:
                encode_v1_carrier(_encode_source, IMAGE_MEDIA_CODE, b"ctx", _signing_private, _bad_start, 3, "m", {})
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid start unit was accepted")
        for _bad_lsb in (0, 9, True):
            try:
                encode_v1_carrier(_encode_source, IMAGE_MEDIA_CODE, b"ctx", _signing_private, 0, _bad_lsb, "m", {})
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid LSB count was accepted")
        for _bad_message, _bad_metadata in ((None, {}), ("m", [("x", 1)])):
            try:
                encode_v1_carrier(_encode_source, IMAGE_MEDIA_CODE, b"ctx", _signing_private, 0, 3, _bad_message, _bad_metadata)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid payload input was accepted")
        try:
            encode_v1_carrier(np.zeros(100, dtype=np.uint8), IMAGE_MEDIA_CODE, b"ctx", _signing_private, 0, 3, "m", {})
        except ValueError:
            pass
        else:
            raise AssertionError("insufficient carrier capacity was accepted")

    def test_focused_checks_for_cryptographic_verification_of_one_resolved_v1_candidate(self):
        # Focused checks for cryptographic verification of one resolved v1 candidate.
        _verify_carrier = np.arange(10000, dtype=np.uint8)
        _verify_contexts = (
            (IMAGE_MEDIA_CODE, b"opaque image context"),
            (AUDIO_MEDIA_CODE, b"\x00opaque audio context\xff"),
        )
        _verify_outputs = {}
        for _media_type, _media_context in _verify_contexts:
            for _lsb_count in (1, 3, 8):
                _encoded, _layout, _payload = encode_v1_carrier(
                    _verify_carrier,
                    _media_type,
                    _media_context,
                    _signing_private,
                    11,
                    _lsb_count,
                    "verification message",
                    {"kind": "focused"},
                )
                _resolved = resolve_region2_candidate(
                    _encoded, StartMagicCandidate(11, _lsb_count)
                )
                _source_copy = _encoded.copy()
                _returned_payload, _returned_key = verify_resolved_v1_candidate(
                    _encoded, _media_type, _media_context, _resolved
                )
                assert _returned_payload == _payload
                assert _returned_key.public_numbers() == _signing_public.public_numbers()
                assert np.array_equal(_encoded, _source_copy)
                _verify_outputs[(_media_type, _lsb_count)] = (_encoded, _layout, _payload, _resolved)

        # Adapter-supplied identity/context is part of the authenticated expectation.
        _valid_encoded, _valid_layout, _valid_payload, _valid_resolved = _verify_outputs[(IMAGE_MEDIA_CODE, 3)]
        for _wrong_media_type, _wrong_context in (
            (AUDIO_MEDIA_CODE, b"opaque image context"),
            (IMAGE_MEDIA_CODE, b"different context"),
        ):
            try:
                verify_resolved_v1_candidate(
                    _valid_encoded, _wrong_media_type, _wrong_context, _valid_resolved
                )
            except ValueError:
                pass
            else:
                raise AssertionError("wrong adapter media identity was accepted")

        # Region 1 corruption reaches the distinct Region 1 hash check.
        _region1_corrupt = _valid_encoded.copy()
        _region1_index = _valid_layout.region1_ranges[0][0]
        _region1_corrupt[_region1_index] ^= np.uint8(1)
        try:
            verify_resolved_v1_candidate(
                _region1_corrupt, IMAGE_MEDIA_CODE, b"opaque image context", _valid_resolved
            )
        except ValueError as _error:
            assert "Region 1" in str(_error) and "hash" in str(_error)
        else:
            raise AssertionError("Region 1 corruption was accepted")

        # Region 2 changes invalidate the RSA-PSS signature.
        _region2_corrupt = _valid_encoded.copy()
        _region2_index = _valid_layout.region2_range[1] - 1
        _region2_corrupt[_region2_index] ^= np.uint8(0x80 if _valid_layout.lsb_count < 8 else 1)
        try:
            verify_resolved_v1_candidate(
                _region2_corrupt, IMAGE_MEDIA_CODE, b"opaque image context", _valid_resolved
            )
        except ValueError as _error:
            assert "signature" in str(_error).lower() or "candidate" in str(_error).lower()
        else:
            raise AssertionError("Region 2 corruption was accepted")

        # Region 3 upper-bit corruption reaches the distinct Region 3 hash check.
        _region3_upper_corrupt = _verify_outputs[(IMAGE_MEDIA_CODE, 3)][0].copy()
        _region3_upper_corrupt[_verify_outputs[(IMAGE_MEDIA_CODE, 3)][1].region3_range[0]] ^= np.uint8(0x80)
        try:
            verify_resolved_v1_candidate(
                _region3_upper_corrupt,
                IMAGE_MEDIA_CODE,
                b"opaque image context",
                _verify_outputs[(IMAGE_MEDIA_CODE, 3)][3],
            )
        except ValueError as _error:
            assert "Region 3" in str(_error) and "hash" in str(_error)
        else:
            raise AssertionError("Region 3 upper-bit corruption was accepted")

        # A signature-bit corruption is distinguished from alignment padding corruption.
        _signature_corrupt = _valid_encoded.copy()
        _signature_corrupt[_valid_layout.region3_range[0]] ^= np.uint8(1)
        try:
            verify_resolved_v1_candidate(
                _signature_corrupt, IMAGE_MEDIA_CODE, b"opaque image context", _valid_resolved
            )
        except ValueError as _error:
            assert "signature" in str(_error).lower()
        else:
            raise AssertionError("signature corruption was accepted")

        _padding_layout = _verify_outputs[(IMAGE_MEDIA_CODE, 3)][1]
        _padding_corrupt = _verify_outputs[(IMAGE_MEDIA_CODE, 3)][0].copy()
        _padding_corrupt[_padding_layout.region3_range[1] - 1] ^= np.uint8(1)
        try:
            verify_resolved_v1_candidate(
                _padding_corrupt,
                IMAGE_MEDIA_CODE,
                b"opaque image context",
                _verify_outputs[(IMAGE_MEDIA_CODE, 3)][3],
            )
        except ValueError as _error:
            assert "padding" in str(_error).lower()
        else:
            raise AssertionError("signature padding corruption was accepted")

        # A resolved record must be exact and current; forged fields and wrong types are rejected.
        _forged_resolved = ResolvedRegion2Candidate(
            _valid_resolved.candidate,
            Region2Header(
                _valid_resolved.header.protocol_version,
                _valid_resolved.header.lsb_count,
                _valid_resolved.header.header_length,
                _valid_resolved.header.payload_length + 1,
            ),
            _valid_resolved.layout,
        )
        for _bad_resolved in (None, (_valid_resolved,), _forged_resolved):
            try:
                verify_resolved_v1_candidate(
                    _valid_encoded,
                    IMAGE_MEDIA_CODE,
                    b"opaque image context",
                    _bad_resolved,
                )
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid resolved candidate was accepted")

        _stale_encoded, _stale_layout, _stale_payload = encode_v1_carrier(
            _verify_carrier,
            AUDIO_MEDIA_CODE,
            b"opaque audio context",
            _signing_private,
            27,
            3,
            "stale candidate",
            {},
        )
        try:
            verify_resolved_v1_candidate(
                _stale_encoded,
                IMAGE_MEDIA_CODE,
                b"opaque image context",
                _valid_resolved,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("stale resolved candidate was accepted")

        for _bad_carrier in (
            [0, 1],
            np.array([0, 1], dtype=np.int16),
            np.array([[0, 1]], dtype=np.uint8),
        ):
            try:
                verify_resolved_v1_candidate(
                    _bad_carrier, IMAGE_MEDIA_CODE, b"opaque image context", _valid_resolved
                )
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid verification carrier was accepted")

    def test_focused_checks_for_bounded_candidate_scanning_verification_and_trust_verdicts(self):
        # Focused checks for bounded candidate scanning, verification, and trust verdicts.
        _decode_carrier = np.arange(10000, dtype=np.uint8)
        _decode_carrier_source = _decode_carrier.copy()
        _decode_contexts = (
            (IMAGE_MEDIA_CODE, b"decode image context"),
            (AUDIO_MEDIA_CODE, b"\x00decode audio context\xff"),
        )
        _decode_outputs = {}
        for _media_type, _media_context in _decode_contexts:
            for _lsb_count in (1, 3, 8):
                _encoded, _layout, _payload = encode_v1_carrier(
                    _decode_carrier,
                    _media_type,
                    _media_context,
                    _signing_private,
                    13,
                    _lsb_count,
                    "decoder message",
                    {"stage": "decode"},
                )
                _candidate = StartMagicCandidate(13, _lsb_count)
                _resolved = resolve_region2_candidate(_encoded, _candidate)
                _decode_outputs[(_media_type, _lsb_count)] = (_encoded, _layout, _payload, _resolved)
                _unknown_result = decode_v1_carrier(_encoded, _media_type, _media_context)
                assert isinstance(_unknown_result, V1VerificationResult)
                assert _unknown_result.valid
                assert _unknown_result.verdict == "Signature Valid — Key Not Trusted"
                assert _unknown_result.payload == _payload
                assert _unknown_result.key_fingerprint == display_rsa_public_key_fingerprint(_signing_public)
                assert _unknown_result.trusted_label is None
                assert _unknown_result.candidate == _candidate
                assert "unknown" in _unknown_result.detail.lower()
                _trusted_result = decode_v1_carrier(
                    _encoded,
                    _media_type,
                    _media_context,
                    (TrustedKeyRecord(serialize_rsa_public_key(_signing_public), "local signer"),),
                )
                assert _trusted_result.valid
                assert _trusted_result.verdict == "Authentic"
                assert _trusted_result.detail == "Signed by trusted key"
                assert _trusted_result.payload == _payload
                assert _trusted_result.trusted_label == "local signer"
                assert _trusted_result.key_fingerprint == _unknown_result.key_fingerprint
                assert np.array_equal(_decode_carrier, _decode_carrier_source)
        # No marker and wrong adapter identity do not produce authenticated output.
        _no_marker = np.zeros(10000, dtype=np.uint8)
        _missing_result = decode_v1_carrier(_no_marker, IMAGE_MEDIA_CODE, b"ctx")
        assert not _missing_result.valid and _missing_result.verdict == "Payload Missing"
        assert _missing_result.payload is None and _missing_result.key_fingerprint is None
        _wrong_identity = decode_v1_carrier(
            _decode_outputs[(IMAGE_MEDIA_CODE, 3)][0],
            AUDIO_MEDIA_CODE,
            b"wrong context",
        )
        assert not _wrong_identity.valid
        assert _wrong_identity.payload is None and _wrong_identity.candidate is None

        # Region 1 and Region 3 upper-bit tampering are classified distinctly as tampering.
        _image_encoded, _image_layout, _image_payload, _image_resolved = _decode_outputs[(IMAGE_MEDIA_CODE, 3)]
        _region1_tampered = _image_encoded.copy()
        _region1_tampered[_image_layout.region1_ranges[0][0]] ^= np.uint8(1)
        _region1_result = decode_v1_carrier(_region1_tampered, IMAGE_MEDIA_CODE, b"decode image context")
        assert not _region1_result.valid and _region1_result.verdict == "Tampered"
        assert "Region 1" in _region1_result.detail
        _region3_tampered = _image_encoded.copy()
        _region3_tampered[_image_layout.region3_range[0]] ^= np.uint8(0x80)
        _region3_result = decode_v1_carrier(_region3_tampered, IMAGE_MEDIA_CODE, b"decode image context")
        assert not _region3_result.valid and _region3_result.verdict == "Tampered"
        assert "Region 3" in _region3_result.detail

        _signature_tampered = _image_encoded.copy()
        _signature_tampered[_image_layout.region3_range[0]] ^= np.uint8(1)
        _signature_result = decode_v1_carrier(_signature_tampered, IMAGE_MEDIA_CODE, b"decode image context")
        assert not _signature_result.valid and _signature_result.verdict == "Signature Invalid"
        assert "signature" in _signature_result.detail.lower()
        _padding_tampered = _image_encoded.copy()
        _padding_tampered[_image_layout.region3_range[1] - 1] ^= np.uint8(1)
        _padding_result = decode_v1_carrier(_padding_tampered, IMAGE_MEDIA_CODE, b"decode image context")
        assert not _padding_result.valid and _padding_result.verdict == "Tampered"
        assert "padding" in _padding_result.detail.lower()

        # A failed fake marker is ignored when a real candidate also verifies.
        _original_scanner = scan_start_magic
        # Supplies a failed fake and valid candidate in a test.
        def _fake_then_valid_scanner(_carrier):
            return (StartMagicCandidate(0, 1), _image_resolved.candidate)
        stego_v1.scan_start_magic = _fake_then_valid_scanner
        try:
            _fake_result = decode_v1_carrier(_image_encoded, IMAGE_MEDIA_CODE, b"decode image context")
        finally:
            stego_v1.scan_start_magic = _original_scanner
        assert _fake_result.valid and _fake_result.payload == _image_payload

        # Multiple valid candidates are ambiguous and expose no authenticated fields.
        # Supplies duplicate valid candidates in a test.
        def _duplicate_valid_scanner(_carrier):
            return (_image_resolved.candidate, _image_resolved.candidate)
        stego_v1.scan_start_magic = _duplicate_valid_scanner
        try:
            _ambiguous_result = decode_v1_carrier(_image_encoded, IMAGE_MEDIA_CODE, b"decode image context")
        finally:
            stego_v1.scan_start_magic = _original_scanner
        assert not _ambiguous_result.valid and _ambiguous_result.verdict == "Cannot Verify"
        assert "ambiguous" in _ambiguous_result.detail.lower()
        assert _ambiguous_result.payload is None and _ambiguous_result.key_fingerprint is None

        # Scanner/resource failures become a safe invalid result.
        # Simulates a scanner resource failure.
        def _failing_scanner(_carrier):
            raise ValueError("candidate resource limit")
        stego_v1.scan_start_magic = _failing_scanner
        try:
            _scanner_result = decode_v1_carrier(_image_encoded, IMAGE_MEDIA_CODE, b"decode image context")
        finally:
            stego_v1.scan_start_magic = _original_scanner
        assert not _scanner_result.valid and _scanner_result.verdict == "Cannot Verify"
        assert _scanner_result.payload is None and "scanner" in _scanner_result.detail.lower()

        # Malformed trust records are rejected before candidate processing.
        for _bad_trust_records in (None, [None], "records"):
            try:
                decode_v1_carrier(_image_encoded, IMAGE_MEDIA_CODE, b"decode image context", _bad_trust_records)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("malformed trust records were accepted")

        for _bad_input in (
            ([0, 1], IMAGE_MEDIA_CODE, b"ctx"),
            (np.array([0, 1], dtype=np.int16), IMAGE_MEDIA_CODE, b"ctx"),
            (_image_encoded, 0, b"ctx"),
            (_image_encoded, IMAGE_MEDIA_CODE, bytearray(b"ctx")),
        ):
            try:
                decode_v1_carrier(*_bad_input)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError("invalid decoder input was accepted")

    def test_focused_bounded_end_to_end_checks_for_png_and_wav_v1_wrappers(self):
        # Focused bounded end-to-end checks for PNG and WAV v1 wrappers.

        _wrapper_message = "wrapper round trip"
        _wrapper_metadata = {"kind": "end-to-end", "scope": "adapter"}
        _wrapper_trusted = (
            TrustedKeyRecord(serialize_rsa_public_key(_signing_public), "wrapper signer"),
        )
        with TemporaryDirectory() as _wrapper_directory_name:
            _wrapper_directory = Path(_wrapper_directory_name)
            _png_input = _wrapper_directory / "input.png"
            _png_output = _wrapper_directory / "output.png"
            _png_source_array = np.arange(10080, dtype=np.uint8).reshape((60, 56, 3))
            Image.fromarray(_png_source_array, mode="RGB").save(_png_input, format="PNG")
            _png_source_bytes = _png_input.read_bytes()

            _wav_input = _wrapper_directory / "input.wav"
            _wav_output = _wrapper_directory / "output.wav"
            _wav_source_bytes = bytes(np.arange(10000, dtype=np.uint8))
            with wave.open(str(_wav_input), "wb") as _wav_file:
                _wav_file.setnchannels(1)
                _wav_file.setsampwidth(1)
                _wav_file.setframerate(8000)
                _wav_file.writeframes(_wav_source_bytes)
            _wav_source_file_bytes = _wav_input.read_bytes()

            for _lsb_count in (1, 3, 8):
                _png_layout, _png_payload = encode_png_v1(
                    _png_input,
                    _png_output,
                    _signing_private,
                    13,
                    _lsb_count,
                    _wrapper_message,
                    _wrapper_metadata,
                )
                _png_unknown = verify_png_v1(_png_output)
                assert _png_unknown.valid
                assert _png_unknown.verdict == "Signature Valid — Key Not Trusted"
                assert _png_unknown.payload.message == _wrapper_message
                assert _png_unknown.payload.metadata == tuple(sorted(_wrapper_metadata.items()))
                _png_trusted_result = verify_png_v1(_png_output, _wrapper_trusted)
                assert _png_trusted_result.valid
                assert _png_trusted_result.verdict == "Authentic"
                assert _png_trusted_result.trusted_label == "wrapper signer"
                _png_saved_array = load_png_from_path(_png_output)
                _png_source_carrier = rgb_array_to_carrier(_png_source_array)
                _png_saved_carrier = rgb_array_to_carrier(_png_saved_array)
                assert _png_saved_array.shape == _png_source_array.shape
                _png_changed = np.flatnonzero(_png_source_carrier != _png_saved_carrier)
                _png_allowed = set(range(*_png_layout.region2_range)) | set(range(*_png_layout.region3_range))
                assert set(_png_changed.tolist()) <= _png_allowed
                _png_mask = (1 << _lsb_count) - 1
                assert all(
                    (int(_png_source_carrier[_i]) ^ int(_png_saved_carrier[_i])) & ~_png_mask == 0
                    for _i in _png_changed
                )
                assert _png_input.read_bytes() == _png_source_bytes

                _wav_layout, _wav_payload = encode_wav_v1(
                    _wav_input,
                    _wav_output,
                    _signing_private,
                    13,
                    _lsb_count,
                    _wrapper_message,
                    _wrapper_metadata,
                )
                _wav_unknown = verify_wav_v1(_wav_output)
                assert _wav_unknown.valid
                assert _wav_unknown.verdict == "Signature Valid — Key Not Trusted"
                assert _wav_unknown.payload.message == _wrapper_message
                assert _wav_unknown.payload.metadata == tuple(sorted(_wrapper_metadata.items()))
                _wav_trusted_result = verify_wav_v1(_wav_output, _wrapper_trusted)
                assert _wav_trusted_result.valid
                assert _wav_trusted_result.verdict == "Authentic"
                assert _wav_trusted_result.trusted_label == "wrapper signer"
                _wav_saved = load_pcm_wav_from_path(_wav_output)
                _wav_source_carrier = wav_frame_bytes_to_carrier(_wav_source_bytes)
                _wav_saved_carrier = wav_frame_bytes_to_carrier(_wav_saved.frame_bytes)
                _wav_changed = np.flatnonzero(_wav_source_carrier != _wav_saved_carrier)
                _wav_allowed = set(range(*_wav_layout.region2_range)) | set(range(*_wav_layout.region3_range))
                assert set(_wav_changed.tolist()) <= _wav_allowed
                _wav_mask = (1 << _lsb_count) - 1
                assert all(
                    (int(_wav_source_carrier[_i]) ^ int(_wav_saved_carrier[_i])) & ~_wav_mask == 0
                    for _i in _wav_changed
                )
                assert _wav_input.read_bytes() == _wav_source_file_bytes

            # Region 1 remains outside the output payload and is detected after saving.
            _png_tampered_array = load_png_from_path(_png_output)
            _png_tampered_carrier = rgb_array_to_carrier(_png_tampered_array)
            _png_tampered_carrier[0] ^= np.uint8(1)
            _png_tampered_array = carrier_to_rgb_array(_png_tampered_carrier, _png_tampered_array.shape)
            _png_tampered_path = _wrapper_directory / "tampered.png"
            save_rgb_png_to_path(_png_tampered_array, _png_tampered_path)
            _png_tampered_result = verify_png_v1(_png_tampered_path)
            assert not _png_tampered_result.valid and _png_tampered_result.verdict == "Tampered"
            assert "Region 1" in _png_tampered_result.detail

            _wav_tampered = load_pcm_wav_from_path(_wav_output)
            _wav_tampered_carrier = wav_frame_bytes_to_carrier(_wav_tampered.frame_bytes)
            _wav_tampered_carrier[0] ^= np.uint8(1)
            _wav_tampered_path = _wrapper_directory / "tampered.wav"
            save_pcm_wav_to_path(wav_data_with_carrier(_wav_tampered, _wav_tampered_carrier), _wav_tampered_path)
            _wav_tampered_result = verify_wav_v1(_wav_tampered_path)
            assert not _wav_tampered_result.valid and _wav_tampered_result.verdict == "Tampered"
            assert "Region 1" in _wav_tampered_result.detail

            # Same-path protection, insufficient capacity, invalid files, and wrong formats.
            for _encoder, _source_path, _output_path in (
                (encode_png_v1, _png_input, _png_input),
                (encode_wav_v1, _wav_input, _wav_input),
            ):
                try:
                    _encoder(_source_path, _output_path, _signing_private, 0, 3, "m", {})
                except ValueError:
                    pass
                else:
                    raise AssertionError("same input/output path was accepted")
            _tiny_png = _wrapper_directory / "tiny.png"
            Image.fromarray(np.zeros((1, 1, 3), dtype=np.uint8), mode="RGB").save(_tiny_png, format="PNG")
            try:
                encode_png_v1(_tiny_png, _wrapper_directory / "tiny-out.png", _signing_private, 0, 1, "m", {})
            except ValueError:
                pass
            else:
                raise AssertionError("insufficient PNG capacity was accepted")
            _tiny_wav = _wrapper_directory / "tiny.wav"
            with wave.open(str(_tiny_wav), "wb") as _wav_file:
                _wav_file.setnchannels(1)
                _wav_file.setsampwidth(1)
                _wav_file.setframerate(8000)
                _wav_file.writeframes(b"x")
            try:
                encode_wav_v1(_tiny_wav, _wrapper_directory / "tiny-wav-out.wav", _signing_private, 0, 1, "m", {})
            except ValueError:
                pass
            else:
                raise AssertionError("insufficient WAV capacity was accepted")

            _invalid_file = _wrapper_directory / "invalid.bin"
            _invalid_file.write_bytes(b"not a media file")
            for _verify_wrapper in (verify_png_v1, verify_wav_v1):
                try:
                    _verify_wrapper(_invalid_file)
                except ValueError:
                    pass
                else:
                    raise AssertionError("invalid adapter input was accepted")
            try:
                verify_png_v1(_wav_input)
            except ValueError:
                pass
            else:
                raise AssertionError("WAV input was accepted by PNG wrapper")
            try:
                verify_wav_v1(_png_input)
            except ValueError:
                pass
            else:
                raise AssertionError("PNG input was accepted by WAV wrapper")
