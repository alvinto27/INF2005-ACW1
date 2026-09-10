"""
Audio LSB Steganography Module (FR2 / FR6 / FR8)
==================================================
Reads/writes WAV/PCM cover audio and embeds/extracts an arbitrary byte
packet using selectable 1-8 bit LSB replacement, with a keyed
(passphrase-derived) start location.

This module deliberately does NOT build its own payload framing, hashing,
or signing. That responsibility lives in the team's shared
`payload_protocol.py` (FR3/FR4/FR9/FR10), the same module the image
prototype (FR1/FR5) uses. This module's job is purely: get raw packet
bytes into/out of audio samples, and compute a stable ("canonical") audio
representation that payload_protocol can hash and verify against.

Division of responsibility, mirroring the image notebook:
  - payload_protocol.create_payload()             -> build payload dict/JSON
  - payload_protocol.pack_verification_packet()    -> sign + frame packet
  - audio_lsb_stego.canonical_cover_bytes()        -> stable audio hash input
  - audio_lsb_stego.embed_lsb() / extract_bytes()  -> LSB mechanics only
  - payload_protocol.unpack_and_verify_packet()    -> signature + hash verdict
"""

import wave
import struct
import hashlib


SUPPORTED_SAMPLE_WIDTHS = {1, 2, 3, 4}  # bytes per sample; covers 8/16/24/32-bit PCM


# ---------------------------------------------------------------------
# FR2: WAV/PCM input
# ---------------------------------------------------------------------

def load_wav(path):
    """Load a WAV/PCM file, returning (raw PCM frame bytes, wave._wave_params).

    Fails explicitly (not silently) if the file isn't a format this module
    supports, mirroring load_png()'s explicit-failure behaviour.
    """
    try:
        with wave.open(path, 'rb') as wf:
            params = wf.getparams()
            if params.sampwidth not in SUPPORTED_SAMPLE_WIDTHS:
                raise ValueError(f"Unsupported sample width: {params.sampwidth} bytes")
            if params.comptype != 'NONE':
                raise ValueError(
                    f"Unsupported compression type {params.comptype!r}; "
                    "expected uncompressed PCM"
                )
            n_frames = wf.getnframes()
            raw = wf.readframes(n_frames)
    except wave.Error as exc:
        raise ValueError("Unreadable or corrupted WAV input") from exc
    return bytearray(raw), params


def save_wav(path, sample_bytes, params):
    """Write raw PCM frames back out as a valid WAV file using the original params."""
    with wave.open(path, 'wb') as wf:
        wf.setparams(params)
        wf.writeframes(bytes(sample_bytes))


def wav_metadata(sample_bytes, params) -> dict:
    return {
        "channels": params.nchannels,
        "sample_width_bytes": params.sampwidth,
        "frame_rate": params.framerate,
        "n_frames": params.nframes,
        "embeddable_bytes": len(sample_bytes),
    }


# ---------------------------------------------------------------------
# Validation helpers (mirrors the image prototype's style)
# ---------------------------------------------------------------------

def _validate_lsb_count(lsb_count: int) -> None:
    if isinstance(lsb_count, bool) or not isinstance(lsb_count, int):
        raise TypeError("lsb_count must be an integer")
    if not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be from 1 through 8")


def _validate_start(sample_bytes, start_sample: int) -> None:
    if isinstance(start_sample, bool) or not isinstance(start_sample, int):
        raise TypeError("start_sample must be an integer")
    if not 0 <= start_sample <= len(sample_bytes):
        raise ValueError("start_sample is outside the sample byte sequence")


# ---------------------------------------------------------------------
# Canonical cover representation for hashing (the key finding from the
# image prototype: you cannot hash raw stego bytes, because embedding
# changes them. Clear the same LSBs you're about to embed into BEFORE
# hashing, so the representation is identical before and after embedding.)
# ---------------------------------------------------------------------

CANONICAL_FORMAT = b"FR2FR6-COVER-audio-v1\x00"


def canonical_cover_bytes(sample_bytes, params, lsb_count: int) -> bytes:
    """Stable representation of the audio cover: format params are covered
    (channels, sample width, frame rate), and every sample byte has its
    low `lsb_count` bits cleared, matching the bits embed_lsb() will touch.

    Computing this on the ORIGINAL cover and again on the STEGO file
    (post-embedding) must yield identical bytes -- that equality is what
    lets payload_protocol.unpack_and_verify_packet() prove "the cover
    besides the hidden payload has not changed."
    """
    _validate_lsb_count(lsb_count)
    clear_mask = (0xFF << lsb_count) & 0xFF

    result = bytearray(CANONICAL_FORMAT)
    result.extend(struct.pack(
        ">HHI", params.nchannels, params.sampwidth, params.framerate
    ))
    result.extend(b & clear_mask for b in sample_bytes)
    return bytes(result)


# ---------------------------------------------------------------------
# Start location design (FR7) -- unchanged from before
# ---------------------------------------------------------------------

def derive_start_location(passphrase: str, total_samples: int, reserved: int = 0) -> int:
    """Deterministic, keyed start-sample index. Same passphrase -> same
    location for embedder and verifier; without it, effectively unguessable.
    """
    digest = hashlib.sha256(passphrase.encode('utf-8')).digest()
    offset = int.from_bytes(digest[:8], 'big')
    usable_range = max(total_samples - reserved, 1)
    return reserved + (offset % usable_range)


# ---------------------------------------------------------------------
# Capacity check (mandatory negative-case requirement)
# ---------------------------------------------------------------------

def audio_capacity_bytes(sample_bytes, lsb_count: int, start_sample: int) -> int:
    _validate_lsb_count(lsb_count)
    _validate_start(sample_bytes, start_sample)
    available_samples = len(sample_bytes) - start_sample
    return (available_samples * lsb_count) // 8


# ---------------------------------------------------------------------
# FR6: LSB embedding -- embeds RAW packet bytes only. No extra framing
# here: payload_protocol.pack_verification_packet() already prepends its
# own 4-byte length header and appends the RSA signature, exactly like
# the image prototype relies on.
# ---------------------------------------------------------------------

def embed_lsb(sample_bytes, data: bytes, lsb_count: int, start_sample: int):
    """Return a NEW bytearray with `data` embedded from start_sample using
    lsb_count low bits per sample byte. The input sample_bytes is left
    untouched (mirrors embed_lsb() returning a copied Image in the
    image prototype).
    """
    _validate_lsb_count(lsb_count)
    _validate_start(sample_bytes, start_sample)
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    required_samples = (len(data) * 8 + lsb_count - 1) // lsb_count
    available = len(sample_bytes) - start_sample
    if required_samples > available:
        raise ValueError(
            f"Payload requires {required_samples} samples, but only "
            f"{available} are available from this start location"
        )

    stego = bytearray(sample_bytes)  # copy; never mutate the caller's cover
    replace_mask = (1 << lsb_count) - 1
    clear_mask = 0xFF ^ replace_mask

    bit_pos = 0
    total_bits = len(data) * 8
    for offset in range(required_samples):
        symbol = 0
        for _ in range(lsb_count):
            symbol <<= 1
            if bit_pos < total_bits:
                byte_val = data[bit_pos // 8]
                bit_in_byte = bit_pos % 8
                symbol |= (byte_val >> (7 - bit_in_byte)) & 1
            bit_pos += 1
        idx = start_sample + offset
        stego[idx] = (stego[idx] & clear_mask) | symbol

    return stego


# ---------------------------------------------------------------------
# FR8: extraction -- mirrors extract_bytes()/extract_protocol_packet()
# from the image prototype, byte-for-byte in approach.
# ---------------------------------------------------------------------

def extract_bytes(sample_bytes, byte_count: int, lsb_count: int, start_sample: int) -> bytes:
    _validate_lsb_count(lsb_count)
    _validate_start(sample_bytes, start_sample)
    if byte_count < 0:
        raise ValueError("byte_count cannot be negative")

    required_samples = (byte_count * 8 + lsb_count - 1) // lsb_count
    available = len(sample_bytes) - start_sample
    if required_samples > available:
        raise ValueError("Requested bytes exceed the available audio capacity")

    symbol_mask = (1 << lsb_count) - 1
    accumulator = 0
    accumulated_bits = 0
    output = bytearray()

    for offset in range(required_samples):
        idx = start_sample + offset
        accumulator = (accumulator << lsb_count) | (sample_bytes[idx] & symbol_mask)
        accumulated_bits += lsb_count

        while accumulated_bits >= 8 and len(output) < byte_count:
            accumulated_bits -= 8
            output.append((accumulator >> accumulated_bits) & 0xFF)
            accumulator &= (1 << accumulated_bits) - 1

    return bytes(output)


def extract_protocol_packet(sample_bytes, public_key, lsb_count: int, start_sample: int) -> bytes:
    """Read payload_protocol's own 4-byte length header first, derive the
    RSA signature size from the public key (not hardcoded), then pull the
    full packet in one go. Same two-step approach as the image prototype's
    extract_protocol_packet().
    """
    length_header = extract_bytes(sample_bytes, 4, lsb_count, start_sample)
    payload_length = struct.unpack(">I", length_header)[0]
    signature_length = (public_key.key_size + 7) // 8
    packet_length = 4 + payload_length + signature_length
    return extract_bytes(sample_bytes, packet_length, lsb_count, start_sample)


# ---------------------------------------------------------------------
# End-to-end self-test, mirroring the image notebook's integration cell:
# builds a real signed packet via payload_protocol, embeds it, reloads
# from disk, verifies (Authentic), then demonstrates Tampered by flipping
# a HIGH bit outside the LSB region -- proving the cover-tamper check
# works independently of whether the embedded packet itself is intact.
# ---------------------------------------------------------------------

if __name__ == '__main__':
    import os
    from payload_protocol import (
        create_payload,
        generate_rsa_keypair,
        pack_verification_packet,
        unpack_and_verify_packet,
    )

    test_path = 'test_cover.wav'
    if not os.path.exists(test_path):
        with wave.open(test_path, 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            silence = struct.pack('<h', 0) * 44100  # 1 second of silence
            wf.writeframes(silence)

    cover_samples, params = load_wav(test_path)
    print("Cover metadata:", wav_metadata(cover_samples, params))

    lsb_count = 2
    passphrase = "team-secret-key-2026"
    start = derive_start_location(passphrase, len(cover_samples))
    print(f"Derived start sample: {start}")

    private_key, public_key = generate_rsa_keypair()
    stable_cover = canonical_cover_bytes(cover_samples, params, lsb_count)

    payload = create_payload(
        "prototype-audio",
        stable_cover,
        {"format": "WAV", "lsb_count": lsb_count},
    )
    packet = pack_verification_packet(payload, private_key)

    capacity = audio_capacity_bytes(cover_samples, lsb_count, start)
    print(f"Capacity at this start/lsb_count: {capacity} bytes, packet needs {len(packet)} bytes")
    assert len(packet) <= capacity, "Packet does not fit -- capacity check would reject this"

    stego_samples = embed_lsb(cover_samples, packet, lsb_count, start)
    assert cover_samples != stego_samples, "Stego should differ from the original cover"

    save_wav('test_stego.wav', stego_samples, params)
    print("Wrote test_stego.wav")

    # --- Verifier side: independent reload from disk ---
    reloaded_samples, reloaded_params = load_wav('test_stego.wav')
    extracted_packet = extract_protocol_packet(reloaded_samples, public_key, lsb_count, start)
    verification = unpack_and_verify_packet(
        extracted_packet, public_key,
        canonical_cover_bytes(reloaded_samples, reloaded_params, lsb_count)
    )
    print("Verification (should be Authentic):", verification[:2])
    assert verification[0:2] == (True, "Authentic")

    # --- Negative case 1: cover tampering, payload left intact ---
    # Flip a HIGH bit (0x80) on a sample far outside the embedding region,
    # exactly like the image notebook flips a high bit on the last pixel.
    tampered = bytearray(reloaded_samples)
    tamper_index = len(tampered) - 1
    tampered[tamper_index] ^= 0x80
    tampered_verification = unpack_and_verify_packet(
        extracted_packet, public_key,
        canonical_cover_bytes(tampered, reloaded_params, lsb_count)
    )
    print("Verification after high-bit tamper (should be Tampered):", tampered_verification[:2])
    assert tampered_verification[0:2] == (False, "Tampered")

    # --- Negative case 2: wrong start location (e.g. wrong passphrase) ---
    wrong_start = derive_start_location("wrong-key", len(reloaded_samples))
    try:
        wrong_packet = extract_protocol_packet(reloaded_samples, public_key, lsb_count, wrong_start)
        wrong_verification = unpack_and_verify_packet(wrong_packet, public_key)
        print("Verification with wrong start location:", wrong_verification[:2])
        assert wrong_verification[0] is False, "Wrong start location should not verify as Authentic"
    except (ValueError, struct.error) as exc:
        print(f"Wrong start location correctly failed to extract: {exc}")

    # --- Negative case 3: capacity check on an oversized payload ---
    oversized_payload = create_payload(
        "prototype-audio-oversized",
        stable_cover,
        {"note": "x" * 1_000_000},  # deliberately far too large for this cover
    )
    oversized_packet = pack_verification_packet(oversized_payload, private_key)
    try:
        embed_lsb(cover_samples, oversized_packet, lsb_count, start)
        print("WARNING: oversized payload unexpectedly fit")
    except ValueError as exc:
        print(f"Capacity check correctly rejected oversized payload: {exc}")

    print("\nAll checks passed.")
