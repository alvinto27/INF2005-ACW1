"""Integration tests for the Flask UI on the current masked-media protocol."""

import io
import json
import os
import struct
import tempfile
import unittest
import wave
import zlib
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import av
import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PIL import Image
from werkzeug.datastructures import MultiDict

from stego import (
    BOOTSTRAP_LSB_COUNT,
    PROTOCOL_VERSION,
    PayloadRecord,
    VideoCarrier,
    bit_sequence_to_bytes,
    bootstrap_span,
    bytes_to_bit_sequence,
    display_rsa_public_key_fingerprint,
    generate_rsa_keypair,
    open_with_private_key,
    parse_bootstrap,
    read_lsb_bits,
    seal_to_public_key,
    write_lsb_bits,
)
from stego.constants import MEDIA_ID_SIZE
from stego.media import _PNG_MAX_DECODED_BYTES
from stego.packet import serialized_record_length
from stego.storage import DISK_SPACE_RESERVE_BYTES
from stego.sources import (
    _convert_audio,
    _convert_image,
    _decoded_audio_frames,
    _decoded_image_frames,
)
from stego_web import create_app, routes
from stego_web.services.current_protocol import (
    CurrentProtocolService,
    infer_payload_claim,
)


PASSWORD = "test-password"


_STORAGE_SPACE_PATCH = patch(
    "stego.storage.shutil.disk_usage",
    return_value=SimpleNamespace(free=16 * 1024**3),
)


def setUpModule() -> None:
    """Give disk-space checks a deterministic default for test fixtures."""
    _STORAGE_SPACE_PATCH.start()


def tearDownModule() -> None:
    """Restore the real disk-space query after this module's tests."""
    _STORAGE_SPACE_PATCH.stop()


def sample_png() -> bytes:
    """Return a strict RGB PNG with enough carrier units for protocol v3."""
    output = io.BytesIO()
    Image.new("RGB", (96, 96), (46, 112, 99)).save(output, format="PNG")
    return output.getvalue()


def sample_16bit_png() -> bytes:
    """Return an RGB 16-bit PNG written with the PyAV PNG encoder."""
    with tempfile.TemporaryDirectory() as directory_name:
        path = Path(directory_name) / "cover.png"
        pixels = np.arange(96 * 96 * 3, dtype=np.uint16).reshape((96, 96, 3))
        container = av.open(str(path), mode="w", format="image2pipe")
        try:
            stream = container.add_stream("png")
            stream.width = 96
            stream.height = 96
            stream.pix_fmt = "rgb48be"
            frame = av.VideoFrame.from_ndarray(pixels, format="rgb48be")
            for packet in (*stream.encode(frame), *stream.encode(None)):
                container.mux(packet)
        finally:
            container.close()
        return path.read_bytes()


def sample_rgba_png() -> tuple[bytes, np.ndarray]:
    """Return an RGBA PNG and a copy of its expected alpha channel."""
    pixels = np.zeros((96, 96, 4), dtype=np.uint8)
    pixels[:, :, :3] = (46, 112, 99)
    pixels[:, :, 3] = 255
    pixels[:, :8, 3] = 0
    pixels[:, -8:, 3] = 0
    pixels[40:56, :, 3] = 128
    alpha = pixels[:, :, 3].copy()
    output = io.BytesIO()
    Image.fromarray(pixels, mode="RGBA").save(output, format="PNG")
    return output.getvalue(), alpha


def sample_jpeg() -> bytes:
    """Return a small RGB JPEG with enough pixels for a protocol-v3 packet."""
    pixels = np.zeros((96, 96, 3), dtype=np.uint8)
    pixels[:, :, 0] = np.arange(96, dtype=np.uint8)[None, :]
    pixels[:, :, 1] = np.arange(96, dtype=np.uint8)[:, None]
    output = io.BytesIO()
    Image.fromarray(pixels).save(output, format="JPEG", quality=88)
    return output.getvalue()


def sample_mp3() -> bytes:
    """Return a short mono MP3 with enough decoded samples for protocol v3."""
    with tempfile.TemporaryDirectory() as directory_name:
        path = Path(directory_name) / "cover.mp3"
        with av.open(str(path), mode="w", format="mp3") as output:
            stream = output.add_stream("libmp3lame", rate=48_000)
            stream.layout = "mono"
            stream.codec_context.format = av.AudioFormat("s16p")
            values = np.full((1, 12_000), 1400, dtype=np.int16)
            frame = av.AudioFrame.from_ndarray(values, format="s16p", layout="mono")
            frame.sample_rate = 48_000
            frame.pts = 0
            frame.time_base = Fraction(1, 48_000)
            for packet in (*stream.encode(frame), *stream.encode(None)):
                output.mux(packet)
        return path.read_bytes()


def sample_mp4_with_video(audio_streams: int = 0) -> bytes:
    """Return a tiny MP4 with one video stream and the requested audio tracks."""
    with tempfile.TemporaryDirectory() as directory_name:
        path = Path(directory_name) / "movie.mp4"
        with av.open(str(path), mode="w", format="mp4") as output:
            video = output.add_stream("mpeg4", rate=12)
            video.width = 64
            video.height = 64
            video.pix_fmt = "yuv420p"
            audio = [
                output.add_stream("aac", rate=48_000) for _ in range(audio_streams)
            ]
            for stream in audio:
                stream.layout = "mono"
            for index in range(24):
                pixels = np.full((64, 64, 3), index * 7, dtype=np.uint8)
                frame = av.VideoFrame.from_ndarray(pixels, format="rgb24")
                frame.pts = index
                frame.time_base = Fraction(1, 12)
                for packet in video.encode(frame):
                    output.mux(packet)
                if index % 3 == 0:
                    for stream in audio:
                        samples = np.full((1, 12_000), 300, dtype=np.int16)
                        audio_frame = av.AudioFrame.from_ndarray(
                            samples, format="s16", layout="mono"
                        )
                        audio_frame.sample_rate = 48_000
                        audio_frame.pts = index * 4_000
                        audio_frame.time_base = Fraction(1, 48_000)
                        for packet in stream.encode(audio_frame):
                            output.mux(packet)
            for stream in [video, *audio]:
                for packet in stream.encode(None):
                    output.mux(packet)
        return path.read_bytes()


def sample_webm_with_video() -> bytes:
    """Return a tiny WebM video fixture using the installed VP8 encoder."""
    with tempfile.TemporaryDirectory() as directory_name:
        path = Path(directory_name) / "movie.webm"
        with av.open(str(path), mode="w", format="webm") as output:
            stream = output.add_stream("libvpx", rate=12)
            stream.width = 64
            stream.height = 64
            stream.pix_fmt = "yuv420p"
            stream.options = {"deadline": "realtime", "cpu-used": "8"}
            for index in range(24):
                pixels = np.full((64, 64, 3), index * 7, dtype=np.uint8)
                frame = av.VideoFrame.from_ndarray(pixels, format="rgb24")
                frame.pts = index
                frame.time_base = Fraction(1, 12)
                for packet in stream.encode(frame):
                    output.mux(packet)
            for packet in stream.encode(None):
                output.mux(packet)
        return path.read_bytes()


def sample_cmyk_jpeg() -> bytes:
    """Return a small CMYK JPEG source for the web refusal test."""
    output = io.BytesIO()
    Image.new("CMYK", (96, 96), (20, 30, 40, 50)).save(output, format="JPEG")
    return output.getvalue()


def sample_animated_gif() -> bytes:
    """Return a two-frame GIF source for the web refusal test."""
    output = io.BytesIO()
    first = Image.new("P", (96, 96), 0)
    palette = [255, 0, 0, 0, 255, 0] + [0, 0, 0] * 254
    first.putpalette(palette)
    second = Image.new("P", (96, 96), 1)
    second.putpalette(palette)
    first.save(output, format="GIF", save_all=True, append_images=[second], duration=40)
    return output.getvalue()


def sample_palette_png() -> bytes:
    """Return a palette PNG to test the strict web carrier boundary."""
    output = io.BytesIO()
    Image.new("P", (96, 96)).save(output, format="PNG")
    return output.getvalue()


def oversized_rgb_png() -> bytes:
    """Build a 66-byte RGB PNG above the decoded-byte cap."""
    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)

    header = struct.pack(">IIBBBBB", 20_000, 20_000, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"x"))
        + chunk(b"IEND", b"")
    )


def sample_wav() -> bytes:
    """Return a mono 16-bit PCM WAV with enough samples for protocol v3."""
    output = io.BytesIO()
    with wave.open(output, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(8000)
        wav_file.writeframes(b"\x00\x00" * 8000)
    return output.getvalue()


def private_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a test private key with the shared test password."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSWORD.encode("utf-8")),
    )


def unencrypted_private_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a test private key without encryption."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize a test public key."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class WebApplicationTests(unittest.TestCase):
    """Exercise the changed sender/receiver web contract end to end."""

    def setUp(self) -> None:
        """Create an isolated app and independent sender/receiver key pairs."""
        self.output_temp = tempfile.TemporaryDirectory(prefix="inf2005-test-output-")
        self.payload_temp = tempfile.TemporaryDirectory(prefix="inf2005-test-payload-")
        self.work_temp = tempfile.TemporaryDirectory(prefix="inf2005-test-work-")
        self.addCleanup(self.output_temp.cleanup)
        self.addCleanup(self.payload_temp.cleanup)
        self.addCleanup(self.work_temp.cleanup)
        self.output_dir = Path(self.output_temp.name)
        self.payload_dir = Path(self.payload_temp.name)
        self.work_dir = Path(self.work_temp.name)
        self.client = create_app(
            {
                "TESTING": True,
                "STEGO_OUTPUT_DIR": self.output_dir,
                "PAYLOAD_OUTPUT_DIR": self.payload_dir,
                "STEGO_WORK_DIR": self.work_dir,
            }
        ).test_client()
        self.sender_private, self.sender_public = generate_rsa_keypair()
        self.receiver_private, self.receiver_public = generate_rsa_keypair()
        self.sender_private_pem = private_pem(self.sender_private)
        self.sender_public_pem = public_pem(self.sender_public)
        self.receiver_private_pem = private_pem(self.receiver_private)
        self.receiver_public_pem = public_pem(self.receiver_public)

    def encode(
        self,
        cover: bytes,
        filename: str,
        lsb_bits: int = 1,
        message: str = "authenticated message",
        payload: tuple[bytes, str] | None = None,
        payload_mime: str = "",
        payload_name: str = "",
        start_unit: int = 2048,
        sender_private_key_pem: bytes | None = None,
        sender_key_password: str = PASSWORD,
    ) -> object:
        """Post one valid encoding request and return its Flask response."""
        data: dict[str, object] = {
            "cover": (io.BytesIO(cover), filename),
            "sender_private_key": (
                io.BytesIO(
                    self.sender_private_pem
                    if sender_private_key_pem is None
                    else sender_private_key_pem
                ),
                "sender-private.pem",
            ),
            "sender_key_password": sender_key_password,
            "receiver_public_key": (
                io.BytesIO(self.receiver_public_pem),
                "receiver-public.pem",
            ),
            "team_id": "P1-4",
            "sender": "Test User",
            "secret_message": message,
            "metadata": "project=verification;sequence=1",
            "start_unit": str(start_unit),
            "lsb_bits": str(lsb_bits),
        }
        if payload is not None:
            data["secret_message"] = ""
            data["payload_file"] = (io.BytesIO(payload[0]), payload[1])
        if payload_mime:
            data["payload_mime"] = payload_mime
        if payload_name:
            data["payload_name"] = payload_name
        response = self.client.post(
            "/encode", data=data, content_type="multipart/form-data"
        )
        self.assertFalse(
            any(path.name.startswith(".stego-staging-") for path in self.output_dir.iterdir())
        )
        return response

    def capacity_request(
        self,
        cover: bytes,
        filename: str,
        message: str | None = "authenticated message",
        file_description: tuple[int, str, str] | None = None,
    ) -> object:
        """Post one valid capacity request with the encode metadata claims."""
        data: dict[str, object] = {
            "cover": (io.BytesIO(cover), filename),
            "team_id": "P1-4",
            "sender": "Test User",
            "metadata": "project=verification;sequence=1",
        }
        if file_description is None:
            if message is not None:
                data["secret_message"] = message
        else:
            data["payload_size"] = str(file_description[0])
            data["payload_filename"] = file_description[1]
            data["payload_type"] = file_description[2]
        return self.client.post(
            "/capacity", data=data, content_type="multipart/form-data"
        )

    def download_stego(self, encoded: dict[str, object]) -> bytes:
        """Fetch the carrier bytes from the API's download URL."""
        response = self.client.get(str(encoded["stego_url"]))
        body = response.get_data()
        response.close()
        self.assertEqual(response.status_code, 200, body[:200].decode("utf-8", "replace"))
        return body

    def decode(
        self,
        encoded: dict[str, object],
        filename: str,
        sender_public: bytes | None = None,
        receiver_private: bytes | None = None,
        receiver_key_password: str = PASSWORD,
    ) -> object:
        """Download one encoded file, then post it for verification."""
        return self.decode_bytes(
            self.download_stego(encoded),
            filename,
            sender_public,
            receiver_private,
            receiver_key_password,
        )

    def decode_bytes(
        self,
        stego_bytes: bytes,
        filename: str,
        sender_public: bytes | None = None,
        receiver_private: bytes | None = None,
        receiver_key_password: str = PASSWORD,
    ) -> object:
        """Post carrier bytes with independently selectable verification keys."""
        response = self.client.post(
            "/decode",
            data={
                "stego": (io.BytesIO(stego_bytes), filename),
                "sender_public_key": (
                    io.BytesIO(sender_public or self.sender_public_pem),
                    "sender-public.pem",
                ),
                "receiver_private_key": (
                    io.BytesIO(
                        self.receiver_private_pem
                        if receiver_private is None
                        else receiver_private
                    ),
                    "receiver-private.pem",
                ),
                "receiver_key_password": receiver_key_password,
            },
            content_type="multipart/form-data",
        )
        self.assertFalse(
            any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir())
        )
        return response

    def get_payload(self, payload: dict[str, object]) -> object:
        """Fetch one payload by the URL returned in an Authentic report."""
        response = self.client.get(str(payload["payload_url"]))
        body = response.get_data()
        self.assertEqual(response.status_code, 200, body[:200])
        response.close()
        return response

    def assert_no_recovered_payloads(self) -> None:
        """Check that no payload or sidecar was stored after failure."""
        self.assertEqual(list(self.payload_dir.iterdir()), [])

    def test_index_has_six_encode_steps_without_integrity(self) -> None:
        """The encode page has six markers and no placeholder integrity step."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.count(b'data-step-marker="'), 6)
        self.assertNotIn(b"<small>Integrity</small>", response.data)
        self.assertIn(b'aria-valuemax="6"', response.data)

    def test_index_loads_capacity_statuses_and_script_before_app(self) -> None:
        """The accessible capacity statuses exist and helpers load before the wizard."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="capacity-status"', response.data)
        self.assertIn(b'id="layout-capacity-status"', response.data)
        self.assertIn(b'role="status" aria-live="polite"', response.data)
        capacity_script = response.data.index(b"/static/capacity.js")
        app_script = response.data.index(b"/static/app.js")
        self.assertLess(capacity_script, app_script)

    def test_index_uses_current_protocol_inputs_and_retains_layout(self) -> None:
        """Encode and verify have separate pages with the current inputs."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Encode", response.data)
        self.assertNotIn(b"Decode and verify media", response.data)
        self.assertIn(b"LAYER / 01", response.data)
        self.assertIn(b"LAYER / 04", response.data)
        self.assertIn(b"feature-motion.js", response.data)
        self.assertIn(b"sender_private_key", response.data)
        self.assertIn(b"receiver_public_key", response.data)
        self.assertNotIn(b'name="receiver_private_key"', response.data)
        self.assertIn(b"payload_file", response.data)
        self.assertIn(b'id="payload-mime" name="payload_mime" readonly aria-readonly="true"', response.data)
        self.assertIn(b'id="payload-name" name="payload_name" readonly aria-readonly="true"', response.data)
        self.assertIn(b"Generated automatically from the payload", response.data)
        self.assertIn(b"Use a supported image, audio, or video file", response.data)
        self.assertIn(b"lossless PNG, WAV, or MKV", response.data)
        self.assertIn(b"accept=\"image/*,audio/*,video/*,.png,.jpg,.jpeg,.webp,.avif,.bmp,.tif,.tiff,.gif,.wav,.mp3,.aac,.m4a,.flac,.ogg,.oga,.opus,.mp4,.mov,.mkv,.webm,.avi\" required", response.data)
        self.assertIn(b'href="/verify"', response.data)
        self.assertIn(b"PNG output", response.data)
        self.assertIn(b"WAV output", response.data)
        self.assertIn(b"protocol v3", response.data)
        self.assertNotIn(b"start_secret", response.data)
        self.assertNotIn(b"original_cover", response.data)
        self.assertIn(b"gsap@3.15", response.data)
        self.assertNotIn(b'id="decode-form"', response.data)
        verify_page = self.client.get("/verify")
        self.assertEqual(verify_page.status_code, 200)
        self.assertIn(b"Decode and verify media", verify_page.data)
        self.assertIn(b'id="decode-form"', verify_page.data)
        self.assertIn(b'name="receiver_private_key"', verify_page.data)
        self.assertNotIn(b'id="encode-form"', verify_page.data)
        self.assertNotIn(b'name="sender_private_key"', verify_page.data)
        self.assertIn(b'accept=".png,.wav,.mkv,image/png,audio/wav,video/x-matroska" required', verify_page.data)
        app_js = self.client.get("/static/app.js")
        self.assertIn(b"source was converted to a lossless", app_js.data)
        self.assertIn(
            b"Allowed, but not advised: long or 4K videos make very large MKV files "
            b"and can take hours. Use a short clip for demonstrations.",
            app_js.data,
        )
        self.assertIn(b"coverMeta.textContent = DEFAULT_COVER_META", app_js.data)
        self.assertIn(b"coverMeta.textContent = isVideo", app_js.data)
        self.assertNotIn(b"coverMeta.innerHTML", app_js.data)
        app_js.close()

    def test_capacity_png_finds_latest_start_for_one_and_eight_lsb(self) -> None:
        """The reported boundary agrees with successful and failed encodes."""
        cover = sample_png()
        message = "capacity boundary proof"
        response = self.capacity_request(cover, "cover.png", message=message)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertEqual(result["media_type"], "image")
        self.assertEqual(result["source_format"], "png")
        self.assertEqual(result["total_units"], 96 * 96 * 3)
        self.assertEqual(result["payload_bytes"], len(message.encode("utf-8")))
        self.assertEqual(result["bootstrap_span"], bootstrap_span(self.receiver_public))
        self.assertEqual(len(result["lsb_results"]), 8)
        self.assertEqual(
            [item["lsb_bits"] for item in result["lsb_results"]], list(range(1, 9))
        )
        for lsb_bits in (1, 8):
            with self.subTest(lsb_bits=lsb_bits):
                item = next(
                    entry for entry in result["lsb_results"]
                    if entry["lsb_bits"] == lsb_bits
                )
                minimum_capacity = self.encode(
                    cover,
                    "cover.png",
                    lsb_bits=lsb_bits,
                    message=message,
                    start_unit=result["bootstrap_span"],
                )
                self.assertEqual(minimum_capacity.status_code, 200)
                self.assertEqual(
                    item["max_payload_bytes_at_min_start"],
                    minimum_capacity.get_json()["capacity_bytes"],
                )
                latest_start = item["max_start_unit"]
                self.assertIsInstance(latest_start, int)
                encoded = self.encode(
                    cover,
                    "cover.png",
                    lsb_bits=lsb_bits,
                    message=message,
                    start_unit=latest_start,
                )
                self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
                too_late = self.encode(
                    cover,
                    "cover.png",
                    lsb_bits=lsb_bits,
                    message=message,
                    start_unit=latest_start + 1,
                )
                self.assertEqual(too_late.status_code, 400)
                self.assertIn("user payload exceeds capacity", too_late.get_json()["error"])

    def test_capacity_reports_wav_units_and_eight_lsb_results(self) -> None:
        """WAV capacity uses the adapter's interleaved sample-unit count."""
        response = self.capacity_request(sample_wav(), "cover.wav")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertEqual(result["media_type"], "audio")
        self.assertEqual(result["source_format"], "wav")
        self.assertEqual(result["total_units"], 8000)
        self.assertEqual(len(result["lsb_results"]), 8)
        self.assertTrue(
            all(
                isinstance(item["max_payload_bytes_at_min_start"], int)
                for item in result["lsb_results"]
            )
        )

    def test_capacity_oversized_payload_has_no_fitting_start(self) -> None:
        """A payload larger than the cover has no valid start for any LSB count."""
        response = self.capacity_request(
            sample_png(),
            "cover.png",
            message=None,
            file_description=(10_000_000, "large.bin", "application/octet-stream"),
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertEqual(result["payload_bytes"], 10_000_000)
        self.assertTrue(
            all(item["max_start_unit"] is None for item in result["lsb_results"])
        )

    def test_capacity_empty_file_type_matches_encode_mimetype_claim(self) -> None:
        """The browser's octet-stream fallback produces the encode file claim."""
        cover = sample_png()
        payload = b"untyped browser file"
        capacity_response = self.capacity_request(
            cover,
            "cover.png",
            message=None,
            file_description=(len(payload), "opaque.bin", "application/octet-stream"),
        )
        encode_response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(cover), "cover.png"),
                "sender_private_key": (
                    io.BytesIO(self.sender_private_pem),
                    "sender-private.pem",
                ),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem),
                    "receiver-public.pem",
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "",
                "metadata": "project=verification;sequence=1",
                "start_unit": "2048",
                "lsb_bits": "1",
                "payload_file": (
                    io.BytesIO(payload),
                    "opaque.bin",
                    "application/octet-stream",
                ),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(
            capacity_response.status_code,
            200,
            capacity_response.get_data(as_text=True),
        )
        self.assertEqual(encode_response.status_code, 200, encode_response.get_data(as_text=True))
        encoded_payload = encode_response.get_json()["payload"]
        self.assertEqual(encoded_payload["mime"], "application/octet-stream")
        metadata = encoded_payload["metadata"].encode("utf-8")
        self.assertEqual(
            capacity_response.get_json()["record_overhead"],
            serialized_record_length(MEDIA_ID_SIZE, 0, len(metadata)),
        )

    def test_capacity_file_description_uses_encode_metadata_overhead(self) -> None:
        """A described file's record overhead matches the encode metadata claim."""
        cover = sample_png()
        payload = b"typed file payload"
        capacity_response = self.capacity_request(
            cover,
            "cover.png",
            message=None,
            file_description=(len(payload), "note.txt", "text/plain"),
        )
        self.assertEqual(
            capacity_response.status_code,
            200,
            capacity_response.get_data(as_text=True),
        )
        encoded_response = self.encode(
            cover, "cover.png", payload=(payload, "note.txt")
        )
        self.assertEqual(encoded_response.status_code, 200, encoded_response.get_data(as_text=True))
        encoded = encoded_response.get_json()
        metadata_bytes = encoded["payload"]["metadata"].encode("utf-8")
        self.assertEqual(
            capacity_response.get_json()["record_overhead"],
            serialized_record_length(MEDIA_ID_SIZE, 0, len(metadata_bytes)),
        )
        self.assertEqual(capacity_response.get_json()["payload_bytes"], len(payload))

    def test_capacity_unsupported_cover_uses_encode_error(self) -> None:
        """Unsupported cover content returns the same HTTP 400 message as encode."""
        cover = sample_cmyk_jpeg()
        encoded = self.encode(cover, "cover.jpg")
        capacity = self.capacity_request(cover, "cover.jpg")
        self.assertEqual(encoded.status_code, 400)
        self.assertEqual(capacity.status_code, 400)
        self.assertEqual(capacity.get_json()["error"], encoded.get_json()["error"])

    def test_capacity_leaves_no_temporary_or_output_files(self) -> None:
        """Converted snapshots and carrier copies are removed after the request."""
        response = self.capacity_request(sample_jpeg(), "cover.jpg")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(list(self.work_dir.iterdir()), [])
        self.assertEqual(list(self.output_dir.iterdir()), [])
        self.assertEqual(list(self.payload_dir.iterdir()), [])

    def test_capacity_video_reports_decoded_carrier_units(self) -> None:
        """The video route counts decoded carrier units without writing output."""
        response = self.capacity_request(sample_mp4_with_video(), "clip.mp4")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertEqual(result["media_type"], "video")
        self.assertEqual(result["source_format"], "mp4")
        self.assertGreater(result["total_units"], 0)
        self.assertEqual(list(self.output_dir.iterdir()), [])
        self.assertEqual(list(self.payload_dir.iterdir()), [])

    def test_capacity_rejects_duplicate_message_fields(self) -> None:
        """Duplicate payload descriptions use the standard form-field error."""
        data = MultiDict(
            [
                ("cover", (io.BytesIO(sample_png()), "cover.png")),
                ("team_id", "P1-4"),
                ("sender", "Test User"),
                ("secret_message", "first"),
                ("secret_message", "second"),
            ]
        )
        response = self.client.post(
            "/capacity", data=data, content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"], "provide exactly one value: secret_message"
        )

    def test_capacity_request_guard_rejects_upload_before_body_parsing(self) -> None:
        """The shared free-space guard applies to capacity multipart bodies."""
        with patch("stego.storage.shutil.disk_usage") as disk_usage:
            disk_usage.return_value.free = DISK_SPACE_RESERVE_BYTES + 10
            response = self.client.post(
                "/capacity",
                data={"cover": (io.BytesIO(b"x" * 1024), "cover.png")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"],
            "upload is larger than the free disk space allows",
        )
        disk_usage.assert_called_once_with(self.work_dir)

    def test_capacity_cover_copy_space_failure_returns_413(self) -> None:
        """Refuse the route's cover copy when it would use the disk reserve."""
        with patch(
            "stego.storage.shutil.disk_usage",
            side_effect=(
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=DISK_SPACE_RESERVE_BYTES + 1),
            ),
        ):
            response = self.capacity_request(sample_png(), "cover.png")
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"],
            "insufficient free disk space for the uploaded file",
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])
        self.assertEqual(list(self.work_dir.iterdir()), [])

    def test_16bit_png_cover_works_through_web_routes(self) -> None:
        """The web routes encode and verify a native 16-bit PNG cover."""
        encoded_response = self.encode(sample_16bit_png(), "cover-16.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        decoded_response = self.decode(encoded_response.get_json(), "stego-16.png")
        self.assertEqual(
            decoded_response.status_code, 200, decoded_response.get_data(as_text=True)
        )
        report = decoded_response.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(
            self.get_payload(report["payload"]).get_data(), b"authenticated message"
        )

    def test_png_message_round_trip_recovers_geometry_and_metadata(self) -> None:
        """PNG encoding and receiver-gated decoding expose authenticated data."""
        encoded_response = self.encode(sample_png(), "cover.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["protocol_version"], PROTOCOL_VERSION)
        self.assertEqual(encoded["protocol_version"], 3)
        self.assertEqual(encoded["bootstrap_span"], 2048)
        self.assertFalse(encoded["source_converted"])
        self.assertEqual(encoded["source_format"], "png")
        self.assertEqual(encoded["payload"]["mime"], "text/plain")
        self.assertEqual(encoded["payload"]["name"], "message.txt")
        decoded = self.decode(encoded, "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["frame_version"], PROTOCOL_VERSION)
        self.assertEqual(report["frame_version"], 3)
        self.assertEqual(report["start_location"], 2048)
        self.assertEqual(report["lsb_bits"], 3)
        self.assertEqual(report["payload"]["metadata"]["team"], "P1-4")
        self.assertEqual(report["payload"]["metadata"]["mime"], "text/plain")
        self.assertEqual(report["payload"]["metadata"]["name"], "message.txt")
        self.assertNotIn("user_payload_base64", report["payload"])
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.get_data(), b"authenticated message")
        self.assertEqual(payload_response.mimetype, "text/plain")
        self.assertEqual(
            payload_response.headers["Content-Disposition"].split(";")[0], "inline"
        )
        self.assertEqual(payload_response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(payload_response.headers["Cache-Control"], "no-store")
        payload_id = str(report["payload"]["payload_url"]).rsplit("/", 1)[-1]
        sidecar = json.loads((self.payload_dir / f"{payload_id}.json").read_text())
        self.assertEqual(
            sidecar,
            {
                "download_name": "message.txt",
                "serve_mime": "text/plain",
                "preview_allowed": True,
            },
        )
        self.assertEqual(
            payload_response.headers["Content-Security-Policy"],
            "default-src 'none'; img-src 'self'; media-src 'self'; sandbox",
        )
        self.assertTrue(report["payload"]["preview_allowed"])
        second_response = self.get_payload(report["payload"])
        self.assertEqual(second_response.get_data(), b"authenticated message")
        self.assertEqual(len(list(self.payload_dir.glob("*.bin"))), 1)
        self.assertEqual(len(list(self.payload_dir.glob("*.json"))), 1)

    def test_png_payload_file_upload_round_trip(self) -> None:
        """PNG carrier uploads preserve an uploaded typed payload file."""
        payload = b"\x89PNG\r\n\x1a\nsmall uploaded PNG payload"
        with patch("stego.media.av.open", wraps=av.open) as av_open:
            encoded_response = self.encode(
                sample_png(),
                "cover.png",
                payload=(payload, "image.png"),
                payload_mime="application/pdf",
                payload_name="spoof.pdf",
            )
        input_opens = [
            call for call in av_open.call_args_list if call.kwargs.get("mode") == "r"
        ]
        self.assertEqual(len(input_opens), 1, "the uploaded PNG cover must be decoded once")
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        decoded = self.decode(encoded_response.get_json(), "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(encoded_response.get_json()["payload"]["mime"], "image/png")
        self.assertEqual(encoded_response.get_json()["payload"]["name"], "image.png")
        self.assertEqual(report["payload"]["metadata"]["mime"], "image/png")
        self.assertEqual(report["payload"]["metadata"]["name"], "image.png")
        self.assertTrue(report["payload"]["preview_allowed"])
        self.assertEqual(self.get_payload(report["payload"]).get_data(), payload)
        self.assertFalse(any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir()))

    def test_jpeg_cover_converts_once_and_verifies_through_web(self) -> None:
        """A JPEG upload becomes PNG once and retains its authenticated message."""
        with patch("stego.sources._decoded_image_frames", wraps=_decoded_image_frames) as decode:
            with patch("stego.sources._convert_image", wraps=_convert_image) as convert:
                encoded_response = self.encode(sample_jpeg(), "cover.jpeg", message="jpeg payload")
        self.assertEqual(decode.call_count, 1)
        self.assertEqual(encoded_response.status_code, 200, encoded_response.get_data(as_text=True))
        converted_input, snapshot = convert.call_args.args
        request_directory = Path(converted_input).parent
        source_directory = Path(snapshot).parent
        self.assertEqual(source_directory.parent, request_directory)
        self.assertTrue(source_directory.name.startswith(".stego-source-"))
        self.assertFalse(request_directory.exists())
        self.assertFalse(source_directory.exists())
        encoded = encoded_response.get_json()
        self.assertTrue(encoded["source_converted"])
        self.assertEqual(encoded["source_format"], "jpeg")
        self.assertEqual(encoded["filename"], "stego.png")
        self.assertEqual(Path(encoded["stego_url"]).suffix, ".png")
        self.assertEqual(list(self.output_dir.glob(".stego-source-*")), [])
        decoded = self.decode(encoded, "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(self.get_payload(report["payload"]).get_data(), b"jpeg payload")

    def test_mp3_cover_converts_to_wav_and_verifies_through_web(self) -> None:
        """An MP3 upload becomes WAV and retains its authenticated message."""
        with patch("stego.sources._decoded_audio_frames", wraps=_decoded_audio_frames) as decode:
            with patch("stego.sources._convert_audio", wraps=_convert_audio) as convert:
                encoded_response = self.encode(sample_mp3(), "cover.mp3", message="mp3 payload")
        self.assertEqual(decode.call_count, 1)
        converted_input, snapshot = convert.call_args.args
        request_directory = Path(converted_input).parent
        source_directory = Path(snapshot).parent
        self.assertEqual(source_directory.parent, request_directory)
        self.assertFalse(request_directory.exists())
        self.assertFalse(source_directory.exists())
        self.assertEqual(encoded_response.status_code, 200, encoded_response.get_data(as_text=True))
        encoded = encoded_response.get_json()
        self.assertTrue(encoded["source_converted"])
        self.assertEqual(encoded["source_format"], "mp3")
        self.assertEqual(encoded["filename"], "stego.wav")
        self.assertEqual(Path(encoded["stego_url"]).suffix, ".wav")
        self.assertEqual(list(self.output_dir.glob(".stego-source-*")), [])
        decoded = self.decode(encoded, "stego.wav")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(self.get_payload(report["payload"]).get_data(), b"mp3 payload")

    def test_lossless_audio_depth_refusal_returns_http_400(self) -> None:
        """Expose the source converter's lossless-depth refusal to the client."""
        with patch("stego.sources._audio_integer_width", return_value=20):
            response = self.encode(sample_mp3(), "cover.mp3")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "unsupported lossless audio sample depth: 20 bits",
        )

    def test_video_cover_with_audio_encodes_and_verifies(self) -> None:
        """Video with audio uses a Matroska output and recovers the exact payload."""
        payload = b"payload for video carrier"
        with patch("stego.video._MIN_FREE_BYTES", 0):
            response = self.encode(
                sample_mp4_with_video(audio_streams=1),
                "movie.mp4",
                payload=(payload, "exact.bin"),
            )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        encoded = response.get_json()
        self.assertEqual(encoded["media_type"], "video")
        self.assertTrue(encoded["source_converted"])
        self.assertEqual(encoded["source_format"], "mp4")
        self.assertEqual(encoded["filename"], "stego.mkv")
        self.assertEqual(encoded["mime_type"], "video/x-matroska")
        self.assertGreater(encoded["file_size"], 0)
        self.assertEqual(encoded["payload"]["name"], "exact.bin")
        download = self.client.get(encoded["stego_url"])
        self.assertEqual(download.mimetype, "video/x-matroska")
        self.assertTrue(download.headers["Content-Disposition"].startswith("attachment;"))
        download.close()
        report_response = self.decode(encoded, "received.mkv")
        self.assertEqual(report_response.status_code, 200)
        report = report_response.get_json()
        self.assertEqual(report["media_type"], "video")
        self.assertEqual(report["verdict"], "Authentic", report["message"])
        self.assertEqual(self.get_payload(report["payload"]).get_data(), payload)

    def test_webm_cover_source_format_uses_uploaded_container_name(self) -> None:
        """The matroska,webm demuxer reports the user's WebM container label."""
        with patch("stego.video._MIN_FREE_BYTES", 0):
            response = self.encode(sample_webm_with_video(), "movie.webm")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["source_format"], "webm")

    def test_video_cover_without_audio_encodes_and_verifies(self) -> None:
        """Video without audio still produces an authentic web carrier."""
        with patch("stego.video._MIN_FREE_BYTES", 0):
            response = self.encode(sample_mp4_with_video(), "movie.mp4")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        report = self.decode(response.get_json(), "received.mkv").get_json()
        self.assertEqual(report["verdict"], "Authentic", report["message"])
        self.assertEqual(self.get_payload(report["payload"]).get_data(), b"authenticated message")

    def test_web_video_pixel_change_is_tampered(self) -> None:
        """Changing one decoded video carrier LSB fails full-media verification."""
        with patch("stego.video._MIN_FREE_BYTES", 0):
            encoded_response = self.encode(sample_mp4_with_video(), "movie.mp4")
        self.assertEqual(encoded_response.status_code, 200, encoded_response.get_data(as_text=True))
        encoded = encoded_response.get_json()
        with tempfile.TemporaryDirectory(dir=self.work_dir) as directory_name:
            original_path = Path(directory_name) / "original.mkv"
            altered_path = Path(directory_name) / "altered.mkv"
            original_path.write_bytes(self.download_stego(encoded))
            carrier = VideoCarrier(original_path)
            try:
                def alter_last_unit(offset: int, units: np.ndarray) -> np.ndarray:
                    changed = units.copy()
                    final_unit = carrier.total_units - 1
                    if offset <= final_unit < offset + changed.size:
                        changed[final_unit - offset] ^= 1
                    return changed

                carrier.rewrite_to_path(altered_path, alter_last_unit)
            finally:
                carrier.close()
            report = self.decode_bytes(altered_path.read_bytes(), "changed.mkv").get_json()
        self.assertEqual(report["verdict"], "Tampered")

    def test_video_two_audio_streams_give_library_refusal(self) -> None:
        """The video backend refusal reaches the web client as HTTP 400."""
        with patch("stego.video._MIN_FREE_BYTES", 0):
            response = self.encode(sample_mp4_with_video(audio_streams=2), "movie.mp4")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "unsupported additional stream")
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_video_verify_input_accepts_mkv(self) -> None:
        """The verification upload control accepts the backend's MKV output."""
        response = self.client.get("/verify")
        self.assertIn(b'accept=".png,.wav,.mkv,image/png,audio/wav,video/x-matroska"', response.data)

    def test_cmyk_and_animated_image_sources_are_http_400(self) -> None:
        """Supported-family images with forbidden content use validation status."""
        cmyk = self.encode(sample_cmyk_jpeg(), "cmyk.jpg")
        self.assertEqual(cmyk.status_code, 400)
        self.assertEqual(cmyk.get_json()["error"], "CMYK images are not supported")
        animated = self.encode(sample_animated_gif(), "animated.gif")
        self.assertEqual(animated.status_code, 400)
        self.assertEqual(
            animated.get_json()["error"], "animated GIF images are not supported"
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_converted_source_snapshot_is_removed_after_encode_failure(self) -> None:
        """A converted snapshot under the request directory is removed on refusal."""
        with patch("stego.sources._convert_image", wraps=_convert_image) as convert:
            response = self.encode(
                sample_jpeg(), "cover.jpg",
                payload=(b"x" * (128 * 1024), "large.bin"),
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("user payload exceeds capacity", response.get_json()["error"])
        converted_input, snapshot = convert.call_args.args
        self.assertFalse(Path(converted_input).parent.exists())
        self.assertFalse(Path(snapshot).parent.exists())
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_rgba_png_web_round_trip_keeps_alpha_bytes(self) -> None:
        """The web flow encodes and verifies RGBA without changing alpha."""
        cover, expected_alpha = sample_rgba_png()
        encoded_response = self.encode(cover, "cover.png", lsb_bits=3)
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["protocol_version"], PROTOCOL_VERSION)
        stego_bytes = self.download_stego(encoded)
        with Image.open(io.BytesIO(stego_bytes)) as stego_image:
            self.assertEqual(stego_image.mode, "RGBA")
            stego_alpha = np.asarray(stego_image, dtype=np.uint8)[:, :, 3].copy()
        self.assertTrue(np.array_equal(stego_alpha, expected_alpha))

        decoded = self.decode_bytes(stego_bytes, "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["frame_version"], PROTOCOL_VERSION)

    def test_palette_png_converts_for_encode_but_stays_invalid_for_verify(self) -> None:
        """Palette PNG sources convert on encode; verification stays strict."""
        detail = "PNG must be RGB or RGBA; palette and grayscale images are not supported"
        encoded = self.encode(sample_palette_png(), "palette.png")
        self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
        self.assertTrue(encoded.get_json()["source_converted"])
        self.assertEqual(encoded.get_json()["source_format"], "png")
        encoded_decode = self.decode(encoded.get_json(), "stego.png")
        self.assertEqual(encoded_decode.status_code, 200)
        self.assertEqual(encoded_decode.get_json()["verdict"], "Authentic")

        decoded = self.decode_bytes(sample_palette_png(), "palette.png")
        self.assertEqual(decoded.status_code, 200)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertEqual(report["message"], detail)
        self.assertIsNone(report["frame_version"])

    def test_rgb_png_with_trns_colour_key_converts_to_rgba_for_encode(self) -> None:
        """A colour-key PNG is converted so the transparency becomes alpha."""
        output = io.BytesIO()
        Image.new("RGB", (96, 96), (46, 112, 99)).save(output, format="PNG", transparency=(0, 0, 0))
        response = self.encode(output.getvalue(), "keyed.png")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["source_converted"])
        decoded = self.decode(response.get_json(), "stego.png")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        self.assertEqual(decoded.get_json()["verdict"], "Authentic")

    def test_invalid_sender_key_is_rejected_after_family_detection(self) -> None:
        """The service identifies a supported source before key validation."""
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_palette_png()), "palette.png"),
                "sender_private_key": (io.BytesIO(b"not a private key"), "sender.pem"),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem),
                    "receiver.pem",
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "authenticated message",
                "metadata": "project=verification;sequence=1",
                "start_unit": "2048",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "sender private key could not be loaded with that password",
        )

    def test_oversized_png_errors_reach_encode_and_verify(self) -> None:
        """The fixed decoded-byte cap gives a clear encode error and verify report."""
        decoded_bytes = 20_000 * 20_000 * 3
        limit = _PNG_MAX_DECODED_BYTES
        detail = (
            "PNG decoded size exceeds configured limit: "
            f"{decoded_bytes} bytes > {limit} bytes"
        )
        png_bytes = oversized_rgb_png()
        self.assertEqual(len(png_bytes), 66)

        encoded = self.encode(png_bytes, "oversized.png")
        self.assertEqual(encoded.status_code, 400)
        self.assertTrue(encoded.is_json)
        self.assertEqual(
            encoded.get_json(),
            {"ok": False, "error": detail},
        )

        decoded = self.decode_bytes(png_bytes, "oversized.png")
        self.assertEqual(decoded.status_code, 200)
        self.assertTrue(decoded.is_json)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertEqual(report["message"], detail)

    def test_unexpected_route_errors_return_safe_json(self) -> None:
        """Unexpected failures return generic JSON; HTTP errors keep their status."""
        self.client.application.config["PROPAGATE_EXCEPTIONS"] = False
        with patch(
            "stego_web.routes.protocol_service.encode",
            side_effect=RuntimeError("secret /home/path"),
        ):
            response = self.encode(sample_png(), "cover.png")
        self.assertEqual(response.status_code, 500)
        self.assertTrue(response.is_json)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "verdict": "Cannot Verify", "error": "internal server error"},
        )
        body = response.get_data(as_text=True)
        self.assertNotIn("secret", body)
        self.assertNotIn("/home", body)

        missing = self.client.get("/not-a-route")
        self.assertEqual(missing.status_code, 404)

    def test_wav_binary_payload_round_trip(self) -> None:
        """WAV carriers preserve an arbitrary binary payload and type claim."""
        payload = b"RIFF\x04\x00\x00\x00WAVE"
        encoded_response = self.encode(
            sample_wav(),
            "cover.wav",
            lsb_bits=2,
            payload=(payload, "clip.wav"),
        )
        self.assertEqual(
            encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
        )
        self.assertFalse(encoded_response.get_json()["source_converted"])
        self.assertEqual(encoded_response.get_json()["source_format"], "wav")
        decoded = self.decode(encoded_response.get_json(), "stego.wav")
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Authentic")
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.get_data(), payload)
        self.assertEqual(payload_response.mimetype, "audio/wav")
        self.assertEqual(report["payload"]["declared_mime"], "audio/wav")
        self.assertNotIn("user_payload_base64", report["payload"])

    def test_png_supports_every_lsb_count(self) -> None:
        """The retained 1-8 control maps exactly to protocol LSB counts."""
        for lsb_bits in range(1, 9):
            with self.subTest(lsb_bits=lsb_bits):
                encoded = self.encode(sample_png(), "cover.png", lsb_bits=lsb_bits)
                self.assertEqual(encoded.status_code, 200, encoded.get_data(as_text=True))
                report = self.decode(encoded.get_json(), "stego.png").get_json()
                self.assertEqual(report["verdict"], "Authentic")
                self.assertEqual(report["lsb_bits"], lsb_bits)

    def test_encode_message_cover_copy_space_failure_returns_413(self) -> None:
        """Refuse the carrier copy when it would use the disk reserve."""
        with patch(
            "stego.storage.shutil.disk_usage",
            side_effect=(
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=DISK_SPACE_RESERVE_BYTES + 1),
            ),
        ):
            response = self.encode(sample_png(), "cover.png", message="message")
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"],
            "insufficient free disk space for the uploaded file",
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])
        self.assertEqual(list(self.work_dir.iterdir()), [])

    def test_encode_payload_file_copy_space_failure_returns_413(self) -> None:
        """Refuse the payload-file copy before copying the cover upload."""
        cover = sample_png()
        payload = b"x" * (len(cover) + 1024)
        call_count = 0

        def disk_usage(_path: str | bytes | os.PathLike[str]) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            free = (
                16 * 1024**3
                if call_count == 1
                else DISK_SPACE_RESERVE_BYTES + len(cover)
            )
            return SimpleNamespace(free=free)

        with patch("stego.storage.shutil.disk_usage", side_effect=disk_usage):
            response = self.encode(
                cover, "cover.png", message="", payload=(payload, "payload.bin")
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"],
            "insufficient free disk space for the uploaded file",
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])
        self.assertEqual(list(self.work_dir.iterdir()), [])

    def test_decode_stego_copy_space_failure_returns_413(self) -> None:
        """Refuse the stego upload copy and leave no recovered files."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        with patch(
            "stego.storage.shutil.disk_usage",
            side_effect=(
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=DISK_SPACE_RESERVE_BYTES + 1),
            ),
        ):
            response = self.decode_bytes(stego_bytes, "stego.png")
        self.assertEqual(response.status_code, 413)
        report = response.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertEqual(
            report["error"],
            "insufficient free disk space for the uploaded file",
        )
        self.assert_no_recovered_payloads()
        self.assertEqual(list(self.work_dir.iterdir()), [])

    def test_decode_upload_copy_check_exact_disk_space_boundary(self) -> None:
        """Accept exact copy space and refuse the same upload one byte below."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        with patch(
            "stego.storage.shutil.disk_usage",
            side_effect=(
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=DISK_SPACE_RESERVE_BYTES + len(stego_bytes)),
                SimpleNamespace(free=16 * 1024**3),
            ),
        ):
            accepted = self.decode_bytes(stego_bytes, "stego.png")
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.get_json()["verdict"], "Authentic")
        for path in self.payload_dir.iterdir():
            path.unlink()

        with patch(
            "stego.storage.shutil.disk_usage",
            side_effect=(
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=DISK_SPACE_RESERVE_BYTES + len(stego_bytes) - 1),
            ),
        ):
            refused = self.decode_bytes(stego_bytes, "stego.png")
        self.assertEqual(refused.status_code, 413)
        self.assertEqual(refused.get_json()["verdict"], "Cannot Verify")
        self.assert_no_recovered_payloads()

    def test_decode_staging_space_failure_returns_cannot_verify(self) -> None:
        """The route keeps low decode-staging space as an HTTP 200 verdict."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        with patch(
            "stego.storage.shutil.disk_usage",
            side_effect=(
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=16 * 1024**3),
                SimpleNamespace(free=DISK_SPACE_RESERVE_BYTES + 1),
            ),
        ):
            response = self.decode_bytes(stego_bytes, "stego.png")
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertIn("insufficient free disk space", report["message"])
        self.assert_no_recovered_payloads()

    def test_bad_verify_key_returns_cannot_verify_report(self) -> None:
        """An unreadable key remains a Cannot Verify report with file size."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        response = self.decode_bytes(
            stego_bytes, "stego.png", sender_public=b"not an RSA key"
        )
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["verdict"], "Cannot Verify")
        self.assertIsNone(report["frame_version"])
        self.assertEqual(report["file_size"], len(stego_bytes))

    def test_wrong_receiver_key_is_payload_missing(self) -> None:
        """A non-recipient cannot open the RSA-OAEP bootstrap."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        wrong_private, _ = generate_rsa_keypair()
        decoded = self.decode(
            encoded, "stego.png", receiver_private=private_pem(wrong_private)
        )
        self.assertEqual(decoded.status_code, 422)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Payload Missing")
        self.assertIsNone(report["payload"])
        self.assertNotIn("payload_url", report)
        self.assert_no_recovered_payloads()

    def test_wrong_sender_key_is_signature_invalid(self) -> None:
        """The receiver rejects a packet under an unrelated sender identity."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        _, wrong_public = generate_rsa_keypair()
        decoded = self.decode(
            encoded, "stego.png", sender_public=public_pem(wrong_public)
        )
        self.assertEqual(decoded.status_code, 200)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Signature Invalid")
        self.assertIsNone(report["payload"])
        self.assertNotIn("payload_url", report)
        self.assert_no_recovered_payloads()

    def test_changed_preserved_image_bit_is_tampered(self) -> None:
        """A carrier change outside the packet footprint fails the masked hash."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        raw = self.download_stego(encoded)
        with Image.open(io.BytesIO(raw)) as image:
            array = np.array(image, dtype=np.uint8, copy=True)
        array.reshape(-1)[-1] ^= np.uint8(0x80)
        changed_output = io.BytesIO()
        Image.fromarray(array, mode="RGB").save(changed_output, format="PNG")
        decoded = self.decode_bytes(changed_output.getvalue(), "changed.png")
        self.assertEqual(decoded.status_code, 200)
        report = decoded.get_json()
        self.assertEqual(report["verdict"], "Tampered")
        self.assertIsNone(report["payload"])
        self.assertNotIn("payload_url", report)
        self.assert_no_recovered_payloads()

    def rewrite_png_bootstrap(
        self,
        stego_bytes: bytes,
        version: int | None = None,
        start_unit: int | None = None,
        flip_session_key: bool = False,
    ) -> bytes:
        """Reseal the receiver bootstrap of an RGB PNG with changed fields."""
        with Image.open(io.BytesIO(stego_bytes)) as image:
            pixels = np.array(image, dtype=np.uint8, copy=True)
        units = pixels.reshape(-1)
        span = bootstrap_span(self.receiver_private)
        envelope = bit_sequence_to_bytes(
            read_lsb_bits(units[:span], span, BOOTSTRAP_LSB_COUNT)
        )
        fields = parse_bootstrap(open_with_private_key(envelope, self.receiver_private))
        session_key = fields.session_key
        if flip_session_key:
            session_key = bytes((session_key[0] ^ 1,)) + session_key[1:]
        plaintext = (
            struct.pack(
                ">BB",
                fields.version if version is None else version,
                fields.lsb_count,
            )
            + (fields.start_unit if start_unit is None else start_unit).to_bytes(8, "big")
            + fields.ciphertext_length.to_bytes(8, "big")
            + session_key
            + fields.aead_nonce
        )
        sealed = seal_to_public_key(plaintext, self.receiver_public)
        units[:span] = write_lsb_bits(
            units[:span], bytes_to_bit_sequence(sealed), BOOTSTRAP_LSB_COUNT
        )
        output = io.BytesIO()
        Image.fromarray(pixels, mode="RGB").save(output, format="PNG")
        return output.getvalue()

    def test_verdict_reports_keep_recovered_fields_and_leave_no_staging(self) -> None:
        """Each verdict reports the fields that verification reached and recovered."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        stego_bytes = self.download_stego(encoded)
        with Image.open(io.BytesIO(stego_bytes)) as image:
            tampered_pixels = np.array(image, dtype=np.uint8, copy=True)
        tampered_pixels.reshape(-1)[-1] ^= np.uint8(0x80)
        tampered_output = io.BytesIO()
        Image.fromarray(tampered_pixels, mode="RGB").save(tampered_output, format="PNG")
        wrong_receiver, _ = generate_rsa_keypair()
        _, wrong_sender = generate_rsa_keypair()
        span = bootstrap_span(self.receiver_private)
        sender_fingerprint = display_rsa_public_key_fingerprint(self.sender_public)
        # Each row: carrier, sender PEM, receiver PEM, verdict, HTTP status,
        # frame_version, start_location, lsb_bits, preserved bits expected.
        cases = (
            ("Authentic", stego_bytes, None, None, 200, 3, 2048, 1, True),
            (
                "Signature Invalid", stego_bytes, public_pem(wrong_sender),
                None, 200, 3, 2048, 1, True,
            ),
            (
                "Payload Missing", stego_bytes, None,
                private_pem(wrong_receiver), 422, None, None, None, False,
            ),
            (
                "Tampered", tampered_output.getvalue(), None,
                None, 200, 3, 2048, 1, True,
            ),
            (
                "Cannot Decrypt",
                self.rewrite_png_bootstrap(stego_bytes, flip_session_key=True),
                None, None, 200, 3, 2048, 1, True,
            ),
            (
                "Wrong Start Location",
                self.rewrite_png_bootstrap(stego_bytes, start_unit=span - 1),
                None, None, 200, 3, span - 1, 1, False,
            ),
            (
                "Cannot Verify",
                self.rewrite_png_bootstrap(stego_bytes, version=2),
                None, None, 200, 2, None, None, False,
            ),
        )
        for (
            verdict, carrier_bytes, sender_public, receiver_private, status,
            frame_version, start_location, lsb_bits, has_preserved,
        ) in cases:
            with self.subTest(verdict=verdict):
                for path in self.payload_dir.iterdir():
                    path.unlink()
                response = self.decode_bytes(
                    carrier_bytes, "stego.png", sender_public, receiver_private
                )
                self.assertEqual(response.status_code, status, response.get_data(as_text=True))
                report = response.get_json()
                self.assertEqual(report["verdict"], verdict)
                self.assertEqual(report["frame_version"], frame_version)
                self.assertEqual(report["start_location"], start_location)
                self.assertEqual(report["lsb_bits"], lsb_bits)
                if has_preserved:
                    self.assertIsInstance(report["preserved_bits"], int)
                    self.assertIsInstance(report["preserved_ratio"], float)
                else:
                    self.assertIsNone(report["preserved_bits"])
                    self.assertIsNone(report["preserved_ratio"])
                expected_fingerprint = (
                    display_rsa_public_key_fingerprint(wrong_sender)
                    if sender_public is not None
                    else sender_fingerprint
                )
                self.assertEqual(report["sender_key_fingerprint"], expected_fingerprint)
                self.assertFalse(
                    any(path.name.startswith(".stego-staging-") for path in self.payload_dir.iterdir())
                )
                if verdict == "Authentic":
                    self.assertIn("payload_url", report["payload"])
                    self.assertEqual(len(list(self.payload_dir.glob("*.bin"))), 1)
                else:
                    self.assertIsNone(report["payload"])
                    self.assertFalse(report["payload_extracted"])
                    self.assert_no_recovered_payloads()

    def test_native_media_preview_signatures_match_claims(self) -> None:
        """Supported browser media families preview only after bounded sniffing."""
        def ftyp(brand: bytes, compatible: bytes) -> bytes:
            return struct.pack(">I4s4sI4s", 24, b"ftyp", brand, 0, compatible)

        def ogg_page(packet: bytes) -> bytes:
            return (
                b"OggS\x00\x02" + bytes(20) + bytes([1, len(packet)]) + packet
            )

        cases = (
            ("image/gif", b"GIF89a tiny image"),
            ("image/webp", b"RIFF\x04\x00\x00\x00WEBP"),
            ("image/avif", ftyp(b"avif", b"avif")),
            ("image/bmp", b"BM\x00\x00tiny bitmap"),
            ("audio/ogg", ogg_page(b"\x01vorbis")),
            ("audio/ogg", ogg_page(b"OpusHead")),
            ("audio/flac", b"fLaC"),
            ("audio/mp4", ftyp(b"M4A ", b"mp42")),
            ("video/mp4", ftyp(b"isom", b"mp41")),
            ("video/webm", b"\x1aE\xdf\xa3\x42\x82\x84webm"),
            ("video/ogg", ogg_page(b"\x80theora")),
        )
        service = CurrentProtocolService()
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "payload.bin"
            for mime, fixture in cases:
                with self.subTest(mime=mime, fixture=fixture[:12]):
                    path.write_bytes(fixture)
                    record = PayloadRecord(
                        "IMG-test", 1, bytes(16), bytes(32), b"",
                        f"mime={mime};name=fixture.bin".encode(),
                    )
                    result = service._verified_payload(record, path)
                    self.assertEqual(result["sniffed_mime"], mime)
                    self.assertTrue(result["type_agrees"])
                    self.assertTrue(result["preview_allowed"])

    def test_preview_excludes_svg_and_matroska(self) -> None:
        """Active SVG and Matroska files stay download-only."""
        cases = (
            ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"),
            ("video/x-matroska", b"\x1aE\xdf\xa3\x42\x82\x88matroska"),
        )
        service = CurrentProtocolService()
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "payload.bin"
            for mime, fixture in cases:
                with self.subTest(mime=mime):
                    path.write_bytes(fixture)
                    record = PayloadRecord(
                        "IMG-test", 1, bytes(16), bytes(32), b"",
                        f"mime={mime};name=fixture.bin".encode(),
                    )
                    result = service._verified_payload(record, path)
                    self.assertFalse(result["preview_allowed"])

    def test_payload_claim_extension_mappings_match_native_preview_types(self) -> None:
        """Server extension claims cover MIME types missing from host databases."""
        cases = (
            ("image.avif", "image/avif"),
            ("clip.m4a", "audio/mp4"),
            ("clip.aac", "audio/mp4"),
            ("sound.flac", "audio/flac"),
            ("sound.opus", "audio/ogg"),
            ("clip.webm", "video/webm"),
        )
        for filename, expected_mime in cases:
            with self.subTest(filename=filename):
                self.assertEqual(
                    infer_payload_claim(filename, "application/octet-stream", False),
                    (expected_mime, filename),
                )

    def test_inferred_gif_claim_ignores_client_overrides_and_previews(self) -> None:
        """A GIF file replaces a previous video claim and previews by its own type."""
        gif_payload = b"GIF89a tiny payload"
        encoded_response = self.encode(
            sample_png(),
            "cover.png",
            payload=(gif_payload, "selected.gif"),
            payload_mime="video/x-matroska",
            payload_name="old-video.mkv",
        )
        self.assertEqual(encoded_response.status_code, 200)
        encoded = encoded_response.get_json()
        self.assertEqual(encoded["payload"]["mime"], "image/gif")
        self.assertEqual(encoded["payload"]["name"], "selected.gif")

        report = self.decode(encoded, "stego.png").get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertEqual(report["payload"]["metadata"]["mime"], "image/gif")
        self.assertEqual(report["payload"]["metadata"]["name"], "selected.gif")
        self.assertTrue(report["payload"]["preview_allowed"])
        response = self.get_payload(report["payload"])
        self.assertEqual(response.mimetype, "image/gif")
        self.assertFalse(response.headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(response.get_data(), gif_payload)

    def test_mime_mismatch_disables_preview_without_invalidating_signature(self) -> None:
        """A file name claim that disagrees with its bytes is not rendered."""
        encoded = self.encode(
            sample_png(), "cover.png", payload=(b"GIF89a tiny payload", "x.png")
        ).get_json()
        report = self.decode(encoded, "stego.png").get_json()
        self.assertEqual(report["verdict"], "Authentic")
        self.assertFalse(report["payload"]["type_agrees"])
        self.assertFalse(report["payload"]["preview_allowed"])
        payload_response = self.get_payload(report["payload"])
        self.assertEqual(payload_response.mimetype, "application/octet-stream")
        self.assertTrue(
            payload_response.headers["Content-Disposition"].startswith("attachment;")
        )
        self.assertEqual(payload_response.headers["X-Content-Type-Options"], "nosniff")

    def test_pdf_payload_is_download_only(self) -> None:
        """A correctly typed PDF is downloadable but never rendered inline."""
        pdf_bytes = b"%PDF-1.7\nminimal PDF payload\n"
        encoded = self.encode(
            sample_png(),
            "cover.png",
            payload=(pdf_bytes, "assignment.pdf"),
        ).get_json()
        report = self.decode(encoded, "stego.png").get_json()
        self.assertEqual(report["verdict"], "Authentic")
        payload = report["payload"]
        self.assertTrue(payload["type_agrees"])
        self.assertFalse(payload["preview_allowed"])
        response = self.get_payload(payload)
        self.assertEqual(response.get_data(), pdf_bytes)
        self.assertEqual(response.mimetype, "application/octet-stream")
        self.assertTrue(response.headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            "default-src 'none'; img-src 'self'; media-src 'self'; sandbox",
        )
        self.assertIn("filename=assignment.pdf", response.headers["Content-Disposition"])

    def test_payload_route_rejects_staging_directories_and_files(self) -> None:
        """Private staging names and nested files cannot use payload download URLs."""
        staging_dir = self.payload_dir / ".stego-staging-test"
        staging_dir.mkdir()
        payload_id = "A" * 22
        (staging_dir / f"{payload_id}.bin").write_bytes(b"private staging bytes")
        (staging_dir / f"{payload_id}.json").write_text("{}", encoding="utf-8")
        for identifier in (staging_dir.name, payload_id):
            with self.subTest(identifier=identifier):
                response = self.client.get(f"/payload/{identifier}")
                self.assertEqual(response.status_code, 404)

    def test_incremental_utf8_check_handles_chunk_boundaries(self) -> None:
        """Text validation accepts split UTF-8 characters and rejects bad bytes."""
        service = CurrentProtocolService()
        with tempfile.TemporaryDirectory(prefix="inf2005-utf8-test-") as temporary:
            path = Path(temporary) / "payload.txt"
            path.write_bytes(b"a" * (64 * 1024 - 1) + "é".encode("utf-8") + b"z")
            self.assertTrue(service._type_agrees("text/plain", None, path))
            path.write_bytes(b"a" * (64 * 1024) + b"\xff")
            self.assertFalse(service._type_agrees("text/plain", None, path))

    def test_payload_route_rejects_invalid_and_missing_ids(self) -> None:
        """Invalid tokens and absent sidecars return JSON 404 responses."""
        for payload_id in ("invalid!", "short", "a" * 21):
            with self.subTest(payload_id=payload_id):
                response = self.client.get(f"/payload/{payload_id}")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.get_json()["error"], "payload file not found")
        missing = self.client.get(f"/payload/{'a' * 22}")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.get_json()["error"], "payload file not found")

    def test_payload_sidecar_failure_removes_partial_payload(self) -> None:
        """A failed sidecar write removes the already-written payload bytes."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        with patch("stego_web.routes.json.dump", side_effect=OSError("sidecar failed")):
            response = self.decode(encoded, "stego.png")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")
        self.assertNotIn("sidecar failed", response.get_data(as_text=True))
        self.assert_no_recovered_payloads()

    def test_large_text_payload_is_download_only(self) -> None:
        """Avoid reading a multi-megabyte authenticated text payload into the browser."""
        payload = PayloadRecord(
            "ID", 0, b"\0" * 16, b"\0" * 32, b"x",
            b"mime=text/plain;name=large.txt",
        )
        path = self.payload_dir / "large.bin"
        path.write_bytes(b"a" * (1024 * 1024 + 1))
        details = CurrentProtocolService()._verified_payload(payload, path)
        self.assertTrue(details["type_agrees"])
        self.assertFalse(details["preview_allowed"])
        path.write_bytes(b"a" * (1024 * 1024))
        self.assertTrue(CurrentProtocolService()._verified_payload(payload, path)["preview_allowed"])

    def test_inactive_layout_estimate_returns_controlled_failure(self) -> None:
        """The disconnected map API must not raise or mislabel its failure as bad input."""
        response = self.client.post("/layout/estimate", data={})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["ok"], False)
        self.assertIn("manual start unit", response.get_json()["error"])

    def test_duplicate_file_and_form_fields_are_rejected(self) -> None:
        """Multipart duplicates must not silently choose an arbitrary first value."""
        duplicate = self.client.post(
            "/decode",
            data=MultiDict([
                ("stego", (io.BytesIO(b"one"), "one.png")),
                ("stego", (io.BytesIO(b"two"), "two.png")),
            ]),
            content_type="multipart/form-data",
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.get_json()["error"], "upload exactly one file: stego")
        self.assertEqual(list(self.payload_dir.iterdir()), [])
        with self.client.application.test_request_context(
            "/encode", method="POST",
            data=MultiDict([("team_id", "first"), ("team_id", "second")]),
        ):
            with self.assertRaisesRegex(ValueError, "exactly one value: team_id"):
                routes._required_form_value("team_id")
        with self.client.application.test_request_context(
            "/encode", method="POST",
            data=MultiDict([("start_unit", "2048"), ("start_unit", "2049")]),
        ):
            with self.assertRaisesRegex(ValueError, "exactly one value: start_unit"):
                routes._integer_form_value("start_unit", 0)
        with self.client.application.test_request_context(
            "/encode", method="POST",
            data=MultiDict([("secret_message", "one"), ("secret_message", "two")]),
        ):
            with self.assertRaisesRegex(ValueError, "exactly one value: secret_message"):
                routes._payload_input(self.work_dir)

    def test_bad_numeric_fields_do_not_reach_the_encoder(self) -> None:
        """Decimal, negative, and out-of-range layout values give controlled errors."""
        for value, expected in (("1.5", "integer"), ("-1", "at least"), ("9", "between 1 and 8")):
            with self.subTest(value=value):
                data = {"start_unit": value, "lsb_bits": "1"}
                if value == "9":
                    data = {"start_unit": "2048", "lsb_bits": value}
                with self.client.application.test_request_context("/encode", method="POST", data=data):
                    with self.assertRaisesRegex(ValueError, expected):
                        routes._lsb_bits() if value == "9" else routes._integer_form_value("start_unit", 0)

    def test_encode_storage_failure_is_safe_and_removes_partial_output(self) -> None:
        """An output-device failure is a 500 without path disclosure or leftover media."""
        def fail_after_write(*args: object, **kwargs: object) -> None:
            Path(str(args[1])).write_bytes(b"partial")
            raise OSError("private path /secret/output")

        with patch("stego_web.routes.protocol_service.encode", side_effect=fail_after_write):
            response = self.encode(sample_png(), "cover.png")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("/secret", response.get_data(as_text=True))
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_decode_storage_failure_is_safe_and_removes_partial_payload(self) -> None:
        """A read/write failure cannot publish a partial plaintext payload."""
        def fail_after_write(*args: object, **kwargs: object) -> None:
            Path(str(args[1])).write_bytes(b"partial secret")
            raise OSError("private path /secret/payload")

        with patch("stego_web.routes.protocol_service.verify", side_effect=fail_after_write):
            response = self.decode_bytes(sample_png(), "received.png")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")
        self.assertNotIn("/secret", response.get_data(as_text=True))
        self.assert_no_recovered_payloads()

    def test_key_generation_supports_both_roles(self) -> None:
        """Sender and receiver setup both produce encrypted RSA key pairs."""
        for role in ("sender", "receiver"):
            with self.subTest(role=role):
                response = self.client.post(
                    "/keys/generate",
                    data={"role": role, "key_password": "setup-password"},
                )
                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertEqual(body["role"], role)
                self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", body["private_key_pem"])
                self.assertIn("BEGIN PUBLIC KEY", body["public_key_pem"])

    def test_key_generation_without_password_returns_unencrypted_pkcs8(self) -> None:
        """An omitted key password generates a plain PKCS#8 private PEM."""
        response = self.client.post("/keys/generate", data={"role": "sender"})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        private_pem_text = response.get_json()["private_key_pem"]
        self.assertTrue(private_pem_text.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertNotIn("ENCRYPTED", private_pem_text)

    def test_key_generation_keeps_nonempty_password_whitespace(self) -> None:
        """A non-empty password is used exactly as entered, without stripping."""
        password = " 123456 "
        response = self.client.post(
            "/keys/generate", data={"role": "sender", "key_password": password}
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        generated_pem = response.get_json()["private_key_pem"].encode("ascii")
        loaded = CurrentProtocolService()._load_private_key(
            generated_pem, password, "sender private key"
        )
        self.assertEqual(loaded.key_size, 2048)

    def test_key_generation_rejects_duplicate_optional_password(self) -> None:
        """Optional key-password fields still reject duplicate values."""
        response = self.client.post(
            "/keys/generate",
            data=MultiDict(
                [
                    ("role", "sender"),
                    ("key_password", "first-password"),
                    ("key_password", "second-password"),
                ]
            ),
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"], "provide exactly one value: key_password"
        )

    def test_key_password_fields_are_optional_with_eight_character_minimum(self) -> None:
        """Each key-password input allows empty text but keeps minlength eight."""
        pages = (
            (
                self.client.get("/").data,
                (b'name="sender_key_password"', b'id="receiver-setup-password"'),
            ),
            (
                self.client.get("/verify").data,
                (b'name="receiver_key_password"',),
            ),
        )
        for page, markers in pages:
            lowered_page = page.lower()
            self.assertIn(b"optional", lowered_page)
            self.assertIn(b"leave empty for an unencrypted key", lowered_page)
            for marker in markers:
                marker_index = page.index(marker)
                input_start = page.rfind(b"<input", 0, marker_index)
                input_end = page.index(b">", marker_index)
                input_markup = page[input_start : input_end + 1]
                self.assertIn(b'minlength="8"', input_markup)
                self.assertNotIn(b" required", input_markup)

    def test_unencrypted_sender_and_receiver_keys_round_trip_with_empty_passwords(self) -> None:
        """Protocol v3 encodes and verifies with unencrypted RSA private keys."""
        sender_pem = unencrypted_private_pem(self.sender_private)
        receiver_pem = unencrypted_private_pem(self.receiver_private)
        encoded_response = self.encode(
            sample_png(),
            "cover.png",
            message="unencrypted demo key round trip",
            sender_private_key_pem=sender_pem,
            sender_key_password="",
        )
        self.assertEqual(
            encoded_response.status_code,
            200,
            encoded_response.get_data(as_text=True),
        )
        decoded = self.decode(
            encoded_response.get_json(),
            "stego.png",
            receiver_private=receiver_pem,
            receiver_key_password="",
        )
        self.assertEqual(decoded.status_code, 200, decoded.get_data(as_text=True))
        self.assertEqual(decoded.get_json()["verdict"], "Authentic")

    def test_encrypted_sender_key_with_empty_password_returns_400(self) -> None:
        """The encode route tells users to enter a password for encrypted keys."""
        response = self.encode(
            sample_png(), "cover.png", sender_key_password=""
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "sender private key is encrypted; enter its password",
        )

    def test_encrypted_receiver_key_with_empty_password_reports_cannot_verify(self) -> None:
        """The encrypted-key mismatch returns the normal Cannot Verify report."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        response = self.decode(encoded, "stego.png", receiver_key_password="")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")
        self.assertEqual(
            response.get_json()["message"],
            "receiver private key is encrypted; enter its password",
        )
        self.assert_no_recovered_payloads()

    def test_wrong_sender_password_keeps_existing_error_message(self) -> None:
        """An incorrect sender password keeps the established error text."""
        response = self.encode(
            sample_png(), "cover.png", sender_key_password="wrong-password"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "sender private key could not be loaded with that password",
        )

    def test_wrong_receiver_password_keeps_existing_report_message(self) -> None:
        """An incorrect receiver password keeps the Cannot Verify report."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        response = self.decode(
            encoded, "stego.png", receiver_key_password="wrong-password"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")
        self.assertEqual(
            response.get_json()["message"],
            "receiver private key could not be loaded with that password",
        )

    def test_unencrypted_sender_key_with_password_returns_400(self) -> None:
        """The encode route rejects a password for an unencrypted sender key."""
        response = self.encode(
            sample_png(),
            "cover.png",
            sender_private_key_pem=unencrypted_private_pem(self.sender_private),
            sender_key_password=PASSWORD,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "sender private key is not encrypted; leave the password empty",
        )

    def test_unencrypted_receiver_key_with_password_reports_cannot_verify(self) -> None:
        """A password for an unencrypted key returns Cannot Verify normally."""
        encoded = self.encode(sample_png(), "cover.png").get_json()
        response = self.decode(
            encoded,
            "stego.png",
            receiver_private=unencrypted_private_pem(self.receiver_private),
            receiver_key_password=PASSWORD,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")
        self.assertEqual(
            response.get_json()["message"],
            "receiver private key is not encrypted; leave the password empty",
        )
        self.assert_no_recovered_payloads()

    def test_seven_character_password_is_rejected_for_generation_encode_and_decode(self) -> None:
        """Non-empty passwords still need at least eight characters."""
        generated = self.client.post(
            "/keys/generate", data={"role": "sender", "key_password": "1234567"}
        )
        self.assertEqual(generated.status_code, 400)
        self.assertEqual(
            generated.get_json()["error"],
            "key password must contain at least 8 characters",
        )
        encoded = self.encode(
            sample_png(), "cover.png", sender_key_password="1234567"
        )
        self.assertEqual(encoded.status_code, 400)
        self.assertEqual(
            encoded.get_json()["error"],
            "key password must contain at least 8 characters",
        )
        valid_encoded = self.encode(sample_png(), "cover.png").get_json()
        decoded = self.decode(
            valid_encoded, "stego.png", receiver_key_password="1234567"
        )
        self.assertEqual(decoded.status_code, 200)
        self.assertEqual(decoded.get_json()["verdict"], "Cannot Verify")
        self.assertEqual(
            decoded.get_json()["message"],
            "key password must contain at least 8 characters",
        )

    def test_obsolete_or_ambiguous_inputs_are_rejected(self) -> None:
        """The route requires current keys, valid layout, and exactly one payload."""
        missing_receiver = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "sender_private_key": (
                    io.BytesIO(self.sender_private_pem),
                    "sender-private.pem",
                ),
                "sender_key_password": PASSWORD,
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "message",
                "start_unit": "2048",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(missing_receiver.status_code, 400)
        self.assertIn("receiver_public_key", missing_receiver.get_json()["error"])

        inside_bootstrap = self.encode(sample_png(), "cover.png").get_json()
        self.assertEqual(inside_bootstrap["start_location"], 2048)
        invalid = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "sender_private_key": (
                    io.BytesIO(self.sender_private_pem),
                    "sender-private.pem",
                ),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem),
                    "receiver-public.pem",
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "message",
                "start_unit": "2047",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertIn("bootstrap", invalid.get_json()["error"])

    def test_download_route_serves_png_and_wav_files(self) -> None:
        """Stored PNG and WAV outputs stream with their carrier MIME types."""
        cases = (("png", sample_png(), "image/png"), ("wav", sample_wav(), "audio/wav"))
        for extension, cover, expected_mime in cases:
            with self.subTest(extension=extension):
                encoded_response = self.encode(cover, f"cover.{extension}")
                self.assertEqual(
                    encoded_response.status_code, 200, encoded_response.get_data(as_text=True)
                )
                body = encoded_response.get_json()
                self.assertNotIn("stego_base64", body)
                self.assertEqual(body["mime_type"], expected_mime)
                download_response = self.client.get(body["stego_url"])
                download_bytes = download_response.get_data()
                self.assertEqual(download_response.status_code, 200)
                self.assertEqual(download_response.mimetype, expected_mime)
                self.assertTrue(
                    download_response.headers["Content-Disposition"].startswith(
                        f"inline; filename=stego.{extension}"
                    )
                )
                self.assertEqual(download_response.headers["Cache-Control"], "no-store")
                stored_path = self.output_dir / str(body["stego_url"]).rsplit("/", 1)[1]
                self.assertEqual(download_bytes, stored_path.read_bytes())
                download_response.close()

    def test_downloaded_stego_file_remains_available(self) -> None:
        """A download does not delete the stored stego file."""
        body = self.encode(sample_png(), "cover.png").get_json()
        first = self.client.get(body["stego_url"])
        first_bytes = first.get_data()
        self.assertEqual(first.status_code, 200)
        stored_path = self.output_dir / str(body["stego_url"]).rsplit("/", 1)[1]
        self.assertTrue(stored_path.is_file())
        first.close()
        second = self.client.get(body["stego_url"])
        second_bytes = second.get_data()
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second_bytes, first_bytes)
        second.close()

    def test_download_rejects_bad_ids_and_extensions(self) -> None:
        """The download route accepts only token-safe IDs and PNG/WAV suffixes."""
        urls = (
            f"/download/{'A' * 22}.png",
            f"/download/{'A' * 21}!.png",
            "/download/..png",
            f"/download/{'A' * 22}.jpg",
            f"/download/{'A' * 23}.png",
        )
        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 404)
                if url == urls[0]:
                    self.assertEqual(
                        response.get_json(),
                        {"ok": False, "error": "stego file not found"},
                    )

    def test_unsupported_carrier_error_is_unchanged(self) -> None:
        """Unsupported files keep the established carrier-error text."""
        response = self.encode(b"not a media file", "cover.bin")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "unsupported or unreadable source; upload an image (PNG, JPEG, WebP, AVIF, BMP, TIFF, GIF) or audio (WAV, MP3, AAC/M4A, FLAC, ALAC, Ogg Vorbis/Opus) file",
        )

    def test_missing_and_empty_carrier_upload_errors_remain(self) -> None:
        """Missing and empty carrier uploads keep their established messages."""
        missing = self.client.post(
            "/encode", data={"secret_message": "message"}, content_type="multipart/form-data"
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.get_json()["error"], "missing required upload: cover")
        empty = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(b""), "empty.png"),
                "secret_message": "message",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(empty.status_code, 400)
        self.assertEqual(empty.get_json()["error"], "uploaded file is empty: cover")
        missing_stego = self.client.post(
            "/decode", data={}, content_type="multipart/form-data"
        )
        self.assertEqual(missing_stego.status_code, 400)
        self.assertEqual(
            missing_stego.get_json()["error"], "missing required upload: stego"
        )
        empty_stego = self.client.post(
            "/decode",
            data={"stego": (io.BytesIO(b""), "empty.wav")},
            content_type="multipart/form-data",
        )
        self.assertEqual(empty_stego.status_code, 400)
        self.assertEqual(
            empty_stego.get_json()["error"], "uploaded file is empty: stego"
        )
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_encode_rejects_sender_private_key_over_64_kib(self) -> None:
        """Reject an oversized sender key before reading it into memory."""
        limit = 64 * 1024
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "sender_private_key": (io.BytesIO(b"x" * (limit + 1)), "sender.pem"),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem), "receiver.pem"
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "message",
                "start_unit": "2048",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {
                "ok": False,
                "error": (
                    "uploaded file is too large: sender_private_key "
                    f"(limit {limit} bytes)"
                ),
            },
        )

    def test_decode_rejects_receiver_private_key_over_64_kib(self) -> None:
        """Reject an oversized receiver key with the existing decode response."""
        limit = 64 * 1024
        response = self.client.post(
            "/decode",
            data={
                "stego": (io.BytesIO(b"not decoded before key loading"), "cover.png"),
                "sender_public_key": (
                    io.BytesIO(self.sender_public_pem), "sender.pem"
                ),
                "receiver_private_key": (
                    io.BytesIO(b"x" * (limit + 1)), "receiver.pem"
                ),
                "receiver_key_password": PASSWORD,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {
                "ok": False,
                "error": (
                    "uploaded file is too large: receiver_private_key "
                    f"(limit {limit} bytes)"
                ),
                "verdict": "Cannot Verify",
            },
        )

    def test_required_upload_without_limit_reads_full_file(self) -> None:
        """Read the complete multipart upload when no size limit is set."""
        content = b"the complete cover upload"
        with self.client.application.test_request_context(
            "/layout/estimate",
            method="POST",
            data={"cover": (io.BytesIO(content), "cover.png")},
            content_type="multipart/form-data",
        ):
            self.assertEqual(
                routes._required_upload("cover", max_bytes=None), content
            )

    def test_key_upload_at_64_kib_is_not_refused_for_size(self) -> None:
        """Accept the size boundary, then report the invalid key itself."""
        limit = 64 * 1024
        response = self.client.post(
            "/encode",
            data={
                "cover": (io.BytesIO(sample_png()), "cover.png"),
                "sender_private_key": (io.BytesIO(b"x" * limit), "sender.pem"),
                "sender_key_password": PASSWORD,
                "receiver_public_key": (
                    io.BytesIO(self.receiver_public_pem), "receiver.pem"
                ),
                "team_id": "P1-4",
                "sender": "Test User",
                "secret_message": "message",
                "start_unit": "2048",
                "lsb_bits": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "sender private key could not be loaded with that password",
        )
        self.assertNotIn("uploaded file is too large", response.get_json()["error"])

    def test_failed_encode_leaves_no_output_file(self) -> None:
        """An encode refusal removes any incomplete output file."""
        response = self.encode(
            sample_png(), "cover.png", payload=(b"x" * (128 * 1024), "large.bin")
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("user payload exceeds capacity", response.get_json()["error"])
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_request_without_content_length_returns_411_before_disk_check(self) -> None:
        """Refuse upload routes without parsing bodies or checking disk space."""
        with patch("stego.storage.shutil.disk_usage") as disk_usage:
            for path, expected_verdict in (
                ("/encode", None),
                ("/decode", "Cannot Verify"),
                ("/capacity", None),
            ):
                response = self.client.open(
                    path,
                    method="POST",
                    data=b"",
                    environ_overrides={"CONTENT_LENGTH": None},
                )
                self.assertEqual(response.status_code, 411)
                self.assertEqual(
                    response.get_json()["error"],
                    "Content-Length header is required",
                )
                self.assertEqual(response.get_json().get("verdict"), expected_verdict)
        disk_usage.assert_not_called()

    def test_disk_guard_rejects_upload_before_body_parsing(self) -> None:
        """The free-space check refuses requests above the guarded capacity."""
        with patch("stego.storage.shutil.disk_usage") as disk_usage:
            disk_usage.return_value.free = 3 * 1024**3 + 10
            response = self.client.post(
                "/decode",
                data={"stego": (io.BytesIO(b"x" * 1024), "cover.mkv")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"],
            "upload is larger than the free disk space allows",
        )
        disk_usage.assert_called_once_with(self.work_dir)

    def test_upload_spooling_and_request_files_use_work_directory(self) -> None:
        """Multipart spools and request temporary directories use STEGO_WORK_DIR."""
        original_stream = tempfile.TemporaryFile
        observed_stream_dirs: list[Path] = []

        def stream_in_work_dir(*args: object, **kwargs: object) -> object:
            observed_stream_dirs.append(Path(str(kwargs["dir"])))
            return original_stream(*args, **kwargs)

        with patch(
            "stego_web.tempfile.TemporaryFile", side_effect=stream_in_work_dir
        ), patch(
            "stego_web.routes.tempfile.TemporaryDirectory",
            wraps=tempfile.TemporaryDirectory,
        ) as temporary_directory:
            response = self.encode(sample_png(), "cover.png")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(observed_stream_dirs)
        self.assertEqual(observed_stream_dirs, [self.work_dir] * len(observed_stream_dirs))
        self.assertTrue(
            any(call.kwargs.get("dir") == self.work_dir
                for call in temporary_directory.call_args_list)
        )
        self.assertEqual(list(self.work_dir.iterdir()), [])

    def test_upload_limit_returns_json(self) -> None:
        """No request cap is configured by default; deployments can set one."""
        self.assertIsNone(self.client.application.config["MAX_CONTENT_LENGTH"])
        client = create_app(
            {
                "TESTING": True,
                "MAX_CONTENT_LENGTH": 100,
                "STEGO_OUTPUT_DIR": self.output_dir,
                "PAYLOAD_OUTPUT_DIR": self.payload_dir,
                "STEGO_WORK_DIR": self.work_dir,
            }
        ).test_client()
        response = client.post(
            "/decode", data={"stego": (io.BytesIO(b"x" * 200), "file")}
        )
        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json()["verdict"], "Cannot Verify")


if __name__ == "__main__":
    unittest.main()
