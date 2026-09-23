# INF2005-ACW1

This project provides a localhost Flask application for strict RGB PNG images and
uncompressed PCM WAV audio, plus a Python API for video frame and video audio
steganography. All adapters use the reduced protocol version 2 in `stego`.

The protocol encrypts the complete payload record with AES-256-GCM, authenticates
the ciphertext and embedding geometry with RSA-PSS, and encrypts a bootstrap to
the intended receiver with RSA-OAEP. Integrity is calculated over every carrier
bit that embedding intentionally preserves.

Requires Python 3.10+.

## Setup and run

```sh
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`. Run all automated checks with:

```sh
python -m unittest -v
python scripts/check-docs.py
```

The optional demonstration notebook additionally needs:

```sh
python -m pip install -r requirements-notebook.txt
```

## Video Python API

Video input may use a format PyAV can decode. The encoded output must end in
`.mkv`. Frame mode writes lossless FFV1 RGB video and remuxes original audio
tracks. Audio mode decodes the first audio track to signed 16-bit PCM, embeds in
one low byte per sample, writes uncompressed PCM audio, and remuxes the original
video streams. Select the mode explicitly; the two payload locations and media
codes are separate.

```python
from stego import bootstrap_span, encode_video, verify_video

start = bootstrap_span(receiver_public_key)
for mode in ("frames", "audio"):
    output = f"stego-{mode}.mkv"
    encode_video(
        "input.mp4", output, signing_private_key, receiver_public_key,
        start, 3, b"secret message", b"mime=text/plain", mode=mode,
    )
    result = verify_video(output, sender_public_key, receiver_private_key, mode=mode)
    assert result.valid and result.payload.user_payload == b"secret message"
```

Audio mode requires an audio track. Both adapters currently decode their selected
carrier in memory. Streaming and chunk processing are not implemented. Verification
authenticates the selected carrier, not unrelated tracks. The Flask UI continues
to offer PNG and WAV; the video functions are available through Python.

To try both video modes on the bundled MPEG-4/AAC cover and keep the encoded
videos for inspection, run:

```sh
python -m scripts.try_video
```

The cover is `samples/video-test-source.mkv`; the command saves
`samples/video-test-output/stego-frames.mkv` and `stego-audio.mkv` and prints
each verification verdict. Use `--mode frames` or `--mode audio` to run one mode.

## Web application flow

Encoding requires:

1. an RGB PNG or uncompressed PCM WAV cover;
2. either a UTF-8 message or one arbitrary payload file;
3. an encrypted sender RSA private key and its password;
4. the intended receiver's RSA public key;
5. a packet start unit at or after the 2,048-unit RSA-2048 bootstrap span; and
6. an LSB count from 1 through 8.

The server validates the inputs, constructs typed authenticated metadata, builds
the masked-media hash, encrypts the complete payload record, signs the encrypted
record and geometry, embeds the receiver bootstrap and packet, and returns the
stego media plus the sender public key.

Verification requires only the received stego file, the trusted sender public
key, and the intended receiver private key/password. The receiver bootstrap
recovers the start unit, LSB count, record length, and AES session material.
The original cover and the previous shared start-location secret are not inputs.

Authenticated payload files can be downloaded after verification. The browser
previews supported text, PNG, JPEG, WAV, and MP3 payloads only when the signed
MIME claim agrees with the recovered bytes.

## Protocol API

The public Python API includes `encode_carrier`, `decode_carrier`, `encode_png`,
`verify_png`, `encode_wav`, and `verify_wav`. Verification requires the sender
public key and receiver private key. For example:

```python
layout, payload = encode_png(
    "cover.png",
    "stego.png",
    sender_private_key,
    receiver_public_key,
    2048,
    3,
    b"message",
    b"mime=text/plain;name=message.txt",
)
result = verify_png("stego.png", sender_public_key, receiver_private_key)
```

All serialised protocol integers use unsigned 64-bit big-endian fields. Existing
version 1 and legacy web `STG1` files are not accepted by the active version-2
web routes. The legacy `payload_protocol.py` module and its tests remain for
historical compatibility; see [Protocol Compatibility](AGENT_docs/PROTOCOL-COMPATIBILITY.md).

## Documentation

- [Agent instructions](AGENTS.md)
- [Documentation index](AGENT_docs/README.md)
- [Agent navigation map](AGENT_docs/AGENT_MAP.md)
- [Protocol design](AGENT_docs/PROTOCOL-DESIGN.md)
- [Web implementation status](AGENT_docs/IMPLEMENTATION-STATUS.md)
- [Assignment specification](docs/INF2005-ACW1-spec_v5-f2f.md)
