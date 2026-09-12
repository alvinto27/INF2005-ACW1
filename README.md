# INF2005-ACW1

A localhost web application for protecting and verifying PNG images and
uncompressed PCM/WAV audio using LSB steganography, SHA-256, and RSA-PSS digital
signatures. The merge retains both protocol implementations already developed
in the repository.

Requires Python 3.10+.

## Setup and run

```sh
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`. The interface supports the seven-step encoding
workflow and a Verify / Decode workflow. It accepts 1-8 LSBs, previews image or
audio media, and uses GSAP 3.15 progressively for animation. The workflows still
work without the CDN or when reduced motion is requested.

Run all protocol and web tests with:

```sh
python -m unittest -v
python scripts/check-docs.py
```

The optional demonstration notebook additionally needs:

```sh
python -m pip install -r requirements-notebook.txt
```

## Flask application protocol

[`stego_web/`](stego_web/) provides `/encode`, `/decode`, `/location/derive`,
and `/keys/generate`. It uses [`payload_protocol.py`](payload_protocol.py) for
canonical JSON payloads and RSA-PSS signatures, and its own registered PNG/WAV
LSB engines for media operations.

The payload contains a media ID, media type, UTC timestamp, SHA-256 hash of the
exact original file bytes, nonce, team ID, sender, and custom metadata. A
PBKDF2-HMAC secret derives a repeatable non-zero embedding position. Full
integrity verification needs the exact original cover: the verifier checks its
signed hash, reconstructs the expected embedding, and compares the received
decoded pixels or PCM bytes. Without the original, a valid signature returns
`Cannot Verify` rather than making a full media-integrity claim.

See [Decoding and Verification](AGENT_docs/DECODING-VERIFICATION.md).

## Masked-media protocol

The incoming [`stego/`](stego/) package provides a separate byte-oriented
packet format plus strict RGB PNG and PCM/WAV adapters. It hashes the carrier
after clearing the LSB positions occupied by the packet. The signature covers
the payload, media interpretation, and embedding layout. This lets it verify
preserved carrier bits directly from the stego object without receiving the
original cover.

Its public API includes `encode_carrier`, `decode_carrier`, `encode_png`,
`verify_png`, `encode_wav`, and `verify_wav`. See the complete
[Masked Media Integrity Design](AGENT_docs/INTEGRITY-DESIGN.md).

## Compatibility boundary

The two implementations intentionally remain separate after this merge. Their
packet framing, location recovery, signing inputs, and integrity hashes differ,
so a file encoded by one must be decoded by the same implementation. The Flask
application continues using its established protocol; the masked-media package
and notebook remain available with their original API and tests.

See [Protocol Compatibility](AGENT_docs/PROTOCOL-COMPATIBILITY.md) before
integrating the masked-media package into the web application.

## Documentation

- [Agent instructions](AGENTS.md)
- [Documentation index](AGENT_docs/README.md)
- [Agent navigation map](AGENT_docs/AGENT_MAP.md)
- [Assignment specification](docs/INF2005-ACW1-spec_v5-f2f.md)
