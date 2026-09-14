# INF2005-ACW1
A GUI-based LSB Replacement steganography program (window-based or web-based) that protects and verifies both image and audio cover objects using steganography, hashing and digital signatures

The `stego` package provides the steganography implementation for strict
RGB PNG and uncompressed PCM WAV carriers. It encrypts arbitrary user bytes in a
single LSB embedding footprint with AES-256-GCM and authenticates them with RSA-PSS.

Every carrier bit that embedding intentionally preserves is represented in the
masked media hash. The encrypted record contains that hash and the user content.
The RSA-OAEP bootstrap gives only the receiver the packet geometry and AES-GCM
session material. The signature authenticates the ciphertext, flags, media
interpretation, and embedding layout.

Requires Python 3.10+.

## Current development stage

This branch implements stage 4c of the [version 2 plan](AGENT_docs/LOCATION-CONFIDENTIALITY-PLAN.md).
The public marker and packet header are removed. Existing version 1 files are not supported.
The receiver recovers packet geometry from an RSA-OAEP bootstrap.

Verification requires the sender public key and receiver private key. For example:

```python
layout, payload = encode_png(
    "cover.png", "stego.png", sender_private_key, receiver_public_key,
    2048, 3, b"message", b"{}"
)
result = verify_png("stego.png", sender_public_key, receiver_private_key)
```

`verify_wav` and `decode_carrier` use the same sender and receiver key roles.
The fixed RSA-2048 bootstrap span is 2,048 carrier units; the selected packet
start must be at or after that span.

## Documentation

- [Agent instructions](AGENTS.md)
- [Documentation index](AGENT_docs/README.md)
- [Agent navigation map](AGENT_docs/AGENT_MAP.md)

Install the library and test dependencies, then run the tests:

```sh
python -m pip install -r requirements.txt
python -m unittest -v
```

The notebook dependency is optional and is needed only to run the demonstration:

```sh
python -m pip install -r requirements-notebook.txt
```
