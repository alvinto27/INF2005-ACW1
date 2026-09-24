# INF2005-ACW1

This project is a localhost Flask application for encrypting, signing, embedding,
decoding, and verifying payloads in strict RGB PNG images and uncompressed PCM
WAV audio. The retained web layout now uses the reduced protocol version 2 in
the `stego` package.

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
public key and receiver private key. `encode_wav` and `verify_wav` read the WAV
in bounded chunks, so the WAV size is not limited by memory. Backend-level
functions (`prepare_carrier_encoding`, `decode_carrier_source`) accept any
`CarrierSource`. For example:

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
