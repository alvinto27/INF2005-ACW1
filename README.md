# INF2005-ACW1
A GUI-based LSB Replacement steganography program (window-based or web-based) that protects and verifies both image and audio cover objects using steganography, hashing and digital signatures

The `stego` package provides the steganography implementation for strict
RGB PNG and uncompressed PCM WAV carriers. It stores arbitrary user bytes in a
single LSB embedding footprint and authenticates them with RSA-PSS.

Every carrier bit that embedding intentionally preserves is represented in the
masked media hash. The payload contains that hash and the user content. The
signature authenticates the payload together with the media interpretation and
embedding layout. RSA-PSS verification validates the signature bytes.

Requires Python 3.10+.

## Current development stage

This branch implements stage 4b of the [version 2 plan](AGENT_docs/LOCATION-CONFIDENTIALITY-PLAN.md).
It is an intermediate format, not the completed version 2 protocol. The public
marker and packet header are removed. Existing version 1 files are not supported.
The version constant stays at 1 until the encryption switch in stage 4c.

Verification now requires three values supplied separately from the carrier:
`start_unit`, `lsb_count`, and `payload_length`. The last value is the complete
serialised record length, not the user message length. For example:

```python
layout, payload = encode_png(
    "cover.png", "stego.png", sender_private_key, 101, 3, b"message", b"{}"
)
result = verify_png(
    "stego.png", sender_public_key,
    layout.start_unit, layout.lsb_count, layout.payload_length,
)
```

`verify_wav` and `decode_carrier` require the same three geometry arguments.
The receiver needs no original cover file. The record is still plaintext, so
**start-location confidentiality is not yet provided**. Stage 4c will encrypt the
record and carry the geometry in the receiver's encrypted bootstrap.

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
