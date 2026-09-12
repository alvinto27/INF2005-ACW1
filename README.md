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
