# INF2005-ACW1
A GUI-based LSB Replacement steganography program (window-based or web-based) that protects and verifies both image and audio cover objects using steganography, hashing and digital signatures

`stego_v1.py` provides the version-1 steganography implementation for strict
RGB PNG and uncompressed PCM WAV carriers. It encodes and verifies canonical
payload records with RSA-PSS signatures and region hashes. Requires Python 3.10+.

## Documentation

- [Agent instructions](AGENTS.md)
- [Documentation index](docs/README.md)
- [Agent navigation map](docs/AGENT_MAP.md)

```sh
python -m pip install -r requirements.txt
python -m unittest -v
```
