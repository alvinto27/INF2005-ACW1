# INF2005-ACW1

This repository contains the cryptographic payload protocol and a localhost
Flask web scaffold for an image/audio LSB steganography coursework project.

## Existing byte protocol

[`payload_protocol.py`](payload_protocol.py) accepts bytes only. It detects PNG
and WAV covers, creates canonical JSON metadata (media ID, type, UTC timestamp,
SHA-256 cover hash, nonce, team ID, and sender), signs it with RSA-2048/PSS and
SHA-256, and packs it with a four-byte big-endian length prefix. Key export and
import use PEM; private keys are password-encrypted.

```python
from payload_protocol import (
    build_verification_packet, create_payload, generate_rsa_keypair,
    sign_payload, verify_verification_packet,
)

private_key, public_key = generate_rsa_keypair()
cover = b"\x89PNG\r\n\x1a\nexample PNG bytes"
payload = create_payload(cover, "P1-4", "Alice")
packet = build_verification_packet(payload, sign_payload(payload, private_key))
valid, verdict, metadata = verify_verification_packet(packet, public_key)
```

## Web scaffold

[`stego_web/`](stego_web/) is the primary Flask architecture. It provides `/`
for the GUI, `/encode` for signed LSB embedding, and `/decode` for extraction,
signature verification, and optional original-cover hash verification. The
steganography engine is split from routes and crypto services; PNG and
uncompressed PCM/WAV are implemented. `run.py` starts the server on localhost.

```sh
python -m pip install -r requirements.txt
python run.py
```

The web API accepts 1–8 LSBs and a passphrase-derived, non-zero start location.
The generated key pair is held in memory for the process and should be replaced
with persistent, authenticated key storage before deployment. Do not expose the
private key returned by the starter `/encode` response outside local testing.

`webapp/` is an additional lower-level example showing reusable carrier and bit
packing adapters; use one scaffold consistently rather than combining both
route implementations.

## Tests and documentation

```sh
python -m unittest -v
python scripts/check-docs.py
```

- [Agent instructions](AGENTS.md)
- [Documentation index](docs/README.md)
- [Agent navigation map](docs/AGENT_MAP.md)
- [Assignment specification](docs/INF2005-ACW1-spec_v5-f2f.md)
