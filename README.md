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

The web API accepts 1-8 LSBs and a passphrase-derived, non-zero start location.
Encoding requires an existing password-encrypted RSA private-key upload. The
optional `/keys/generate` setup endpoint can create initial localhost demo keys;
`/encode` itself never generates or returns private-key material.
The wizard calls `/location/derive` to display the same PBKDF2-HMAC-SHA256
location that the encoding pipeline will use.

The interface uses GSAP 3.15 from jsDelivr for progressive card, progress, and
result animations. If the CDN is unavailable or the browser requests reduced
motion, the complete encode and decode workflows continue without animation.

## Verify / Decode

Open **Verify / Decode** from the page navigation. Upload the received PNG/WAV,
the sender's trusted public PEM key, and enter the encoding start secret.
Media type and LSB count default to automatic recovery; a known LSB value can
also be selected. Upload the exact original cover for full integrity checks.
Click **Verify received media** to see the verdict, signature/integrity checks,
extracted metadata, hashes, and collapsible technical details.

The signed hash authenticates the original file bytes. To check the received
file too, verification re-embeds the extracted signed packet into the verified
original and compares expected and received pixels/PCM data. Without an original,
a valid signature returns **Cannot Verify**, not a media-authenticity claim.
No private key is needed. See [decoding details](docs/DECODING_VERIFICATION.md).

## Tests and documentation

```sh
python -m unittest -v
python scripts/check-docs.py
```

- [Agent instructions](AGENTS.md)
- [Documentation index](docs/README.md)
- [Agent navigation map](docs/AGENT_MAP.md)
- [Assignment specification](docs/INF2005-ACW1-spec_v5-f2f.md)
