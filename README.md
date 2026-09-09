# INF2005-ACW1
A GUI-based LSB Replacement steganography program (window-based or web-based) that protects and verifies both image and audio cover objects using steganography, hashing and digital signatures

The standalone `payload_protocol.py` module signs verification metadata with
RSA PKCS#1 v1.5 and SHA-256. It takes and returns bytes without file I/O or
steganography dependencies. Requires Python 3.10+.

## Documentation

- [Agent instructions](AGENTS.md)
- [Documentation index](docs/README.md)
- [Agent navigation map](docs/AGENT_MAP.md)

```sh
python -m pip install -r requirements.txt
python -m unittest -v
```

```python
from payload_protocol import (
    create_payload, generate_rsa_keypair,
    pack_verification_packet, unpack_and_verify_packet,
)

private_key, public_key = generate_rsa_keypair()
cover = b"original cover bytes"
payload = create_payload("media-001", cover, {"author": "Alice"})
packet = pack_verification_packet(payload, private_key)
valid, verdict, metadata = unpack_and_verify_packet(packet, public_key, cover)
assert valid and verdict == "Authentic"
```

Packets contain a four-byte big-endian JSON byte length, canonical JSON bytes,
and a signature (256 bytes for the default RSA-2048 key). The parser derives the
signature length from the public key and permits trailing bytes. Packing the
same payload with the same key is deterministic; creating a fresh payload adds
a new UTC timestamp and random nonce. Omitted custom metadata is absent from JSON.

Verification returns `Authentic`, `Tampered`, `Signature Invalid`,
`Payload Missing or Incomplete`, or `Payload Missing or Corrupted`.
Signed invalid JSON also returns `Payload Missing or Corrupted`. Cover hashes
must be compared against the original bytes that were hashed; embedding data
into a cover changes its bytes. Without a cover argument, `Authentic` confirms
the metadata signature only. Nonces do not enforce replay protection by themselves.
PEM export returns unencrypted private keys or public keys as bytes.
