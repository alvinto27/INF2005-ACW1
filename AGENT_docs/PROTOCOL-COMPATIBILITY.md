# Current and legacy protocol compatibility

## Active web format

The Flask routes now use masked-media protocol version 3 from the
`stego` package through `stego_web/services/current_protocol.py`. The retained
browser layout was adapted to its actual key and geometry flow:

- encoding uses the sender private key and receiver public key;
- the sender explicitly selects a start unit at or after the bootstrap span and
  an LSB count from 1 through 8;
- verification uses the sender public key and receiver private key/password; and
- verification recovers geometry from the RSA-OAEP bootstrap and does not need
  the original cover or a shared start-location secret.

`test_webapp.py` exercises this active path for PNG and WAV carriers.

## Retained legacy format

`payload_protocol.py` and the earlier services under `stego_web/services/`
retain the legacy `STG1` implementation for its existing unit tests and design
history. They are not called by `stego_web/routes.py`.

| Property | Active web protocol v3 | Retained legacy `STG1` |
| --- | --- | --- |
| Packet | Encrypted binary payload record, RSA-PSS signature, and encrypted receiver bootstrap | Public `STG1` frame containing canonical JSON and an RSA signature |
| Start location | Selected during encoding; encrypted in the receiver bootstrap | Derived from a shared secret with PBKDF2-HMAC |
| Integrity hash | V3 full media hash over masked carrier units and fixed sample bytes, with layout context | SHA-256 over exact original cover-file bytes |
| Encode keys | Sender private and receiver public | Sender private only |
| Verify inputs | Stego file, sender public, receiver private/password | Stego file, sender public, shared secret, and exact original cover for full integrity |
| Active tests | `test_stego.py`, `test_webapp.py` | `test_payload_protocol.py` |

## Compatibility rule

The formats are not interoperable. Version 2 masked-media files are not accepted:
a readable version 2 bootstrap returns `Cannot Verify` with detail
`unsupported bootstrap version`, never `Tampered`. The active `/decode` route also
rejects legacy `STG1` media instead of guessing a format or weakening the
receiver-private-key gate. RSA keys can share a PEM representation, but packet
structures, signing inputs, PSS policies, hashes, and discovery rules differ. A
future legacy importer must be explicitly versioned and isolated from the active
protocol-3 verdict path.
