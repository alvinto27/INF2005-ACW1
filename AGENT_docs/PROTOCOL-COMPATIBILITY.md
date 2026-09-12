# Protocol compatibility after the merge

## Resolution

The merge retains both integrity implementations because each side has active
callers and tests. The Flask application continues to use the current web
protocol; the incoming masked-media implementation remains available as the
independent `stego` package. Neither implementation was made to parse the
other's packets during conflict resolution.

## Differences that prevent interoperability

| Property | Flask application | `stego` package |
| --- | --- | --- |
| Entry point | `run.py` and `stego_web/` | `stego/__init__.py` |
| Packet | `STG1` frame containing canonical JSON and RSA signature | Binary header, binary payload record, RSA signature, and alignment bits |
| Start location | Derived from a shared secret with PBKDF2-HMAC | Supplied for encoding and discovered from packet magic for verification |
| Signed media hash | SHA-256 of exact original file bytes | SHA-256 of masked carrier units and layout context |
| Full verification input | Stego file, public key, shared secret, and exact original cover | Stego file and public key |
| Tests | `test_payload_protocol.py`, `test_webapp.py` | `test_stego.py` |

An encoder and decoder must therefore come from the same column. RSA-PSS keys
may have the same PEM representation, but that does not make signatures or
packets compatible: the signed byte sequences and PSS salt policies differ.

## Integrity retained from each side

The Flask path retains its exact-original-file hash, canonical payload schema,
secret-derived location, bounded `STG1` extraction, signature verification, and
expected-versus-received decoded-media comparison.

The `stego` path retains its masked-media invariant, geometry-bound signing
input, packet discovery, preserved-bit reporting, strict media adapters, and
standalone notebook demonstration.

## Future integration rule

If the web application adopts `stego`, introduce an explicit protocol selector
or a versioned migration. Do not replace its backend while presenting old
`STG1` files as compatible. Add cross-boundary rejection tests and update the
GUI's required inputs, because masked-media verification does not need the
original cover or the current start-location secret.
