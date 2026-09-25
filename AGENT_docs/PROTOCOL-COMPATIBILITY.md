# Protocol compatibility

## Active web format

The Flask routes use masked-media protocol version 3 from the `stego` package
through `stego_web/services/current_protocol.py`. The active web flow uses
separate sender and receiver keys:

- Encoding uses the sender private key and receiver public key.
- The sender selects a start unit at or after the bootstrap span and an LSB count
  from 1 through 8.
- Verification uses the sender public key and receiver private key/password.
- The encrypted receiver bootstrap recovers the packet geometry. The original
  cover and a shared start-location secret are not required.

`test_webapp.py` covers this active path, and `test_stego.py` covers the protocol
library.

## Older formats

The earlier `STG1` implementation used signed canonical JSON, a public frame
marker, and a start location derived from a shared secret. It was a separate,
legacy format: it did not use the version-3 receiver bootstrap and was not
interoperable with the masked-media protocol. Its implementation and dedicated
tests have been removed. The [Merge Leftover Removal record](MERGE-LEFTOVER-REMOVAL.md)
records its behavior, authors, source permalinks, and removal evidence.

Version 1 and version 2 masked-media files are also not accepted by the active
version-3 routes. A readable version 2 bootstrap returns `Cannot Verify` with
detail `unsupported bootstrap version`; the verifier does not fall back to an
older protocol.

## Compatibility rule

The active Flask routes accept protocol version 3 only. They reject older
masked-media files and do not import or guess the historical `STG1` format. Do
not present these formats as interoperable. Any future importer must be
explicitly versioned and isolated from the protocol-3 verdict path. Preserve the
receiver-private-key gate and the documented version-3 verification verdicts.
