# Flask application implementation status

The localhost entry point `run.py` creates the application from `stego_web`.
The active routes adapt uploaded bytes to the reduced masked-media protocol
version 2 through `stego_web/services/current_protocol.py`; they no longer use
the legacy `STG1` encoding and verification pipelines.

## Requirement coverage

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| FR1 image input | Implemented | Strict 8-bit RGB PNG upload, validation, preview, encoding, decoding, and comparison. |
| FR2 audio input | Implemented | Uncompressed PCM/WAV upload, validation, playback, encoding, decoding, and comparison. |
| FR3 payload generation | Implemented | Encrypted record contains media ID, timestamp, nonce, masked-media hash, raw user payload, and typed team metadata. |
| FR4 digital signature | Implemented | RSA-2048 RSA-PSS/SHA-256 covers protocol version, media context, layout, and ciphertext. |
| FR5 image LSB embedding | Implemented | PNG adapter and GUI support 1-8 LSBs. |
| FR6 audio LSB embedding | Implemented | WAV adapter embeds into the least-significant byte of each PCM sample and supports 1-8 LSBs. |
| FR7 variable start location | Implemented | GUI accepts a start unit outside the receiver bootstrap; the encrypted bootstrap hides and transports it. |
| FR8 extraction and decoding | Implemented | Receiver private key opens the bootstrap and recovers start unit, LSB count, record length, and AES material. |
| FR9 hash verification | Implemented | Receiver recomputes the masked-media hash directly from the stego carrier; no original cover is required. |
| FR10 verdict generation | Implemented | Protocol verdicts are returned without substituting weaker web-specific outcomes. |
| FR11 positive/negative cases | Automated coverage present | PNG/WAV round trips, all LSB counts, wrong sender/receiver keys, preserved-bit tampering, MIME mismatch, invalid inputs, and upload limits are tested. Captured demonstration evidence is still needed. |
| FR12 evidence/reproducibility | Partially implemented | README, setup, tests, notebook, and GUI are present; the final submission still needs selected screenshots/logs and sample transfer evidence. |
| FR13 innovation | Candidate implemented | Receiver-gated location confidentiality and encrypted typed payloads are available; the team must finalize its explanation. |

## Active web flow

1. `run.py` calls `stego_web.create_app()` and serves the retained seven-card GUI.
2. `/encode` accepts a strict cover, raw message/file payload, sender private key
   and password, receiver public key, explicit start unit, and LSB count.
3. `CurrentProtocolService` detects the carrier, loads both RSA key roles, builds
   delimiter-checked typed metadata, and creates a request-scoped temporary workspace.
4. `stego.encode_png` or `stego.encode_wav` calculates geometry and masked-media
   integrity, encrypts the record with AES-256-GCM, signs it with RSA-PSS, encrypts
   the bootstrap with RSA-OAEP, and writes the stego object.
5. The response returns stego bytes, sender public key, authenticated record
   summary, capacity, geometry, and preserved-bit measurements. It never returns
   either private key.
6. `/decode` accepts the stego object, trusted sender public key, receiver private
   key, and receiver-key password.
7. `stego.verify_png` or `stego.verify_wav` opens one receiver bootstrap, verifies
   the signature, decrypts and parses the record, and checks the masked-media hash.
8. Authenticated payload bytes are returned for download. The browser previews
   only supported media whose signed MIME claim agrees with recognized magic bytes.
9. The temporary workspace is removed at the end of each request and responses
   carry `Cache-Control: no-store`.

## Carrier size

The library now reads WAV carriers in bounded chunks, so `stego.encode_wav` and
`stego.verify_wav` accept WAVs larger than the old 64 MiB cap. The GUI does not
gain this yet: Flask limits requests to 32 MiB, the service reads uploads and
outputs fully into memory, returns the stego object as base64 JSON, and validates
WAV covers with the capped whole-file loader. The follow-up is in the
[Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md#12-web-boundary-follow-up).

`/keys/generate` is an explicit local setup helper for either sender or receiver.
Deployment beyond trusted localhost still needs persistent key management, access
control, rotation, transport protection, and auditing.
