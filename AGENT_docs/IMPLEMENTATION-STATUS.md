# Flask application implementation status

The localhost entry point `run.py` creates the application from `stego_web`.
The active routes adapt uploaded bytes to the reduced masked-media protocol
version 3 through `stego_web/services/current_protocol.py`; they no longer use
the legacy `STG1` encoding and verification pipelines.

## Requirement coverage

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| FR1 image input | Implemented | Strict 8-bit RGB or RGBA PNG upload, validation, preview, encoding, decoding, and comparison. |
| FR2 audio input | Implemented | Uncompressed PCM/WAV upload, validation, playback, encoding, decoding, and comparison. |
| FR3 payload generation | Implemented | Encrypted record contains media ID, timestamp, nonce, v3 full media hash, raw user payload, and typed team metadata. |
| FR4 digital signature | Implemented | RSA-2048 RSA-PSS/SHA-256 covers protocol version, media context, layout, and ciphertext. |
| FR5 image LSB embedding | Implemented | PNG adapter and GUI support 1-8 LSBs. |
| FR6 audio LSB embedding | Implemented | WAV adapter embeds into the least-significant byte of each PCM sample and supports 1-8 LSBs. |
| FR7 variable start location | Implemented | GUI accepts a start unit outside the receiver bootstrap; the encrypted bootstrap hides and transports it. |
| FR8 extraction and decoding | Implemented | Receiver private key opens the bootstrap and recovers start unit, LSB count, record length, and AES material. |
| FR9 hash verification | Implemented | Receiver recomputes the v3 full media hash over masked RGB units, RGBA alpha bytes, and declared PCM sample bytes; no original cover is required. |
| FR10 verdict generation | Implemented | Protocol verdicts are returned without substituting weaker web-specific outcomes. |
| FR11 positive/negative cases | Automated coverage present | PNG/WAV round trips, all LSB counts, wrong sender/receiver keys, preserved-bit tampering, MIME mismatch, invalid inputs, and upload limits are tested. Captured demonstration evidence is still needed. |
| FR12 evidence/reproducibility | Partially implemented | README, setup, tests, notebook, and GUI are present; the final submission still needs selected screenshots/logs and sample transfer evidence. |
| FR13 innovation | Candidate implemented | Receiver-gated location confidentiality and encrypted typed payloads are available; the team must finalize its explanation. |

## Active web flow

1. `run.py` calls `stego_web.create_app()` and serves the retained seven-card GUI.
2. `/encode` accepts a strict cover, raw message/file payload, sender private key
   and password, receiver public key, explicit start unit, and LSB count.
3. Flask saves the cover upload to a request-scoped temporary file. Key PEMs and
   the payload file remain bounded byte inputs.
4. `CurrentProtocolService` detects the carrier from its first 12 bytes, loads both
   RSA key roles, and builds delimiter-checked typed metadata.
5. `stego.encode_png` or `stego.encode_wav` calculates geometry and full media
   integrity, encrypts the record with AES-256-GCM, signs it with RSA-PSS, encrypts
   the bootstrap with RSA-OAEP, and writes directly to `instance/stego-outputs`.
6. The response returns a `stego_url`, filename, MIME type, sender public key,
   authenticated record summary, capacity, geometry, and preserved-bit measurements.
   It does not return stego bytes or either private key.
7. `GET /download/<id>.<ext>` validates the generated token and PNG/WAV extension,
   then sends the stored file inline for browser preview or download.
8. `/decode` saves the stego upload to a temporary file. `stego.verify_png` or
   `stego.verify_wav` opens one receiver bootstrap, verifies the signature,
   decrypts and parses the record, and checks the v3 full media hash.
9. The report uses the file's stat size. An `Authentic` result stores the
   decrypted payload in `instance/recovered-payloads` and returns `payload_url`.
   The JSON does not include payload bytes or Base64 data.
10. `GET /payload/<id>` serves the stored payload with a safe MIME type,
    download name, and browser security headers. Temporary upload files are
    removed after each request. Stego and recovered payload files remain without
    expiry until the user deletes them. Recovered payload files are plaintext;
    anyone who can read the instance folder can read them. Responses carry
    `Cache-Control: no-store`.

## Carrier size

The library reads WAV carriers in bounded chunks. The 64 MiB whole-file WAV cap
and whole-file loader have been removed. Flask accepts requests up to 256 MiB,
which can be changed through `create_app(test_config)`. Carrier uploads go to
request-scoped temporary files. Encoded carriers are written to
`instance/stego-outputs` and served through `stego_url`; files stay there with no
expiry until the user deletes them. The output is not returned as base64. Verified
payloads are stored as plaintext files in `instance/recovered-payloads` and
served through `payload_url`; these files also stay until manual deletion. WAV
headers are checked with `read_pcm_wav_info`, and verify reports use the file
size from `stat()`. Pillow still decodes each PNG into a full image array, so PNG
working memory grows with image dimensions. See the
[Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md#12-web-boundary-follow-up).

`/keys/generate` is an explicit local setup helper for either sender or receiver.
Deployment beyond trusted localhost still needs persistent key management, access
control, rotation, transport protection, and auditing.
