# Web Application Guide

**Status:** The localhost Flask application uses the current masked-media protocol. This file is the source of truth for web inputs, request handling, verification reports, payload previews, and assignment requirement status. See [Current Protocol](CURRENT-PROTOCOL.md) for wire and cryptographic rules, and [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) for bounded I/O and staging behavior.

## Entry points

`run.py` creates the Flask app from `stego_web`. Routes in `stego_web/routes.py` use `stego_web/services/current_protocol.py`; the adapter calls the public file-backed APIs from `stego`. The browser verification controller is `stego_web/static/verify.js`. The main encode wizard is `stego_web/static/app.js`.

## Encode request

`POST /encode` accepts a PNG or PCM WAV cover, a message or payload file, the sender private key and password, the receiver public key, a start unit, and an LSB count from 1 through 8. The start unit must be at or after the reserved bootstrap span. Flask saves the cover and payload to request-scoped temporary files. Key PEMs remain byte inputs. The service detects the carrier from its first 12 bytes, loads the key roles, and builds delimiter-checked typed metadata.

The adapter calls `stego.encode_png_from_payload_path` or `stego.encode_wav_from_payload_path`. The library writes the result to `instance/stego-outputs`. The response contains a `stego_url`, file details, sender public key, record summary, capacity, geometry, and preserved-bit measurements; it does not contain stego bytes or private keys. `GET /download/<id>.<ext>` checks the token and extension before serving the file.

## Decode request

`POST /decode` requires four multipart fields:

- `stego`: one 8-bit RGB/RGBA PNG or uncompressed PCM WAV;
- `sender_public_key`: the trusted sender RSA-2048 public PEM;
- `receiver_private_key`: the intended receiver's encrypted RSA-2048 private PEM; and
- `receiver_key_password`: the password for that private key.

The request does not include media type, LSB count, start unit, record length, a shared location secret, or the original cover. The bootstrap supplies geometry and AES session material. Flask stores the upload in a temporary file and calls `verify_png_to_payload_path` or `verify_wav_to_payload_path`.

The route uses these HTTP status codes:

| Condition | HTTP status | Body |
| --- | --- | --- |
| A required upload or form field is missing or empty, or the upload cannot be saved | 400 | `ok`, `error`, and verdict `Cannot Verify`; no report fields |
| All fields are present, but the service cannot use them: the carrier is not PNG or WAV, the PNG or WAV is not a supported format, the sender public key cannot be read, or the receiver private key cannot be opened with the password | 200 | Full report with verdict `Cannot Verify` |
| The receiver private key cannot open the bootstrap | 422 | Full report with verdict `Payload Missing` |
| Verification completes with any other verdict | 200 | Full report; callers must read the verdict |
| The upload is larger than the request limit | 413 | JSON error |

A readable version 2 bootstrap returns `Cannot Verify` with detail `unsupported bootstrap version`; the decoder does not retry with an older format.

Verification reads the bootstrap, validates recovered fields and bounds, reads the packet at that location, checks padding, verifies RSA-PSS before decryption, opens AES-GCM, parses the record, and checks the v3 media hash last. It reads one bootstrap and does not search for alternative packets. Cryptographic and integrity decisions remain in `stego/core.py`; Flask validates inputs and serializes the result.

## Result and payload handling

Reports include verdict and detail, carrier type and size, protocol version, recovered start unit and LSB count, signature and integrity state, sender-key fingerprint, preserved-bit count and ratio, and authenticated record fields.

A `null` field means that verification did not reach that step or did not recover that value. `null` differs from `false`. When a later step fails, the fields that verification recovered before the failure stay set:

| Field | Set when |
| --- | --- |
| `frame_version` | The receiver private key opened the bootstrap. The value is the version byte read from the received bootstrap, not the version of this application. A readable version 2 bootstrap gives `2`. |
| `start_location`, `lsb_bits` | The bootstrap was opened and its fields were valid. |
| `preserved_bits`, `preserved_ratio` | The recovered geometry fits the carrier. `Wrong Start Location` leaves them `null`. |
| `sender_key_fingerprint` | The service loaded the supplied sender public key and called the library. It identifies the supplied key, not a recovered value. |
| `payload` | The verdict is `Authentic`. Other verdicts never give payload fields, a payload file, or a `payload_url`. |

For example, `Signature Invalid`, `Cannot Decrypt`, and `Tampered` keep `frame_version` 3, the start location, the LSB count, and the preserved bits. `Payload Missing` and the 400 and service-level `Cannot Verify` responses have `frame_version` `null`. The browser shows the bootstrap as opened only when `frame_version` is not `null`.

Only an `Authentic` result includes `payload_url` and parsed typed metadata. The library atomically publishes authenticated payload bytes to `instance/recovered-payloads`; the route writes a small sidecar containing `download_name`, `serve_mime`, and `preview_allowed`. If sidecar creation fails, the payload is removed. The response contains a URL, not payload bytes or Base64.

The service recognizes PNG, JPEG, WAV, MP3, and PDF magic. It allows inline preview only when the metadata is unambiguous, the declared MIME agrees with recognized bytes, and the MIME is one of `text/plain`, `image/png`, `image/jpeg`, `audio/wav`, or `audio/mpeg`. Text is checked as UTF-8 in bounded chunks. The browser inserts response text with `textContent`, prevents duplicate submits, and handles JSON and transport failures. A signed false MIME claim does not change the cryptographic verdict; the payload is saved but not rendered.

`GET /payload/<id>` validates the token and sidecar, sets a safe MIME type and download name, and applies `nosniff`, a restrictive Content Security Policy, and `Cache-Control: no-store`. Files have no expiry. Recovered payloads are plaintext on disk; anyone who can read the instance folder can read them. Use host-level access controls outside a trusted localhost deployment.

## Errors and storage

For `POST /encode`, carrier and form validation errors return JSON with HTTP 400. For `POST /decode`, the status codes are in the table in [Decode request](#decode-request). If the route cannot store the sidecar for an `Authentic` payload, it removes the payload and returns HTTP 500 with verdict `Cannot Verify`. Unexpected errors are logged and return a generic HTTP 500. Werkzeug statuses such as 404, 405, and 413 are retained.

The whole-request limit is `MAX_CONTENT_LENGTH = 256 MiB`; `create_app(test_config)` can override it. Upload files are deleted when the request ends. Encoded carriers and recovered payloads remain in their output directories until users delete them. Private `.stego-staging-*` directories are removed on normal exits. Power loss or `SIGKILL` can leave unauthenticated plaintext staging; stop the server and remove these directories manually after a crash. See [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#cleanup-rule).

`/keys/generate` is a local setup helper for sender or receiver keys. Deployment beyond trusted localhost still needs key storage and access controls, key rotation, transport protection, and auditing.

## Requirement coverage

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| FR1 image input | Implemented | Strict 8-bit RGB/RGBA PNG validation, preview, encode, decode, and comparison. |
| FR2 audio input | Implemented | PCM/WAV validation, playback, encode, decode, and comparison. |
| FR3 payload generation | Implemented | Encrypted record contains media ID, timestamp, nonce, full media hash, raw payload, and typed metadata. |
| FR4 digital signature | Implemented | RSA-PSS/SHA-256 covers protocol version, media context, layout, and ciphertext. |
| FR5 image LSB embedding | Implemented | PNG adapter and GUI support 1–8 LSBs. |
| FR6 audio LSB embedding | Implemented | WAV adapter embeds into the low byte of each PCM sample and supports 1–8 LSBs. |
| FR7 variable start location | Implemented | GUI selects a start unit outside the bootstrap; the encrypted bootstrap carries it. |
| FR8 extraction and decoding | Implemented | Receiver private key opens the bootstrap and recovers geometry and AES material. |
| FR9 hash verification | Implemented | The receiver hashes masked RGB units, RGBA alpha, and declared PCM sample bytes without the original cover. |
| FR10 verdict generation | Implemented | Protocol verdicts are returned without weaker web-specific substitutes. |
| FR11 positive and negative cases | Automated coverage present | PNG/WAV round trips, all LSB counts, wrong keys, tampering, MIME mismatch, invalid inputs, and upload limits are tested. Captured demonstration evidence is still needed. |
| FR12 evidence and reproducibility | Partly implemented | Setup, tests, notebook, and GUI exist. The final submission still needs selected screenshots/logs and sample transfer evidence. |
| FR13 innovation | Candidate implemented | Receiver-gated location confidentiality and encrypted typed payloads are available; the team must finalize its explanation. |

## Tests and limits

Run `python -m unittest -v`. `test_webapp.py` covers the Flask request/response pipeline; `test_stego.py` covers protocol boundaries and negative verdicts. A wrong receiver key and an absent payload intentionally share one result. Authenticity depends on the sender public key supplied by the receiver. PNG ancillary chunks and WAV chunks outside declared samples are not covered; overwritten LSBs cannot be recovered or authenticated. Version 3 media-hash limits are listed in [Current Protocol](CURRENT-PROTOCOL.md#limits-and-compatibility).
