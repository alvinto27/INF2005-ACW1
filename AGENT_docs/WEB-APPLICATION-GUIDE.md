# Web Application Guide

**Status:** The localhost Flask application uses the current masked-media protocol. This file is the source of truth for web inputs, request handling, verification reports, payload previews, and assignment requirement status. See [Current Protocol](CURRENT-PROTOCOL.md) for wire and cryptographic rules, and [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) for bounded I/O and staging behavior.

## Entry points

`run.py` creates the Flask app from `stego_web`. Routes in `stego_web/routes.py` use `stego_web/services/current_protocol.py`; the adapter calls the public file-backed APIs from `stego`. PyAV is required for runtime image, audio, and video I/O; Pillow is not used by the application. The browser verification controller is `stego_web/static/verify.js`. The main encode wizard is `stego_web/static/app.js`.

## Encode request

`POST /encode` accepts a still image (PNG, JPEG, WebP, AVIF, BMP, TIFF, or GIF), audio (WAV, MP3, AAC/M4A, FLAC, ALAC, or Ogg Vorbis/Opus), or a video container with one real video stream and zero or one audio stream. It also accepts a message or payload file, the sender private key and password, the receiver public key, a start unit, and an LSB count from 1 through 8. The payload MIME and filename claims are generated from the selected message or file. The browser displays them as read-only fields; the server ignores any submitted `payload_mime` or `payload_name` values and infers its own claims before signing them.

Flask saves each request's uploads and working files under `STEGO_WORK_DIR`, defaulting to `instance/work`. This host uses `/tmp` as a RAM-backed filesystem, so multipart uploads and video snapshots must stay on the instance filesystem. The request deletes its temporary directory after success or failure. PyAV multipart file streams are also created in the work directory. PNG and RIFF/WAVE use the fast signature path. For other sources, the service inspects PyAV streams and uses `detect_source_family()` to select an adapter. Strict PNG and PCM WAV carriers bypass conversion and keep their current ancillary data. Key PEMs remain byte inputs.

The adapter calls `open_image_source()` or `open_audio_source()`, then passes the yielded `carrier_source` to the PNG or WAV file API. Those APIs accept `carrier_source`; the video file API does not, so it constructs one `VideoCarrier` for validation, counting, and its bounded read passes. Video encode writes a lossless FFV1 + PCM Matroska output named `stego.mkv`; its source is always reported as converted. The library has a 4 GiB carrier-unit cap, 256 MiB canonical frame-byte cap, 2 GiB output cap, and 3 GiB free-space reserve (plus payload size for payload-file encoding). The response contains `source_converted`, container-based `source_format`, output `file_size`, and a `stego_url`, file details, sender public key, record summary, capacity, geometry, and preserved-bit measurements; it does not contain stego bytes or private keys. `GET /download/<id>.<ext>` checks the token and extension before serving the file. MKV is served as an attachment because browsers do not play the FFV1 Matroska output inline.

## Decode request

`POST /decode` requires four multipart fields:

- `stego`: one 8-bit or 16-bit RGB/RGBA PNG, uncompressed PCM WAV, or an EBML Matroska video carrier (`.mkv`);
- `sender_public_key`: the trusted sender RSA-2048 public PEM;
- `receiver_private_key`: the intended receiver's encrypted RSA-2048 private PEM; and
- `receiver_key_password`: the password for that private key.

The request does not include media type, LSB count, start unit, record length, a shared location secret, or the original cover. The bootstrap supplies geometry and AES session material. Flask stores the upload in the work directory and calls `verify_png_to_payload_path`, `verify_wav_to_payload_path`, or `verify_video_to_payload_path` based on the carrier family.

The route uses these HTTP status codes:

| Condition | HTTP status | Body |
| --- | --- | --- |
| A required upload or form field is missing or empty, or the upload cannot be saved | 400 | `ok`, `error`, and verdict `Cannot Verify`; no report fields |
| All fields are present, but the service cannot use them: the carrier is unsupported or unreadable, the sender public key cannot be read, or the receiver private key cannot be opened with the password | 200 | Full report with verdict `Cannot Verify` |
| The receiver private key cannot open the bootstrap | 422 | Full report with verdict `Payload Missing` |
| Verification completes with any other verdict | 200 | Full report; callers must read the verdict |
| The upload exceeds a configured `MAX_CONTENT_LENGTH` or the free-space guard | 413 | JSON error |

A readable version 2 bootstrap returns `Cannot Verify` with detail `unsupported bootstrap version`; the decoder does not retry with an older format.

Verification reads the bootstrap, validates recovered fields and bounds, reads the packet at that location, checks padding, verifies RSA-PSS before decryption, opens AES-GCM, parses the record, and checks the v3 media hash last. It reads one bootstrap and does not search for alternative packets. Cryptographic and integrity decisions remain in `stego/core.py`; Flask validates inputs and serializes the result.

## Result and payload handling

The `/encode` JSON response keeps its existing fields and adds:

| Field | Meaning |
| --- | --- |
| `source_converted` | `true` when a source was converted to canonical PNG/WAV or rewritten as FFV1/PCM Matroska; strict PNG and PCM WAV return `false`. |
| `source_format` | Detected source label, such as `jpeg`, `mp3`, `m4a`, `ogg-opus`, `png`, `wav`, `mp4`, `matroska`, `webm`, or `mov`. |
| `file_size` | Encoded output size in bytes. |
| `payload.mime` | The final MIME claim sealed in the authenticated metadata. |
| `payload.name` | The final filename claim sealed in the authenticated metadata. |

The browser shows a short conversion note, for example: “Your JPEG source was converted to a lossless PNG before embedding.”

`/decode` reports include verdict and detail, carrier type and size, protocol version, recovered start unit and LSB count, signature and integrity state, sender-key fingerprint, preserved-bit count and ratio, and authenticated record fields.

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

The service reads at most a 4 KiB prefix to recognize preview types; it does not decode uploaded media. It allows inline preview only when the metadata is unambiguous, the declared MIME agrees with recognized bytes, and the MIME is in this allowlist:

| Preview | MIME types |
| --- | --- |
| Text | `text/plain` (checked as UTF-8 in bounded chunks) |
| Images | `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/avif`, `image/bmp` |
| Audio | `audio/wav`, `audio/mpeg`, `audio/ogg`, `audio/flac`, `audio/mp4`, `audio/webm` |
| Video | `video/mp4`, `video/webm`, `video/ogg` |

The browser uses native image, audio, and video elements for allowed media. WebM is conservatively sniffed as `video/webm`; an audio-only WebM claim does not match that sniff and stays download-only. Matroska, SVG, HTML, XML, PDF, and other non-allowlisted types remain download-only. A signed false MIME claim does not change the cryptographic verdict; the payload is saved but not rendered. The browser inserts response text with `textContent`, prevents duplicate submits, and handles JSON and transport failures.

`GET /payload/<id>` validates the token and sidecar, sets a safe MIME type and download name, and applies `nosniff`, a restrictive Content Security Policy, and `Cache-Control: no-store`. Files have no expiry. Recovered payloads are plaintext on disk; anyone who can read the instance folder can read them. Use host-level access controls outside a trusted localhost deployment.

## Errors and storage

The `POST /encode` status rules are:

| Condition | HTTP status | Body |
| --- | --- | --- |
| Missing fields, unsupported or unreadable source, source conversion refusal, invalid keys, or layout/capacity failure | 400 | JSON `error`; known source failures keep the library message |
| Upload exceeds a configured request limit or the free-space guard | 413 | JSON error |
| Unexpected server failure | 500 | Generic JSON error |

Source refusals that return 400 include CMYK images, animated images, floating-point or over-16-bit images, the image decoded-byte cap, RIFF-size cap, unsupported video pixel formats, more than two audio channels, and extra video/audio/subtitle/data streams. Video backend messages are returned for carrier-unit, frame-byte, free-space, and output-size limit failures. The source converter turns RGB PNG `tRNS` colour-key transparency into RGBA alpha. The strict PNG adapter still refuses that input when it is used directly. Unsupported or unreadable files return HTTP 400. `/decode` accepts PNG, PCM WAV, and Matroska video. Its status codes are in the table in [Decode request](#decode-request). If the route cannot store the sidecar for an `Authentic` payload, it removes the payload and returns HTTP 500 with verdict `Cannot Verify`. Unexpected errors are logged and return a generic HTTP 500. Werkzeug statuses such as 404, 405, and 413 are retained.

The default `MAX_CONTENT_LENGTH` is `None`; deployments and tests can configure a fixed request cap. Before Flask reads an encode/decode body, it compares `Content-Length` with free space in `STEGO_WORK_DIR` minus a 1 GiB margin. Exceeding that space returns 413 with `upload is larger than the free disk space allows`. Werkzeug's multipart file streams, both route request directories (`inf2005-encode-*` and `inf2005-stego-*`), and converted source snapshots use `STEGO_WORK_DIR`. The default is `instance/work`, on the same filesystem as outputs; do not use `/tmp`, which is a tmpfs RAM disk on this host. There are no additional web upload-size caps. Backend video limits are:

| Limit | Value | Refusal |
| --- | ---: | --- |
| Carrier units | 4 GiB units | Library capacity/limit message, HTTP 400 |
| Canonical decoded frame | 256 MiB | `video frame exceeds configured frame-byte limit`, HTTP 400 |
| Encoded Matroska output | 2 GiB | `video output exceeds configured byte limit`, HTTP 400 |
| Free disk before encode | 3 GiB reserve, plus payload size for payload-file encoding | `insufficient free disk space for video output`, HTTP 400 |

The optional fixed request cap and the free-space guard return 413. `create_app(test_config)` can override the work directory and request cap. `TemporaryDirectory` removes request files and source snapshots on normal success or failure; there is no stale-directory sweeper. Encoded carriers and recovered payloads remain in their output directories until users delete them. Private `.stego-staging-*` directories are removed on normal exits. Power loss or `SIGKILL` can leave request or unauthenticated plaintext staging; stop the server and remove these directories manually after a crash. See [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#cleanup-rule).

`/keys/generate` is a local setup helper for sender or receiver keys. Deployment beyond trusted localhost still needs key storage and access controls, key rotation, transport protection, and auditing.

## Requirement coverage

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| FR1 image input | Implemented | Common image sources convert to canonical PNG for encode; strict 8-bit or 16-bit RGB/RGBA PNG is used for verify. |
| FR2 audio input | Implemented | Common audio sources convert to canonical PCM/WAV for encode; strict PCM/WAV is used for verify. |
| Optional video carrier | Implemented | Video covers encode to FFV1/PCM Matroska, and the web verifier accepts those outputs. |
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

Run `python -m unittest -v`. `test_webapp.py` covers the Flask request/response pipeline; `test_stego.py` covers protocol, image/audio source conversion, and negative verdicts; `test_video.py` covers the video carrier. A wrong receiver key and an absent payload intentionally share one result. Authenticity depends on the sender public key supplied by the receiver. PNG ancillary chunks and WAV chunks outside declared samples are not covered; overwritten LSBs cannot be recovered or authenticated. Version 3 media-hash limits are listed in [Current Protocol](CURRENT-PROTOCOL.md#limits-and-compatibility).
