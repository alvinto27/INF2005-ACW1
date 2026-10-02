# Web application

This guide describes the Flask web app: its pages, routes, request fields, responses, and storage. The [protocol guide](protocol.md) covers the data format and cryptography. The [carrier and payload flow](carrier-and-payload-flow.md) covers how files are read and written.

## Structure

```text
browser                      server                                  library
app.js / verify.js  ──►  stego_web/routes.py  ──►  services/current_protocol.py  ──►  stego/
(via api.js)             (checks the request)      (calls the file-based API)         (all crypto and checks)
```

The web layer checks inputs and converts results to JSON. All cryptographic and integrity decisions are made in the `stego` library. PyAV handles all media input and output; the app does not use Pillow.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /` | Encode page |
| `GET /verify` | Verify page |
| `POST /encode` | Create a stego file |
| `POST /capacity` | Check whether a payload fits a cover |
| `POST /decode` | Verify a stego file |
| `POST /keys/generate` | Generate an RSA-2048 key pair |
| `GET /download/<id>.<ext>` | Download a stego file |
| `GET /payload/<id>` | Preview or download a recovered payload |

## Pages

### Encode page

The encode form has six steps:

| Step | What happens |
| --- | --- |
| 1. Input | Select the cover and the payload. On leaving this step, the browser sends a capacity check. |
| 2. Sender | Load or generate the sender's private key. |
| 3. Receiver | Load or generate the receiver's public key. |
| 4. Layout | Choose the LSB count, then the start unit with a slider or number box. The slider range comes from the capacity check. |
| 5. Protect | The server hashes the carrier, encrypts and signs the record, and embeds it. |
| 6. Export | Download the stego file. |

On the Layout step:

- If a new LSB count makes the start unit too large, the page moves it and shows `Start moved to <n>, the latest start that fits at LSB <k>.`
- If nothing fits at that LSB count, the page disables the start controls and shows `Does not fit at LSB <k>. Try LSB <m>.`

### Verify page

Upload the stego file, the sender's public key, and the receiver's private key (with its password, if it has one). The page shows the verdict and a report. For an `Authentic` result, it also shows the payload preview or a download link.

### Accessibility and scripts

- Each page has a skip link, native file inputs, visible focus outlines, and text verdicts.
- The current step is marked with `aria-current`, and focus moves to the new step's heading.
- Animations use GSAP 3.15 from `cdn.jsdelivr.net`. This is the app's only external request. Without it, or with reduced motion turned on, the pages work without animation.
- The pages need JavaScript. A `noscript` message says so.

### Browser time limits

All requests go through `api.js`, which checks response fields and turns errors into readable messages.

| Request | Time limit |
| --- | --- |
| Encode (image or audio) | 5 minutes |
| Encode (video) | 1 hour |
| Key generation | 1 minute |
| Verify | 2 minutes (30 minutes for MKV) |

The browser never retries an encode or verify request by itself. A manual retry starts a new job, because the server does not cancel a job when the browser disconnects.

## POST /encode

### Fields

| Field | Required | Notes |
| --- | --- | --- |
| `cover` | Yes | See accepted formats below |
| `secret_message` or `payload_file` | One of them | Text message or any one file |
| `team_id`, `sender` | Yes | Stored in the signed metadata |
| `metadata` | No | Extra metadata text |
| `sender_private_key` | Yes | PEM, up to 64 KiB |
| `sender_key_password` | No | Empty for an unencrypted key; otherwise at least 8 characters |
| `receiver_public_key` | Yes | PEM, up to 64 KiB |
| `start_unit` | Yes | 2,048 or higher |
| `lsb_bits` | Yes | 1 to 8 |

The server works out the payload's MIME type and file name itself and ignores any values sent by the browser.

### Accepted covers

| Type | Formats | Output |
| --- | --- | --- |
| Image | Still PNG, JPEG, WebP, AVIF, BMP, TIFF, GIF | PNG |
| Audio | WAV (PCM), MP3, AAC (ADTS), M4A (AAC or ALAC), FLAC, Ogg (Vorbis or Opus) | WAV |
| Video | MP4/MOV, Matroska/WebM, AVI, with one video stream and at most one audio stream | FFV1/PCM MKV |

PNG and PCM WAV files that already meet the carrier rules are used directly and keep their metadata. Other files are converted first (see [source conversion](carrier-and-payload-flow.md#source-conversion)). Refused formats are listed in [known limitations](known-limitations.md#refused-source-formats).

A converted WAV over 2 GiB is allowed but not advised: some older audio programs cannot open it, and encoding needs about 8 GiB of free disk.

### Response

| Field | Meaning |
| --- | --- |
| `stego_url` | Download link for the stego file |
| `source_converted` | `true` if the cover was converted, which is always the case for video |
| `source_format` | Detected format, for example `jpeg`, `mp3`, `png`, `mp4` |
| `file_size` | Output size in bytes |
| `payload.mime`, `payload.name` | The MIME type and file name stored in the signed metadata |

The response also includes the sender's public key, a record summary, capacity, layout, and preserved-bit counts. It never includes the stego file itself or any private key. MKV files are always served as downloads.

### Status codes

| Status | When |
| --- | --- |
| 200 | Success |
| 400 | A field is missing, repeated, or invalid; the cover is unsupported or cannot be read; a key or password is wrong; or the payload does not fit |
| 411 | No `Content-Length` header |
| 413 | The upload is over the size limit or would use up the disk reserve |
| 500 | Server error (details are logged, not returned) |

## POST /capacity

The browser calls this after step 1 to check whether the payload fits. It sends the cover and a description of the payload, not the payload itself.

| Field | Notes |
| --- | --- |
| `cover`, `team_id`, `sender`, `metadata` | As for `/encode` |
| `secret_message` | For a text payload |
| `payload_size`, `payload_filename`, `payload_type` | For a file payload: size (at least 1), name, and browser MIME type (may be empty) |

The response contains carrier details and an `lsb_results` list with one entry for each LSB count from 1 to 8:

| Field | Meaning |
| --- | --- |
| `lsb_bits` | The LSB count |
| `max_start_unit` | Latest start unit at which the payload fits, or `null` |
| `max_payload_bytes_at_min_start` | Largest payload at start unit 2,048, or `null` |

The result is only an estimate, because the browser reports the payload size. `/encode` makes the final check. The status codes are the same as for `/encode`.

## POST /decode

### Fields

| Field | Required | Notes |
| --- | --- | --- |
| `stego` | Yes | PNG, PCM WAV, or MKV |
| `sender_public_key` | Yes | PEM, up to 64 KiB |
| `receiver_private_key` | Yes | PEM, up to 64 KiB |
| `receiver_key_password` | No | Same rules as for encoding |

The request does not include the LSB count, start unit, or original cover. The bootstrap provides them.

### Status codes

| Status | When | Body |
| --- | --- | --- |
| 200 | Verification finished with any verdict except `Payload Missing` | Full report |
| 200 | The file or a key cannot be used, or there is not enough disk space to stage the payload | Full report, verdict `Cannot Verify` |
| 400 | A field is missing or empty, or a key file is over 64 KiB | Error, verdict `Cannot Verify` |
| 411 | No `Content-Length` header | Error, verdict `Cannot Verify` |
| 413 | The upload is over the size limit or would use up the disk reserve | Error |
| 422 | The receiver's key cannot open the bootstrap | Full report, verdict `Payload Missing` |
| 500 | Storage failure, including failure to save an `Authentic` payload | Error, verdict `Cannot Verify` |

### Report fields

The report includes the verdict and detail, carrier type and size, start unit, LSB count, signature and integrity results, the sender key fingerprint, preserved-bit counts, and the record fields. A field is `null` when verification did not reach the step that sets it:

| Field | Set when |
| --- | --- |
| `frame_version` | The bootstrap was opened. It is the version read from the file, for example `2` for a version 2 file. |
| `start_location`, `lsb_bits` | The bootstrap was opened and its fields are valid |
| `preserved_bits`, `preserved_ratio` | The packet fits in the carrier |
| `sender_key_fingerprint` | The sender's public key was loaded |
| `payload`, `payload_url` | The verdict is `Authentic` |

## Recovered payloads

After an `Authentic` result, the payload is saved to `instance/recovered-payloads/` with a small sidecar file that records its download name, MIME type, and whether it can be previewed. The response contains a link, not the payload bytes.

The browser previews a payload only if its signed MIME type matches its first 4 KiB and is in this list:

| Type | MIME types |
| --- | --- |
| Text | `text/plain` (valid UTF-8, up to 1 MiB) |
| Image | `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/avif`, `image/bmp` |
| Audio | `audio/wav`, `audio/mpeg`, `audio/ogg`, `audio/flac`, `audio/mp4`, `audio/webm` |
| Video | `video/mp4`, `video/webm`, `video/ogg` |

- Anything else, such as SVG, HTML, PDF, or Matroska, is download-only.
- WebM is always detected as `video/webm`, so a file labelled as audio-only WebM is download-only.
- A wrong MIME type does not change the verdict. The file is saved but not previewed.
- `GET /payload/<id>` sends `nosniff`, a strict Content Security Policy, and `Cache-Control: no-store`.
- Response text is inserted with `textContent`, never as HTML.

## Storage and disk space

| Folder | Contents | Removed |
| --- | --- | --- |
| `instance/work/` | Uploads and temporary files for each request | When the request ends |
| `instance/stego-outputs/` | Stego files | By the user |
| `instance/recovered-payloads/` | Recovered payloads, unencrypted | By the user |

- Temporary files go in `instance/work/` (set by `STEGO_WORK_DIR`), not `/tmp`, because `/tmp` uses RAM on some systems.
- There is no fixed upload size limit by default. `MAX_CONTENT_LENGTH` can set one.
- Every upload needs a `Content-Length` header. The server refuses an upload that would leave less than 3 GiB free (`upload is larger than the free disk space allows`).
- Before writing output, the server checks there is room for it plus the 3 GiB reserve. For video, it checks again before every write. Video limits are in [video carrier](video-carrier.md#output-and-limits).
- If the server is killed (for example by a power cut), `.stego-staging-*` folders can be left behind and may hold unencrypted payload data. Stop the server and delete them.
- Anyone who can read `instance/` can read recovered payloads. The app is meant for a trusted local machine.

## Key generation

`POST /keys/generate` takes a `role` (`sender` or `receiver`) and an optional `key_password`, and returns a new RSA-2048 key pair as PEM text. An empty password gives an unencrypted private key, which is suitable for demos only.

## Requirement coverage

| Requirement | Status | Where |
| --- | --- | --- |
| FR1 Image input | Done | Common image formats are converted to PNG; verification uses 8- or 16-bit RGB/RGBA PNG |
| FR2 Audio input | Done | Common audio formats are converted to PCM WAV |
| FR3 Payload generation | Done | Record holds media ID, timestamp, nonce, media hash, payload, and metadata |
| FR4 Digital signature | Done | RSA-PSS/SHA-256 over version, media context, layout, and ciphertext |
| FR5 Image LSB embedding | Done | 1 to 8 LSBs |
| FR6 Audio LSB embedding | Done | Low byte of each PCM sample, 1 to 8 LSBs |
| FR7 Variable start location | Done | Start unit chosen on the Layout step and stored in the bootstrap |
| FR8 Extraction and decoding | Done | Receiver's private key opens the bootstrap |
| FR9 Hash verification | Done | Media hash recomputed without the original cover |
| FR10 Verdict generation | Done | Seven verdicts, see [protocol](protocol.md#verification-verdicts) |
| FR11 Positive and negative cases | Done | Notebook and tests cover all verdicts, LSB counts, and file payloads |
| FR12 Evidence and reproducibility | Done | README, tests, notebook, and the demonstration ZIP (see [`demo/`](../demo/README.md)) |
| FR13 Innovation | Done | Receiver-only payload location (RSA-OAEP bootstrap), fully encrypted file payloads, and a lossless video carrier |

## Tests

| File | Covers |
| --- | --- |
| `test_webapp.py` | Routes, requests, responses, and previews |
| `test_stego.py` | Protocol, PNG and WAV carriers, source conversion, and verdicts |
| `test_video.py` | Video carrier |
