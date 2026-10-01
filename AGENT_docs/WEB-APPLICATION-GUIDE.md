# Web Application Guide

**Status:** The localhost Flask application uses the current masked-media protocol. This file is the source of truth for web inputs, request handling, verification reports, payload previews, and assignment requirement status. See [Current Protocol](CURRENT-PROTOCOL.md) for wire and cryptographic rules, and [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) for bounded I/O and staging behavior.

## Entry points

`run.py` creates the Flask app from `stego_web`. Routes in `stego_web/routes.py` use `stego_web/services/current_protocol.py`; the adapter calls the public file-backed APIs from `stego`. PyAV is required for runtime image, audio, and video I/O; Pillow is not used by the application. The browser verification controller is `stego_web/static/verify.js`. The main encode wizard is `stego_web/static/app.js`.

## Interface and accessibility

`GET /` serves the encoding page with a dark navigation bar, blue-lit hero,
four protocol diagrams, and a light workspace. `GET /verify` is a separate
receiver page: its outer canvas is white and its inner form workspace is blue.
Both pages fill the browser width without an outer frame. Navigation between
them uses a short fade over a white veil, then reveals the destination workspace.
The navigation remains a standard link when JavaScript is unavailable, and the
fade is skipped for reduced motion. The encode page links to `/verify` in its
header and hero, not below the encode workspace. The diagrams depict carrier
embedding, receiver-gated encryption, signature and media-hash checks, and the
verification verdict. They are inline decorative SVGs with scroll-triggered
motion; they require no image downloads or WebGL. Reduced-motion users see them
without animation.

The encode page has six steps: Input, Sender, Receiver, Layout, Protect, and
Export. Step 4 uses the capacity result to set a start-unit slider for the
selected LSB count. A number box stays in sync for exact values and sends
`start_unit`. The slider range runs from the bootstrap span to the latest legal
start that fits. In Protect, the server hashes preserved RGB units, RGBA alpha,
and declared PCM sample bytes with the chosen geometry before encryption and
signing.
Three.js carrier-map assets exist, but the template does not load them and the
map is not part of the active page. A separate `/verify` page handles
receiver-side verification. See [Three.js carrier map](#threejs-carrier-map) for
the asset status and known gaps.

The existing form field names, request contracts, key-generation controls,
media previews, downloads, and verdicts remain unchanged. The layout uses four
feature columns on desktop, two on tablets, and one on phones; workspace forms
and media previews also stack on narrow screens.

A skip link leads to the form on each page. Native file controls remain keyboard
accessible, the current wizard step is exposed with `aria-current`, and step
changes move focus to the new heading. Form labels, visible focus outlines,
live progress messages, and text verdicts support keyboard and screen-reader
use. CSS and the optional GSAP motion layer respect reduced-motion preferences.
If GSAP is unavailable, the existing local motion helper keeps interactions
functional. Both templates load GSAP 3.15 from `https://cdn.jsdelivr.net` (an
external request; the rest of the app is local). Without network access or when
reduced motion is enabled, `motion.js` skips GSAP and the workflow still works.
JavaScript is required for the workflow; a `noscript` notice explains this.
Exported media and recovered payloads remain on disk until deleted.

Both pages use the local `api.js` request boundary for JSON response validation,
status-specific messages, connection failures, and timeouts. Encode and key
generation keep controls retryable after failure; encode freezes its form inputs
while a request is in flight. The browser validates successful response fields
and same-origin download URLs before showing success. Non-video encode requests
time out after five minutes; video encode after one hour; key generation after
one minute; verification after two minutes or 30 minutes for MKV.

## Encode request

`POST /encode` accepts a still PNG, JPEG, WebP, AVIF, BMP, TIFF, or GIF image; WAV with a `pcm_*` codec; MP3; AAC ADTS; M4A in a MOV/MP4-family container with AAC or ALAC; FLAC; Ogg with Vorbis or Opus; or video in MP4/MOV, Matroska/WebM, or AVI with one decodable video stream and zero or one audio stream. Audio-only Matroska/WebM is refused. The cover file picker uses the same allowlist as the server. It also accepts either a message or payload file, required `team_id` and `sender` values, optional additional metadata, the sender private key and optional password, the receiver public key, a start unit, and an LSB count from 1 through 8. The payload MIME and filename claims are generated from the selected message or file. The browser displays them as read-only fields; the server ignores any submitted `payload_mime` or `payload_name` values and infers its own claims before signing them. Each sender or receiver key file can be up to 64 KiB.

The password is optional. Leave it empty for an unencrypted private key. A non-empty password must contain at least 8 characters and is used exactly as entered. Unencrypted private keys are for demos only: anyone with the file can use the key.

Flask saves each request's uploads and working files under `STEGO_WORK_DIR`, defaulting to `instance/work`. This host uses `/tmp` as a RAM-backed filesystem, so multipart uploads and video snapshots must stay on the instance filesystem. The request deletes its temporary directory after success or failure. PyAV multipart file streams are also created in the work directory. The PNG encoder stages its intermediate `.stego-staging-*.png` beside the output and removes it after the write; this keeps it off `/tmp`. PNG uses a signature path. The source gate checks WAV's codec and inspects PyAV streams for other accepted inputs before `detect_source_family()` selects an adapter. Strict PNG and PCM WAV carriers bypass conversion and keep their current ancillary data. Key PEMs remain byte inputs.

Image and audio source-conversion limits and temporary-storage checks are described in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#source-conversion).

Allowed, but not advised. A WAV file larger than 2 GiB can fail to open in some older audio programs, because they read the WAV size field as a signed number. The application reads it correctly. Such a file also needs about 8 GiB of disk during encoding (converted copy plus output) and cannot be sent by email.

The adapter calls `open_image_source()` or `open_audio_source()`, then passes the yielded `carrier_source` to the PNG or WAV file API. The video API builds its own `VideoCarrier` for validation, counting, and bounded reads. Video encode writes lossless FFV1/PCM Matroska and reports the source as converted. Its resource limits are in [Video Carrier Design](VIDEO-CARRIER-DESIGN.md#output-and-limits). The response contains `source_converted`, container-based `source_format`, output `file_size`, and a `stego_url`, file details, sender public key, record summary, capacity, geometry, and preserved-bit measurements; it does not contain stego bytes or private keys. `GET /download/<id>.<ext>` checks the token and extension before serving the file. MKV is served as an attachment because browsers do not play the FFV1 Matroska output inline.

## Capacity request

`POST /capacity` estimates whether a described payload fits a cover. It accepts these multipart fields:

- `cover`: one supported image, audio, or video source;
- `team_id` and `sender`: one value each;
- `metadata`: optional additional metadata; and
- exactly one payload description: `secret_message`, or all three file-description fields `payload_size`, `payload_filename`, and `payload_type`.

`payload_size` must be an integer of at least 1. `payload_filename` and `payload_type` are the selected browser file's `File.name` and `File.type`; an empty type is allowed, but the field must be present. The file itself is not uploaded. Message size uses its UTF-8 byte length. Duplicate values are rejected.

A successful JSON response includes `media_type`, `source_format`, `total_units`, `bootstrap_span`, `record_overhead`, and `payload_bytes`. `lsb_results` contains one result for each LSB count from 1 through 8. Each result has `lsb_bits`, `max_start_unit`, and `max_payload_bytes_at_min_start`. `max_start_unit` is the latest legal start that fits the supplied payload, or `null` if it cannot fit. The maximum payload value is measured at the earliest legal start, the bootstrap span, or is `null` if even an empty record cannot fit. Capacity uses the same metadata builder and layout checks as encode, including the configured RSA-2048 bootstrap span and the real media-ID length. Image and audio counts use their canonical adapters; video counts use decoded carrier units.

The route stores no output carrier or payload. It removes the uploaded cover copy and any converted source snapshot when the request ends.

### Early capacity check in the wizard

When the user leaves Input, the browser sends one capacity request with the cover and the payload description, not the payload bytes. It keeps the result while these inputs stay unchanged. On Layout, the LSB slider comes first. The result sets the start-unit slider's minimum to the bootstrap span and its maximum to the latest legal start for that LSB. The number box stays in sync and supports exact values when the slider is coarse. The page hides the status line when the selected start fits. If an LSB change makes the start too large, the page moves it and shows `Start moved to <n>, the latest start that fits at LSB <k>.` If no start fits at the selected LSB, it disables both start controls and suggests the smallest LSB that fits with `Does not fit at LSB <k>. Try LSB <m>.` `/encode` remains the final authority.

| Condition | HTTP status | Body |
| --- | --- | --- |
| The estimate succeeds | 200 | JSON with `ok`, protocol version, carrier details, and capacity results |
| A required value is missing, duplicated, invalid, or the cover is unsupported or unreadable | 400 | JSON with `ok: false` and `error` |
| The request has no `Content-Length` header | 411 | JSON with `ok: false` and `error` |
| The request exceeds a configured size limit or a disk-space guard refuses the upload copy | 413 | JSON error |
| A storage or read failure occurs | 500 | Generic JSON error; the server logs the exception |

A capacity result is an estimate, not an encode result. The client supplies the file size, and the cover can change after the request. `/encode` remains authoritative: it performs key checks, creates the payload record, and writes and validates the encoded carrier.

## Decode request

`POST /decode` requires three multipart fields and accepts one optional password field:

- `stego`: one 8-bit or 16-bit RGB/RGBA PNG, uncompressed PCM WAV, or an EBML Matroska video carrier (`.mkv`);
- `sender_public_key`: the trusted sender RSA-2048 public PEM;
- `receiver_private_key`: the intended receiver's RSA-2048 private PEM, encrypted or unencrypted; and
- `receiver_key_password`: optional; leave it empty for an unencrypted private key.

A non-empty password must contain at least 8 characters and is used exactly as entered. Unencrypted private keys are for demos only: anyone with the file can use the key.

The sender public key and receiver private key files can each be up to 64 KiB.

The request does not include media type, LSB count, start unit, record length, a shared location secret, or the original cover. The bootstrap supplies geometry and AES session material. Flask stores the upload in the work directory and calls `verify_png_to_payload_path`, `verify_wav_to_payload_path`, or `verify_video_to_payload_path` based on the carrier family.

The route uses these HTTP status codes:

| Condition | HTTP status | Body |
| --- | --- | --- |
| The request has no `Content-Length` header | 411 | JSON error with verdict `Cannot Verify` |
| A required upload or form field is missing or empty, or the upload cannot be saved | 400 | `ok`, `error`, and verdict `Cannot Verify`; no report fields |
| A key file exceeds 64 KiB | 400 | JSON error with verdict `Cannot Verify` |
| All fields are present, but the service cannot use them: the carrier is unsupported or unreadable, the sender public key cannot be read, the receiver private key cannot be opened with the given password, or the password does not match the receiver key's encryption state | 200 | Full report with verdict `Cannot Verify`; password/encryption mismatches include a clear message |
| The receiver private key cannot open the bootstrap | 422 | Full report with verdict `Payload Missing` |
| Verification completes with any other verdict | 200 | Full report; callers must read the verdict |
| The upload exceeds a configured `MAX_CONTENT_LENGTH`, fails the request free-space guard, or fails the per-upload free-space check before a route copies it | 413 | JSON error |

Too little free space for file-backed decode staging returns HTTP 200 with verdict `Cannot Verify`; no recovered payload is published. The check runs before the ciphertext staging file is created and accounts for three ciphertext lengths plus the shared reserve.

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

The browser uses native image, audio, and video elements for allowed media. Text
previews are limited to 1 MiB; larger authenticated text remains downloadable.
Text preview reads are bounded and time out after 30 seconds, with a retry
control if they fail. WebM is conservatively sniffed as `video/webm`; an
audio-only WebM claim does not match that sniff and stays download-only.
Matroska, SVG, HTML, XML, PDF, and other non-allowlisted types remain
download-only. A signed false MIME claim does not change the cryptographic
verdict; the payload is saved but not rendered. The browser inserts response
text with `textContent`, prevents duplicate submits, and handles JSON and
transport failures.

`GET /payload/<id>` validates the token and sidecar, sets a safe MIME type and download name, and applies `nosniff`, a restrictive Content Security Policy, and `Cache-Control: no-store`. Files have no expiry. Recovered payloads are plaintext on disk; anyone who can read the instance folder can read them. Use host-level access controls outside a trusted localhost deployment.

## Errors and storage

The `POST /encode` status rules are:

| Condition | HTTP status | Body |
| --- | --- | --- |
| The request has no `Content-Length` header | 411 | JSON `error` |
| Missing or duplicate fields/files, unsupported or unreadable source, source conversion refusal, invalid or oversized key files, key/password encryption mismatch, short non-empty password, or layout/capacity failure | 400 | JSON `error`; known source failures keep the library message |
| Upload exceeds a configured request limit, fails the request free-space guard, or fails the per-upload free-space check before a route copies it | 413 | JSON error |
| Storage or unexpected server failure | 500 | Generic JSON error without filesystem details; server logs the exception |

Source refusals that return 400 include CMYK images, animated images, floating-point or over-16-bit images, the image decoded-byte cap, converted PCM size limit, unsupported video pixel formats, more than two audio channels in converted sources, unsupported lossless audio sample depths, and extra video/audio/subtitle/data streams. The fixed source allowlist also refuses AIFF, WMA, audio-only Matroska/WebM, JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, and other unlisted formats with a specific or generic source-format reason. A decode failure in an allowed format says the file could not be decoded and may be damaged. Strict PCM WAV carriers accept any positive channel count. Video backend messages are returned for carrier-unit, frame-byte, free-space, and output-size limit failures. The source converter turns RGB PNG `tRNS` colour-key transparency into RGBA alpha. The strict PNG adapter still refuses that input when it is used directly. Unsupported or unreadable files return HTTP 400. `/decode` accepts PNG, PCM WAV, and Matroska video. Its status codes are in the table in [Decode request](#decode-request). If the route cannot store the sidecar for an `Authentic` payload, it removes the payload and returns HTTP 500 with verdict `Cannot Verify`. Unexpected errors are logged and return a generic HTTP 500. Werkzeug statuses such as 404, 405, and 413 are retained.

The default `MAX_CONTENT_LENGTH` is `None`; deployments and tests can configure a fixed request cap. Before Flask reads an encode, decode, or capacity body, it requires `Content-Length`; a missing header returns 411. It compares the declared length with free space in `STEGO_WORK_DIR` minus the shared 3 GiB reserve. An upload that does not fit returns 413 with `upload is larger than the free disk space allows`. Werkzeug's multipart file streams, route request directories (`inf2005-encode-*`, `inf2005-capacity-*`, and `inf2005-stego-*`), and converted source snapshots use `STEGO_WORK_DIR`. The default is `instance/work`, on the same filesystem as outputs; do not use `/tmp`, which is a tmpfs RAM disk on this host. Key files have a 64 KiB limit. Other uploads have no fixed application size cap by default, but the free-space guard, configured `MAX_CONTENT_LENGTH`, and backend limits still apply. Backend video limits are:

| Limit | Value | Refusal |
| --- | ---: | --- |
| Carrier units | 512 Gi units | Library capacity/limit message, HTTP 400 |
| Canonical decoded frame | 256 MiB | `video frame exceeds configured frame-byte limit`, HTTP 400 |
| Encoded Matroska output | 1280 GiB (1.25 TiB) | `video output exceeds configured byte limit`, HTTP 400 |
| Free disk before encode | 3 GiB reserve, plus payload size for payload-file encoding | `insufficient free disk space for video output`, HTTP 400 |
| Free disk before each mux write | 3 GiB reserve, packet size, and 1 MiB mux slack | `insufficient free disk space for video output`, HTTP 400 |

Image and audio output checks run before the output write. The PNG check uses twice the PNG bound for the encoder temporary and final PNG; payload-file encoding also includes the payload size. The WAV check uses the source file size. These checks keep the shared 3 GiB reserve. Video encoding checks free space before each Matroska packet write. It requires the 3 GiB reserve, the packet size, and 1 MiB of mux slack. A failed check closes and removes the staged output; the route returns HTTP 400 and does not publish a file. The output-size limit is still checked after each packet. For large-video resource limits and recommended demonstration sizes, see [Video Carrier Design](VIDEO-CARRIER-DESIGN.md#output-and-limits).

The optional fixed request cap and the upload free-space guard return 413. `create_app(test_config)` can override the work directory and request cap. `TemporaryDirectory` removes request files and source snapshots on normal success or failure; there is no stale-directory sweeper. A client disconnect or timeout does not cancel a running Flask/PyAV job. The application has no job-cancellation or idempotency-key support. The browser never retries encode or decode POST requests automatically; a manual retry can start a second job and create another output. Encoded carriers and recovered payloads remain in their output directories until users delete them. Private `.stego-staging-*` directories are removed on normal exits. Power loss or `SIGKILL` can leave request or unauthenticated plaintext staging; stop the server and remove these directories manually after a crash. See [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#cleanup-rule).

`/keys/generate` is a local setup helper for sender or receiver keys. Its `key_password` field is optional; an empty value returns an unencrypted private key. A non-empty password must have at least 8 characters. The browser warns that an unencrypted private key is for demos only because anyone with the file can use it. Deployment beyond trusted localhost still needs key storage and access controls, key rotation, transport protection, and auditing.

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
| FR9 hash verification | Implemented | The receiver hashes masked RGB units, RGBA alpha, declared PCM sample bytes, and canonical video/audio data without the original cover. |
| FR10 verdict generation | Implemented | Protocol verdicts are returned without weaker web-specific substitutes. |
| FR11 positive and negative cases | Demonstrated and tested | The notebook shows positive PNG/WAV runs and negative image/audio verdicts, capacity refusals, all LSB counts, and file-payload cases. Tests add wrong-key, tampering, MIME mismatch, invalid-input, upload-limit, and other edge coverage. |
| FR12 evidence and reproducibility | Partly implemented | Setup, tests, GUI, and an executable notebook provide repeatable evidence; the demonstration is complete. The submission package still needs the demonstration files and assignment-only keys, test evidence, and key instructions. |
| FR13 innovation | Candidate implemented | Receiver-gated location confidentiality and encrypted typed payloads are available; the team must finalize its explanation. |

## Tests and limits

Run `python -m unittest -v`. `test_webapp.py` covers the Flask request/response pipeline; `test_stego.py` covers protocol, image/audio source conversion, and negative verdicts; `test_video.py` covers the video carrier. A wrong receiver key and an absent payload intentionally share one result. Authenticity depends on the sender public key supplied by the receiver. PNG ancillary chunks and WAV chunks outside declared samples are not covered; overwritten LSBs cannot be recovered or authenticated. Version 3 media-hash limits are listed in [Current Protocol](CURRENT-PROTOCOL.md#limits-and-compatibility).

## Three.js carrier map

**Status: Not connected.** The map assets exist, but the active GUI does not load them. `POST /layout/estimate` returns a controlled 503 because the estimator service is not implemented. Manual `start_unit` entry is the only working layout control.

### Current state

The repository contains `stego_web/static/stego-map.js`,
`stego_web/static/stego-map-geometry.js`, and locally bundled Three.js files
under `stego_web/static/vendor/three/`. `VERSION.txt` records version 0.180.0
(`r180`) and the upstream source. The vendor directory includes its upstream
MIT `LICENSE`.

`index.html` does not load these map assets, and the template does not contain
the controls that the map module expects. The active six-step wizard uses the
manual `start_unit` field in Step 4. Therefore, the Three.js map,
click-to-select behavior, footprint overlays, hover inspector, and difference
view are not active GUI features. The source files describe an intended map;
they do not prove a working interface.

### Known gaps

- The map module is intended to post the cover, receiver key, payload, metadata,
  `start_unit`, and LSB count to `POST /layout/estimate`. The estimator does not
  exist in `CurrentProtocolService`. The route reports this explicitly with
  HTTP 503 instead of attempting the missing call.
- `index.html` does not load `stego-map.js` and does not contain the map
  controls.
- The map and geometry assets have no active integration test in
  `test_webapp.py`.

`POST /encode` remains the active validation path.

### Intended geometry (design notes)

These notes describe the intended map. They are not active behavior until the
gaps above are fixed.

An RGB PNG contributes three carrier units per pixel. For a pixel at `(x, y)`:

```text
pixel_index = y * width + x
start_unit = pixel_index * 3
total_units = width * height * 3
```

Map clicks select the first channel of a pixel. Manual entry can select any
exact carrier unit. Units 0–2,047 are reserved for the receiver bootstrap.
Unit 2,048 is the third channel of pixel 682, so the first whole-pixel map
selection would be unit 2,049.

The packet is one contiguous carrier-unit range. The client maps that range to
at most three row rectangles: a partial first row, a block of complete rows,
and a partial final row. WAV covers use linear sample units, not the image map.

The estimate response is intended to contain non-secret layout information
only: carrier dimensions, unit counts, packet footprint, payload capacity,
remaining units, usage, and preserved-bit ratio. `POST /encode` repeats all
validation and is authoritative.
