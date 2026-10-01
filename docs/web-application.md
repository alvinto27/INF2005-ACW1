# Web application

This guide explains how the local Flask application behaves: what the two pages do, what each route accepts and returns, how recovered payloads are previewed safely, where files are stored, and where each assignment requirement is met. The [protocol guide](protocol.md) covers the wire format and cryptography, and [carrier and payload flow](carrier-and-payload-flow.md) covers how files are read and written.

## How the code fits together

`run.py` creates the Flask app from `stego_web`. The routes in `stego_web/routes.py` call `stego_web/services/current_protocol.py`, a thin adapter over the public file-based API in `stego`. All cryptographic and integrity decisions stay in the `stego` library; the web layer only validates inputs and turns results into JSON. PyAV handles all image, audio, and video input and output at runtime; the application does not use Pillow. In the browser, `stego_web/static/app.js` drives the encode wizard and `stego_web/static/verify.js` drives the verify page.

## The two pages

**The encode page (`GET /`)** has a dark navigation bar, a hero section, four animated diagrams, and a light workspace that holds the wizard. The diagrams show carrier embedding, receiver-only encryption, the signature and media-hash checks, and the final verdict. They are inline, decorative SVGs, so they need no image downloads or WebGL. The page links to `/verify` from its header and hero.

**The verify page (`GET /verify`)** is for the receiver. It has a white outer page with a blue form workspace.

Both pages use the full browser width. Moving between them plays a short fade; without JavaScript the link still works as a normal link, and the fade is skipped for users who prefer reduced motion.

### The encode wizard

The wizard has six steps: Input, Sender, Receiver, Layout, Protect, and Export.

- In **Layout**, the capacity result sets the range of a start-unit slider for the chosen LSB count. The range runs from the end of the bootstrap area to the latest start that still fits. A number box beside the slider stays in sync and is what the form actually sends as `start_unit`.
- In **Protect**, the server hashes the preserved media data (the masked RGB units, RGBA alpha, and the PCM sample bytes) using the chosen layout, then encrypts and signs the record.

On desktop, the feature diagrams sit in four columns, dropping to two on tablets and one on phones. Forms and media previews also stack on narrow screens.

### Accessibility

Each page has a skip link to its form. File inputs are the browser's native controls, so they work from the keyboard. The current wizard step is marked with `aria-current`, and changing step moves focus to the new heading. Labels, visible focus outlines, live progress messages, and text verdicts (not just colours) support keyboard and screen-reader users.

### Animation and the one external request

Animations use GSAP 3.15, loaded from `https://cdn.jsdelivr.net`. This is the only request the app makes outside your machine. If GSAP cannot load, or reduced motion is turned on, `motion.js` skips it and a small local helper keeps everything working. The workflow does need JavaScript itself, and a `noscript` notice says so.

### Requests from the browser

Both pages send requests through `api.js`. It checks that each JSON response has the expected shape, turns HTTP status codes and connection failures into readable messages, and applies time limits:

| Request | Time limit |
| --- | --- |
| Encode (image or audio) | 5 minutes |
| Encode (video) | 1 hour |
| Key generation | 1 minute |
| Verify | 2 minutes, or 30 minutes for MKV |

While an encode is running, its form inputs are frozen. If encode or key generation fails, the controls stay usable so you can try again. Before showing success, the browser checks the response fields and that each download link points back to the same server.

## Encode request

`POST /encode` creates a stego file. The cover can be:

- a still image: PNG, JPEG, WebP, AVIF, BMP, TIFF, or GIF;
- audio: WAV with a `pcm_*` codec, MP3, AAC (ADTS), M4A (a MOV/MP4-family container) with AAC or ALAC, FLAC, or Ogg with Vorbis or Opus; or
- video: MP4/MOV, Matroska/WebM, or AVI, with one decodable video stream and zero or one audio stream. Audio-only Matroska/WebM is refused.

The browser's file picker uses the same list as the server. Along with the cover, the request carries:

- either a text message or a payload file;
- `team_id` and `sender` (both required), plus optional extra metadata;
- the sender's private key and its optional password;
- the receiver's public key; and
- a start unit and an LSB count from 1 to 8.

Each key file can be up to 64 KiB. The payload's MIME type and file name are filled in from the chosen message or file and shown as read-only fields. The server ignores any `payload_mime` or `payload_name` the browser sends and works out its own values before signing them, so the signed claims cannot be set by hand.

The key password is optional; leave it empty for an unencrypted private key. A non-empty password must be at least 8 characters and is used exactly as typed. Unencrypted private keys are for demos only, because anyone who has the file can use the key.

### What happens to the upload

Flask saves each request's uploads and working files in `STEGO_WORK_DIR`, which defaults to `instance/work`. Werkzeug's multipart upload streams go there too. We keep them on the instance filesystem rather than in `/tmp`, because on some systems `/tmp` lives in RAM and a large upload or video snapshot would use up memory. The request deletes its temporary folder whether it succeeds or fails. The PNG encoder writes a temporary `.stego-staging-*.png` beside the output and removes it once the write is done.

The server then decides how to read the cover. PNG files are recognised by their file signature, WAV files by their codec, and other formats by inspecting their PyAV streams; `detect_source_family()` then picks the image, audio, or video adapter. Strict PNG and PCM WAV covers skip conversion and keep their existing ancillary data. Everything else is converted first, as described in [Carrier and Payload Flow](carrier-and-payload-flow.md#source-conversion), which also lists the conversion limits and temporary-storage checks.

For images and audio, the adapter calls `open_image_source()` or `open_audio_source()` and passes the resulting `carrier_source` to the PNG or WAV file API. Video works differently: the video API builds its own `VideoCarrier` to validate, count, and read the source in bounded chunks, then writes lossless FFV1/PCM Matroska. Video sources are therefore always reported as converted. The video resource limits are in [Video Carrier](video-carrier.md#output-and-limits).

A note on large audio: a converted WAV larger than 2 GiB is allowed, but not advised. Some older audio programs cannot open it, because they read the WAV size field as a signed number (StegoVerify reads it correctly). Such a file also needs about 8 GiB of free disk during encoding, for the converted copy plus the output, and is too large to send by email.

### The response

The JSON response includes `source_converted`, `source_format` (based on the container), the output `file_size`, a `stego_url`, file details, the sender's public key, a record summary, capacity, the layout, and preserved-bit measurements. It never contains the stego bytes or any private key. `GET /download/<id>.<ext>` checks the token and the extension before serving the file. MKV files are always served as downloads, because browsers cannot play FFV1 Matroska inline.

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

When the user leaves the Input step, the browser sends one capacity request with the cover and a description of the payload, not the payload itself. It reuses that result until one of those inputs changes. On the Layout step, the user picks the LSB count first. The result then sets the start-unit slider's range, from the bootstrap span up to the latest start that fits at that LSB count. The number box beside it allows exact values when the slider is too coarse. While the chosen start fits, no status message is shown. If an LSB change makes the start too large, the page moves it and shows `Start moved to <n>, the latest start that fits at LSB <k>.` If no start fits at the selected LSB, it disables both start controls and suggests the smallest LSB that fits with `Does not fit at LSB <k>. Try LSB <m>.` `/encode` still has the final say.

| Condition | HTTP status | Body |
| --- | --- | --- |
| The estimate succeeds | 200 | JSON with `ok`, protocol version, carrier details, and capacity results |
| A required value is missing, duplicated, invalid, or the cover is unsupported or unreadable | 400 | JSON with `ok: false` and `error` |
| The request has no `Content-Length` header | 411 | JSON with `ok: false` and `error` |
| The request exceeds a configured size limit or a disk-space guard refuses the upload copy | 413 | JSON error |
| A storage or read failure occurs | 500 | Generic JSON error; the server logs the exception |

A capacity result is only an estimate. The browser reports the payload size itself, and the cover could change after the check. `/encode` is the real authority: it checks the keys, builds the payload record, and writes and validates the stego file.

## Decode request

`POST /decode` requires three multipart fields and accepts one optional password field:

- `stego`: one 8-bit or 16-bit RGB/RGBA PNG, uncompressed PCM WAV, or an EBML Matroska video carrier (`.mkv`);
- `sender_public_key`: the trusted sender RSA-2048 public PEM;
- `receiver_private_key`: the intended receiver's RSA-2048 private PEM, encrypted or unencrypted; and
- `receiver_key_password`: optional; leave it empty for an unencrypted private key.

The same password rules apply as for encoding, and each key file can be up to 64 KiB.

Notice what the request does *not* include: the media type, the LSB count, the start unit, the record length, a shared secret, or the original cover. The receiver does not need to know any of these, because the bootstrap supplies the layout and the AES session key. Flask stores the upload in the work directory and calls `verify_png_to_payload_path`, `verify_wav_to_payload_path`, or `verify_video_to_payload_path` based on the carrier family.

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

Verification runs in a fixed order:

1. Read and open the bootstrap, then check that its fields and bounds make sense.
2. Read the packet at the recovered location and check its padding.
3. Verify the RSA-PSS signature, before any decryption.
4. Decrypt with AES-GCM and parse the record.
5. Check the version 3 media hash last.

There is exactly one bootstrap, and the verifier never searches for another packet. All cryptographic and integrity decisions are made in `stego/core.py`; Flask only validates inputs and turns the result into JSON.

## Result and payload handling

These `/encode` response fields describe the source and the payload claims:

| Field | Meaning |
| --- | --- |
| `source_converted` | `true` when a source was converted to canonical PNG/WAV or rewritten as FFV1/PCM Matroska; strict PNG and PCM WAV return `false`. |
| `source_format` | Detected source label, such as `jpeg`, `mp3`, `m4a`, `ogg-opus`, `png`, `wav`, `mp4`, `matroska`, `webm`, or `mov`. |
| `file_size` | Encoded output size in bytes. |
| `payload.mime` | The final MIME claim sealed in the authenticated metadata. |
| `payload.name` | The final filename claim sealed in the authenticated metadata. |

The browser shows a short conversion note, for example: “Your JPEG source was converted to a lossless PNG before embedding.”

A `/decode` report includes the verdict and its detail, carrier type and size, protocol version, recovered start unit and LSB count, signature and integrity state, sender-key fingerprint, preserved-bit count and ratio, and authenticated record fields.

A `null` field means verification did not reach that step or did not recover that value, which is different from `false`. If a later step fails, the fields recovered before the failure are still filled in:

| Field | Set when |
| --- | --- |
| `frame_version` | The receiver private key opened the bootstrap. The value is the version byte read from the received bootstrap, not the version of this application. A readable version 2 bootstrap gives `2`. |
| `start_location`, `lsb_bits` | The bootstrap was opened and its fields were valid. |
| `preserved_bits`, `preserved_ratio` | The recovered geometry fits the carrier. `Wrong Start Location` leaves them `null`. |
| `sender_key_fingerprint` | The service loaded the supplied sender public key and called the library. It identifies the supplied key, not a recovered value. |
| `payload` | The verdict is `Authentic`. Other verdicts never give payload fields, a payload file, or a `payload_url`. |

For example, `Signature Invalid`, `Cannot Decrypt`, and `Tampered` keep `frame_version` 3, the start location, the LSB count, and the preserved bits. `Payload Missing` and the 400 and service-level `Cannot Verify` responses have `frame_version` `null`. The browser shows the bootstrap as opened only when `frame_version` is not `null`.

Only an `Authentic` result includes a `payload_url` and the parsed payload metadata. The library writes the authenticated payload to `instance/recovered-payloads` in one atomic step, and the route saves a small sidecar file beside it with `download_name`, `serve_mime`, and `preview_allowed`. If the sidecar cannot be written, the payload is deleted. The response carries a link to the payload, never the payload bytes or a Base64 copy.

To decide whether a payload can be previewed, the service reads at most its first 4 KiB; it never decodes the media. It allows an inline preview only when the metadata is unambiguous, the declared MIME agrees with recognized bytes, and the MIME is in this allowlist:

| Preview | MIME types |
| --- | --- |
| Text | `text/plain` (checked as UTF-8 in bounded chunks) |
| Images | `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/avif`, `image/bmp` |
| Audio | `audio/wav`, `audio/mpeg`, `audio/ogg`, `audio/flac`, `audio/mp4`, `audio/webm` |
| Video | `video/mp4`, `video/webm`, `video/ogg` |

Allowed media is shown with the browser's own image, audio, and video elements. Text previews are capped at 1 MiB; longer authenticated text can still be downloaded. Reading a text preview is bounded and times out after 30 seconds, with a retry button if it fails.

WebM is always sniffed as `video/webm`, to be on the safe side, so a payload that claims to be audio-only WebM does not match and stays download-only. Matroska, SVG, HTML, XML, PDF, and any other type not in the table are download-only too.

A false MIME claim that the sender signed does not change the cryptographic verdict, since the signature only proves who made the claim. The payload is saved but not rendered. The browser also inserts all response text with `textContent` (never as HTML), blocks duplicate submits, and handles malformed JSON and network failures.

`GET /payload/<id>` validates the token and sidecar, sets a safe MIME type and download name, and applies `nosniff`, a restrictive Content Security Policy, and `Cache-Control: no-store`. Files never expire. Recovered payloads are stored as plain, unencrypted files, so anyone who can read the `instance/` folder can read them. Running the app anywhere other than a trusted localhost would need operating-system access controls on that folder.

## Errors and storage

The `POST /encode` status rules are:

| Condition | HTTP status | Body |
| --- | --- | --- |
| The request has no `Content-Length` header | 411 | JSON `error` |
| Missing or duplicate fields/files, unsupported or unreadable source, source conversion refusal, invalid or oversized key files, key/password encryption mismatch, short non-empty password, or layout/capacity failure | 400 | JSON `error`; known source failures keep the library message |
| Upload exceeds a configured request limit, fails the request free-space guard, or fails the per-upload free-space check before a route copies it | 413 | JSON error |
| Storage or unexpected server failure | 500 | Generic JSON error without filesystem details; server logs the exception |

Source files refused with HTTP 400 include CMYK images, animated images, floating-point or over-16-bit images, the image decoded-byte cap, converted PCM size limit, unsupported video pixel formats, more than two audio channels in converted sources, unsupported lossless audio sample depths, and extra video/audio/subtitle/data streams. The fixed source allowlist also refuses AIFF, WMA, audio-only Matroska/WebM, JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, and other unlisted formats with a specific or generic source-format reason. A decode failure in an allowed format says the file could not be decoded and may be damaged. Strict PCM WAV carriers accept any positive channel count. Video backend messages are returned for carrier-unit, frame-byte, free-space, and output-size limit failures. The source converter turns RGB PNG `tRNS` colour-key transparency into RGBA alpha. The strict PNG adapter still refuses that input when it is used directly.

`/decode` accepts PNG, PCM WAV, and Matroska video; its status codes are listed under [Decode request](#decode-request). If the route cannot store the sidecar for an `Authentic` payload, it removes the payload and returns HTTP 500 with verdict `Cannot Verify`. Unexpected errors are logged and return a generic HTTP 500. Werkzeug's own statuses, such as 404, 405, and 413, are passed through unchanged.

### Upload size and disk space

By default `MAX_CONTENT_LENGTH` is `None`, so there is no fixed request size cap, although tests and deployments can set one. Before Flask reads an encode, decode, or capacity body, it requires `Content-Length`; a missing header returns 411. It compares the declared length with free space in `STEGO_WORK_DIR` minus the shared 3 GiB reserve. An upload that does not fit returns 413 with `upload is larger than the free disk space allows`. Werkzeug's multipart file streams, route request directories (`inf2005-encode-*`, `inf2005-capacity-*`, and `inf2005-stego-*`), and converted source snapshots use `STEGO_WORK_DIR`. The default is `instance/work`, on the same filesystem as the outputs (see [What happens to the upload](#what-happens-to-the-upload) for why). Key files have a 64 KiB limit. Other uploads have no fixed application size cap by default, but the free-space guard, configured `MAX_CONTENT_LENGTH`, and backend limits still apply. The video backend has these limits:

| Limit | Value | Refusal |
| --- | ---: | --- |
| Carrier units | 512 Gi units | Library capacity/limit message, HTTP 400 |
| Canonical decoded frame | 256 MiB | `video frame exceeds configured frame-byte limit`, HTTP 400 |
| Encoded Matroska output | 1280 GiB (1.25 TiB) | `video output exceeds configured byte limit`, HTTP 400 |
| Free disk before encode | 3 GiB reserve, plus payload size for payload-file encoding | `insufficient free disk space for video output`, HTTP 400 |
| Free disk before each mux write | 3 GiB reserve, packet size, and 1 MiB mux slack | `insufficient free disk space for video output`, HTTP 400 |

For images and audio, the free-space check runs once, before the output is written. The PNG check uses twice the PNG bound for the encoder temporary and final PNG; payload-file encoding also includes the payload size. The WAV check uses the source file size. These checks keep the shared 3 GiB reserve. Video encoding checks free space before each Matroska packet write. It requires the 3 GiB reserve, the packet size, and 1 MiB of mux slack. A failed check closes and removes the staged output; the route returns HTTP 400 and does not publish a file. The output-size limit is still checked after each packet. For large-video resource limits and recommended demonstration sizes, see [Video Carrier](video-carrier.md#output-and-limits).

### Cleanup and long-running jobs

The optional fixed request cap and the upload free-space guard return 413. `create_app(test_config)` can override the work directory and request cap. `TemporaryDirectory` removes request files and source snapshots on normal success or failure; there is no stale-directory sweeper. A client disconnect or timeout does not cancel a running Flask/PyAV job. The application has no job-cancellation or idempotency-key support. The browser never retries encode or decode POST requests automatically; a manual retry can start a second job and create another output. Encoded carriers and recovered payloads remain in their output directories until users delete them. Private `.stego-staging-*` directories are removed on normal exits. Power loss or `SIGKILL` can leave request or unauthenticated plaintext staging; stop the server and remove these directories manually after a crash. See [Carrier and Payload Flow](carrier-and-payload-flow.md#cleanup-rule).

### Key generation

`/keys/generate` is a local setup helper for sender or receiver keys. Its `key_password` field is optional; an empty value returns an unencrypted private key. A non-empty password must have at least 8 characters. The browser warns that an unencrypted private key is for demos only, because anyone with the file can use it. Running this beyond a trusted localhost would still need key storage and access controls, key rotation, transport protection, and auditing.

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
| FR12 evidence and reproducibility | Implemented | Setup instructions, automated tests, the GUI, and an executable notebook give repeatable evidence. The demonstration files, verdict screenshots, and assignment-only keys go in [demo/](../demo/README.md), with steps to reproduce each verdict. |
| FR13 innovation | Implemented | Only the intended receiver can find the payload, because its location and depth are sealed in an RSA-OAEP bootstrap. The whole record, including typed file payloads, is encrypted, and an optional lossless video carrier is supported. |

## Tests and limits

Run `python -m unittest -v`. `test_webapp.py` covers the Flask request/response pipeline; `test_stego.py` covers protocol, image/audio source conversion, and negative verdicts; `test_video.py` covers the video carrier. A wrong receiver key and a missing payload give the same result, because without the right key an encrypted bootstrap cannot be told apart from ordinary cover bits. Authenticity depends on the sender public key supplied by the receiver. PNG ancillary chunks and WAV chunks outside declared samples are not covered; overwritten LSBs cannot be recovered or authenticated. Version 3 media-hash limits are listed in [Protocol](protocol.md#limits-and-compatibility).
