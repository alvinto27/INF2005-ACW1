# INF2005-ACW1

This project is a localhost Flask application for encrypting, signing, embedding,
decoding, and verifying payloads with protocol version 3 from the `stego`
package. The primary carriers are 8-bit or 16-bit RGB/RGBA PNG and uncompressed
PCM WAV. The library and Flask web app also support a video carrier. The web app
accepts common image and audio sources and rewrites video covers to lossless
FFV1/PCM Matroska (`.mkv`) before embedding.

The protocol encrypts the complete payload record with AES-256-GCM, authenticates
the ciphertext and embedding geometry with RSA-PSS, and encrypts a bootstrap to
the intended receiver with RSA-OAEP. [Protocol](docs/protocol.md)
defines the media hash and verification rules. Container and ancillary metadata
are outside the authenticity check; output metadata behavior is in [Carrier and
payload flow](docs/carrier-and-payload-flow.md#metadata-in-the-output).
The protocol carrier accepts single-frame 8-bit or 16-bit RGB/RGBA PNG images,
with a decoded image size limit of 715,827,880 bytes.

Requires Python 3.12+ because NumPy 2.5.3 requires it.

## For markers

### Quick start

Requires Python 3.12 or later.

Linux and macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`. The encode page is `/`; the verify page is `/verify`.

### Expected test output

- `python -m unittest` → `Ran 308 tests ... OK`; one subtitle test is skipped if the FFmpeg command-line tool is not installed (`OK (skipped=1)`).
- `node --test scripts/test-api-js.cjs scripts/test-capacity-js.cjs` → 15 tests pass.

### Folder guide

| Path | Contents |
| --- | --- |
| `stego/` | Protocol and carrier library. |
| `stego_web/` | Flask application, web pages, and browser code. |
| `run.py` | Local Flask application entry point. |
| `test_*.py` | Python protocol, carrier, and web tests. |
| `notebooks/` | End-to-end demonstration notebook. |
| `presentation/` | Technical-design slides and PDF export. |
| `demo/` | Instructions for files supplied in the separate demonstration ZIP. |
| `docs/` | Design and protocol guides, assignment brief. |
| `scripts/` | Documentation checker and JavaScript tests. |

### Requirement coverage

For requirement evidence, see the [requirement coverage table](docs/web-application.md#requirement-coverage).

**Expected verdicts:** `Authentic`, `Tampered`, `Signature Invalid`, `Payload Missing`, `Wrong Start Location`, `Cannot Decrypt`, and `Cannot Verify`. See [verification verdicts](docs/protocol.md#verification-verdicts).

## Setup and run

```sh
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`. Run all automated checks with:

```sh
python -m unittest -v
python scripts/check-docs.py
```

CI runs these commands on Python 3.12, 3.13, and 3.14. It also runs the
dependency-free browser-request and capacity-helper tests; run them locally if
Node is available:

```sh
node --test scripts/test-api-js.cjs scripts/test-capacity-js.cjs
```

The optional demonstration notebook additionally needs:

```sh
python -m pip install -r requirements-notebook.txt
```

The notebook is a human-readable, human-verifiable proof of the end-to-end flow.
It runs the sender and receiver steps in order. Each step states what to expect
and prints the evidence beside it, so a reader can check the result without
reading library code. It demonstrates PNG (including 16-bit RGB), RGBA and WAV
encoding and verification, failure verdicts, typed payloads, PNG/WAV payload-file
flows, assignment payload sizes, all LSB counts from 1 through 8, JPEG-to-PNG and
MP3-to-WAV conversion, and a short 8-bit video example. It also simulates
low-space, audio-depth, RIFF-size, and video mux-space refusals without creating
large files, and prints video limits and cost estimates. Party A-to-Party B
transfer is a folder simulation.

The notebook does not show every feature. Tests and the guides in `docs/`
cover details it omits, including the decoded-PNG size cap, metadata and EXIF
handling, refused source formats, high-bit-depth and alpha video, video
payload-file functions, and the web application. The notebook's storage and
limit refusals are safe simulations, not tests at the real maximum sizes. The
tests prove individual rules and edge cases. The library code, tests, and guides
are the reference for exact API contracts.

## Web application flow

Encoding requires:

1. a still PNG, JPEG, WebP, AVIF, BMP, TIFF, or GIF image; WAV with a `pcm_*` codec; MP3; AAC ADTS; M4A with AAC or ALAC; FLAC; Ogg with Vorbis or Opus; or video in MP4/MOV, Matroska/WebM, or AVI with one decodable video stream and zero or one audio stream. Audio-only Matroska/WebM is refused. The output is lossless PNG, WAV, or FFV1/PCM Matroska (`.mkv`);
2. either a UTF-8 message or one arbitrary payload file, plus required team ID and sender values; its MIME and filename claims are generated automatically from the selected input and are read-only in the browser; the server ignores submitted claim overrides;
3. a sender RSA private key; its password is optional. Leave it empty for an unencrypted key. Unencrypted keys are for demos only;
4. the intended receiver's RSA public key;
5. a packet start unit at or after the 2,048-unit RSA-2048 bootstrap span; and
6. an LSB count from 1 through 8.

The server validates the inputs, converts non-strict sources once to a canonical
PNG or WAV snapshot in the request temporary directory, and saves uploaded payload
files to a private request-scoped temporary file (or writes a short message there).
It constructs typed authenticated metadata, builds the full media hash, encrypts and signs the payload
record, embeds the receiver bootstrap and packet, and returns the stego media plus
the sender public key. Payload bytes are processed in bounded chunks.

Verification accepts the received PNG, WAV, or Matroska video stego file, the
trusted sender public key, and the intended receiver private key. Its password is
optional; leave it empty for an unencrypted key. Unencrypted keys are for demos only.
The receiver bootstrap recovers the start unit, LSB count, record length, and
AES session material.
The original cover and the previous shared start-location secret are not inputs.

After an `Authentic` result, the protocol writes only the recovered payload to a
private temporary file, then publishes it in `instance/recovered-payloads` and
returns a download URL. It checks MIME signatures and text UTF-8 in bounded reads.
The browser previews text, PNG, JPEG, GIF, WebP, AVIF, BMP, WAV, MP3, Ogg,
FLAC, MP4, and WebM only when the signed MIME claim agrees with a bounded
signature check of the recovered bytes. Video payloads use a native controls
player. SVG, HTML, XML, PDF, Matroska, and other non-allowlisted formats remain
download-only. The verify JSON returns a URL, not payload bytes. These recovered
files stay without an expiry. Delete them manually. Anyone
who can read the server's instance folder can read the recovered payloads.

Payload verification uses temporary files under `.stego-staging-*` directories.
Normal exits remove them. A power loss or `SIGKILL` can leave unauthenticated
plaintext in these private directories. After a crash, stop the server and
manually delete `.stego-staging-*` directories under the instance folder.

The local server has no fixed request-size cap by default. It requires
`Content-Length` and keeps a shared 3 GiB free-space reserve before it reads an
encode or verify upload. It stores multipart streams and request temporary files
under `instance/work`, not `/tmp` (a RAM-backed tmpfs on this host). A configured
`MAX_CONTENT_LENGTH` still applies. A WAV file larger than 2 GiB can fail to open
in some older audio programs because they read the WAV size field as signed;
the application reads it correctly. See the [Web Application Guide](docs/web-application.md) for request
and storage behavior. Video resource limits and large-file warnings are in the [video
carrier design](docs/video-carrier.md#output-and-limits).
Encoded PNG, WAV, and MKV files are stored in `instance/stego-outputs` and
returned by download URL, not as base64. Files do not expire; delete them when
they are no longer needed.

## Protocol API

The public Python API includes `encode_png`, `verify_png`, `encode_wav`,
`verify_wav`, `PngCarrier`, `WavCarrier`, `VideoCarrier`, `encode_video`, and
`verify_video`. It also includes the source helpers `open_image_source`,
`open_audio_source`, `detect_source_family`, `encode_image`, and `encode_audio`,
plus their payload-file variants. The core provides PNG, WAV, and video
payload-file encode and verify functions. Source converters accept only the
listed still-image signatures and the fixed audio/video container and codec
allowlist above. Converted audio has one or two channels. They create temporary canonical PNG/WAV carriers;
strict PNG and PCM WAV inputs bypass conversion. Strict PCM WAV carriers accept
any positive channel count. Converted snapshots are removed
when the context or encode call ends. CMYK images are refused because a CMYK ICC
profile is not valid on an RGB PNG, and colour-managed conversion needs a library
outside PyAV. See [Source conversion](docs/carrier-and-payload-flow.md#source-conversion).

Verification requires the sender public key and receiver private key. The
file-backed carriers provide bounded range reads, chunk iteration, and
sequential rewrites. `WavCarrier` reads whole PCM frames, so carrier working
memory does not grow with the WAV size.

The video API includes `VideoCarrier`, `encode_video`, `verify_video`,
`encode_video_from_payload_path`, and `verify_video_to_payload_path`. The Flask
web app also accepts supported video covers and verifies `.mkv` outputs. Video
encode writes lossless FFV1 video and PCM audio to Matroska; this output can be
much larger than the compressed input and browsers do not play it inline.
See the [video carrier design](docs/video-carrier.md#output-and-limits)
for carrier-unit, canonical frame-byte, output-size, and disk-space limits. PyAV is a
required install dependency in `requirements.txt`; PNG, WAV, and video I/O use PyAV.
Pillow is used only by tests and the demonstration notebook. The public
`CarrierSource` abstraction and `prepare_carrier_encoding` /
`decode_carrier_source` entry points support backend-level operations. The public
`lsb_range_transform` helper prepares LSB changes for a carrier range. For example:

```python
layout, payload = encode_png(
    "cover.png",
    "stego.png",
    sender_private_key,
    receiver_public_key,
    2048,
    3,
    b"message",
    b"mime=text/plain;name=message.txt",
)
result = verify_png("stego.png", sender_public_key, receiver_private_key)
```

All serialised protocol integers use unsigned 64-bit big-endian fields. Existing
version 1 and version 2 masked-media files are not accepted by the active
version-3 web routes. A readable version 2 bootstrap returns `Cannot Verify`
with `unsupported bootstrap version`. The separate legacy `STG1` implementation
has been removed and is not interoperable with this protocol. See [Protocol
Compatibility](docs/protocol.md#limits-and-compatibility) and [Repository
History](docs/history/repository-history.md).

## Documentation

- [Protocol](docs/protocol.md)
- [Web application](docs/web-application.md)
- [Carrier and payload flow](docs/carrier-and-payload-flow.md)
- [Video carrier](docs/video-carrier.md)
- [Known limitations](docs/known-limitations.md)
- [Protocol history](docs/history/protocol-history.md) and [repository history](docs/history/repository-history.md)
- [Technical-design presentation](presentation/README.md)
- [Assignment brief](docs/assignment/INF2005-ACW1-spec_v5-f2f.md)
