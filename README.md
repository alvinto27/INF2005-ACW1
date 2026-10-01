# StegoVerify — INF2005 ACW1

StegoVerify hides a signed, encrypted payload inside an image, an audio file, or a video, and later checks whether that file is still authentic. It is a Flask web application that runs on your own machine, backed by a Python library (`stego/`) that implements our masked-media protocol, version 3.

In short, the sender:

1. encrypts the whole payload record with **AES-256-GCM**,
2. signs the ciphertext and its embedding position with **RSA-PSS**, and
3. hides a small **RSA-OAEP** "bootstrap" that only the intended receiver can open. The bootstrap tells the receiver where the rest of the payload starts and how many low bits it uses.

The receiver needs only the stego file, the sender's public key, and their own private key. They do not need the original cover file or a shared secret. Verification ends in one clear verdict, such as `Authentic` or `Tampered`.

## For markers

| To check | Go to |
| --- | --- |
| That it runs | [Quick start](#quick-start), then [Running the tests](#running-the-tests) for the expected output |
| Where each requirement is met | [Requirement coverage](docs/web-application.md#requirement-coverage) |
| The demonstration files and keys | [`demo/`](demo/README.md) |
| The end-to-end flow, step by step | The [demonstration notebook](#demonstration-notebook) |
| The design and its reasoning | The [slides](presentation/README.md) and the [documentation](#documentation) |
| What it does not claim | [Known limitations](docs/known-limitations.md) |

## Quick start

You need **Python 3.12 or later** (NumPy 2.5.3 requires it).

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

Then open <http://127.0.0.1:5000>. The encode page is at `/` and the verify page is at `/verify`. The server listens on localhost only and is meant for local use, not public hosting.

## Running the tests

```sh
python -m unittest
node --test scripts/test-api-js.cjs scripts/test-capacity-js.cjs
python scripts/check-docs.py
```

Expected results:

| Command | Expected output |
| --- | --- |
| `python -m unittest` | `Ran 308 tests ... OK`. One subtitle test is skipped if the FFmpeg command-line tool is not installed, which shows as `OK (skipped=1)`. |
| `node --test ...` | 15 tests pass. These cover the browser's request handling and capacity helpers, and need only Node.js. |
| `python scripts/check-docs.py` | No broken links in the Markdown documentation. |

GitHub Actions runs all three on Python 3.12, 3.13, and 3.14.

## Using the web application

### Encoding (protecting a file)

The encode page is a six-step wizard:

1. **Choose the cover and the hidden payload.** The cover can be:
   - an image: PNG, JPEG, WebP, AVIF, BMP, TIFF, or GIF (still images only);
   - audio: PCM WAV, MP3, AAC (ADTS), M4A with AAC or ALAC, FLAC, or Ogg with Vorbis or Opus;
   - video: MP4/MOV, Matroska/WebM, or AVI, with one video stream and at most one audio stream.

   The payload is either a text message or any single file. You also enter a team ID and a sender name. The app fills in the payload's MIME type and file name itself, and the server works these out again rather than trusting the browser.
2. **Load the sender's signing key** (an RSA private key). The page can generate a key pair for you. A key password is optional, but keys without a password are only suitable for demos.
3. **Select the intended receiver** by loading their RSA public key.
4. **Choose the layout**: the start unit for the payload (it must come after the 2,048-unit bootstrap area) and the number of least-significant bits to use, from 1 to 8. The page warns you early if the payload will not fit.
5. **Protect the record.** The server builds the signed, encrypted record and embeds it.
6. **Download the stego file.** Output is always lossless: PNG for images, WAV for audio, and FFV1/PCM Matroska (`.mkv`) for video.

Other formats are first converted to a lossless PNG or WAV copy, and that copy is what carries the payload. This also applies to PNG and WAV files that are not already 8- or 16-bit RGB/RGBA PNG or PCM WAV. Video output is lossless too, so an `.mkv` can be much larger than the original clip, and browsers cannot play it inline.

### Verifying (checking a file)

On the verify page, upload the stego file (PNG, WAV, or MKV), the sender's public key, and your receiver private key. The receiver's key opens the bootstrap, which recovers the start unit, the LSB count, the record length, and the AES session key. The app then checks the signature, decrypts the record, and recomputes the media hash.

If the result is `Authentic`, you can preview the recovered payload in the browser or download it. A preview is shown only when the file's signed MIME type matches its actual contents, and only for common text, image, audio, and video types. Anything else, such as SVG, HTML, or PDF, is download-only.

### Verdicts

| Verdict | Meaning |
| --- | --- |
| `Authentic` | Every check passed, and the media is unchanged since signing. |
| `Tampered` | The signature is valid, but the protected media content has changed. |
| `Signature Invalid` | The signature does not match. The sender key is wrong, or the record or its position was altered. |
| `Payload Missing` | The receiver key cannot open the bootstrap. The key is wrong, or the file carries no payload. |
| `Wrong Start Location` | The recovered position points outside the file or overlaps the bootstrap. |
| `Cannot Decrypt` | The encrypted record fails its authentication check. |
| `Cannot Verify` | The file cannot be read or parsed as a valid stego file. |

The [protocol guide](docs/protocol.md#verification-verdicts) gives the exact conditions for each verdict.

### Where files are stored

Everything the app writes stays inside the `instance/` folder, which Git ignores:

| Folder | Contents |
| --- | --- |
| `instance/work/` | Temporary upload and working files for each request. They are deleted when the request ends. |
| `instance/stego-outputs/` | Stego files you have created. |
| `instance/recovered-payloads/` | Payloads recovered after an `Authentic` result. |

Stego outputs and recovered payloads are not deleted automatically, so clear them out when you no longer need them. Recovered payloads are stored as plain files, so anyone who can read this folder can read them.

There is no fixed upload size limit. Instead, the server keeps 3 GiB of free disk space in reserve and refuses any upload or output that would use it up. If the server is killed mid-request, for example by a power cut, it can leave `.stego-staging-*` folders behind. Stop the server and delete them by hand. The [web application guide](docs/web-application.md) covers request handling and storage in full.

## Demonstration notebook

`notebooks/FR1-12 Prototype.ipynb` walks through the sender and receiver steps in order. Before each step it says what should happen, and afterwards it prints the evidence next to that expectation, so you can check the flow without reading the library code. It needs one extra package:

```sh
pip install -r requirements-notebook.txt
```

The notebook covers:

- PNG (including 16-bit), RGBA, and WAV encoding and verification;
- the failure verdicts, typed payloads, and payload files;
- the assignment's payload sizes, and every LSB count from 1 to 8;
- a simulated transfer from Party A's folder to Party B's folder;
- JPEG-to-PNG and MP3-to-WAV conversion, plus a short 8-bit video example with its limits and cost estimates;
- safe simulations of refusals for low disk space, unsupported audio depth, oversized WAV (RIFF) files, and video mux space. These use small files instead of real huge ones.

The tests and the guides in `docs/` cover the finer rules that the notebook leaves out.

## Python API

The `stego` package can be used without the web app:

```python
from stego import encode_png, verify_png

layout, record = encode_png(
    "cover.png",
    "stego.png",
    sender_private_key,
    receiver_public_key,
    2048,                                  # start unit
    3,                                     # LSB count
    b"message",
    b"mime=text/plain;name=message.txt",   # payload metadata
)
result = verify_png("stego.png", sender_public_key, receiver_private_key)
```

| Area | Functions |
| --- | --- |
| PNG and WAV | `encode_png`, `verify_png`, `encode_wav`, `verify_wav`, `PngCarrier`, `WavCarrier` |
| Video | `encode_video`, `verify_video`, `encode_video_from_payload_path`, `verify_video_to_payload_path`, `VideoCarrier` |
| Source conversion | `open_image_source`, `open_audio_source`, `detect_source_family`, `encode_image`, `encode_audio`, and their payload-file variants |
| Lower-level building blocks | `CarrierSource`, `prepare_carrier_encoding`, `decode_carrier_source`, `lsb_range_transform` |

All media input and output goes through PyAV. Pillow is used only by the tests and the notebook. Payloads and WAV audio are processed in bounded chunks, so their memory use does not grow with file size. A PNG cover is decoded whole.

## Project layout

| Path | Contents |
| --- | --- |
| `stego/` | Protocol and carrier library |
| `stego_web/` | Flask application, web pages, and browser code |
| `run.py` | Starts the local web server |
| `test_stego.py`, `test_video.py`, `test_webapp.py` | Protocol, carrier, video, and web tests |
| `notebooks/` | End-to-end demonstration notebook |
| `presentation/` | Technical-design slides, with a PDF export |
| `demo/` | Demonstration files and keys, supplied in a separate ZIP |
| `docs/` | Design guides, project history, and the assignment brief |
| `scripts/` | Documentation link checker and JavaScript tests |

For where each assignment requirement is met, see the [requirement coverage table](docs/web-application.md#requirement-coverage).

## Limits and compatibility

- Only protocol version 3 files are accepted. Files from our earlier versions 1 and 2, or from the older, removed `STG1` implementation, are not compatible. A version 2 file returns `Cannot Verify` with the detail `unsupported bootstrap version`.
- The authenticity check covers the decoded media content, not container metadata. For example, PNG text chunks or Matroska tags can change without changing the verdict.
- PNG covers must be single-frame 8-bit or 16-bit RGB or RGBA images, up to 715,827,880 bytes once decoded.
- A converted WAV larger than 2 GiB may not open in some older audio programs, which read the size field as a signed number. StegoVerify reads it correctly.
- On Windows, VLC's default Direct3D11 renderer can show stego `.mkv` videos with a yellow-green tint. The pixels are correct. To see the true colours, set VLC's video output to OpenGL.

The [known limitations](docs/known-limitations.md) guide lists the rest.

## Documentation

| Guide | What it covers |
| --- | --- |
| [Protocol](docs/protocol.md) | Wire format, media hash, cryptography, and verdicts |
| [Web application](docs/web-application.md) | Requests, responses, previews, storage, and requirement coverage |
| [Carrier and payload flow](docs/carrier-and-payload-flow.md) | How files are read, converted, and rewritten, with measurements |
| [Video carrier](docs/video-carrier.md) | The video format, its limits, and its performance |
| [Known limitations](docs/known-limitations.md) | What the protocol does not cover, and refused formats |
| [Protocol history](docs/history/protocol-history.md) and [repository history](docs/history/repository-history.md) | How the design evolved |
| [Presentation](presentation/README.md) | Technical-design slides |
| [Assignment brief](docs/assignment/INF2005-ACW1-spec_v5-f2f.md) | The supplied specification |
