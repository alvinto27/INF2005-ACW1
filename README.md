# StegoVerify — INF2005 ACW1

StegoVerify is a local Flask web app for INF2005 ACW1. It embeds an encrypted, signed payload (a text message or a file) in an image, audio file, or video. The receiver extracts the payload and checks whether the media was changed after embedding.

## How it works

```text
 SENDER                                     RECEIVER
 1. Encrypt the payload    (AES-256-GCM)    1. Open the bootstrap   (own private key)
 2. Sign it                (RSA-PSS)        2. Check the signature  (sender's public key)
 3. Encrypt the bootstrap  (RSA-OAEP)       3. Decrypt the payload
 4. Write both into the cover's LSBs        4. Re-check the media fingerprint
              │                             5. Give one verdict
              │                                          ▲
              └──────────────► stego file ───────────────┘
```

Terms used above:

- **LSB (least-significant bit):** the lowest bit of a pixel colour value or audio sample. The payload is written into the lowest 1 to 8 bits.
- **Bootstrap:** a short record at the start of the cover, encrypted with the receiver's public key. It holds the payload's start position, the number of LSBs used, and the AES key.
- **Media fingerprint:** a SHA-256 hash of the cover, computed without the bits that embedding changes. It is stored inside the signed payload. If the media changes later, the hash does not match and the verdict is `Tampered`.

Verification does not need the original cover file.

## Quick links

| Topic | Link |
| --- | --- |
| Setup and tests | [Quick start](#quick-start), [Tests](#tests) |
| Requirement coverage | [Web application guide](docs/web-application.md#requirement-coverage) |
| Demonstration files and keys | [`demo/`](demo/README.md) |
| End-to-end walkthrough | [Notebook](#demonstration-notebook) |
| Design | [Slides](presentation/README.md), [guides](#documentation) |
| Known limitations | [Known limitations](docs/known-limitations.md) |

## Quick start

You need **Python 3.12 or later**.

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

Open <http://127.0.0.1:5000>. The encode page is `/` and the verify page is `/verify`. The server listens on localhost only.

## Tests

| Command | Expected result |
| --- | --- |
| `python -m unittest` | `Ran 308 tests ... OK`. If the FFmpeg command-line tool is not installed, one test is skipped: `OK (skipped=1)`. |
| `node --test scripts/test-api-js.cjs scripts/test-capacity-js.cjs` | 15 tests pass. Needs Node.js only. |
| `python scripts/check-docs.py` | 0 broken links in the docs. |

GitHub Actions runs all three on Python 3.12, 3.13, and 3.14.

## Using the app

### Encode

1. Select the cover and the payload (a text message or a file).
2. Load the sender's private key, or generate a sender key pair.
3. Load the receiver's public key, or generate a receiver key pair.
4. Set the start unit and the LSB count (1 to 8). The page shows whether the payload fits.
5. Select **Encrypt, sign and export**.
6. Download the stego file.

| Cover type | Accepted formats | Output |
| --- | --- | --- |
| Image | PNG, JPEG, WebP, AVIF, BMP, TIFF, GIF (still images) | PNG |
| Audio | WAV, MP3, AAC, M4A, FLAC, Ogg | WAV |
| Video | MP4, MOV, MKV, WebM, AVI | MKV |

The output is always lossless, because lossy formats such as JPEG and MP3 would change the embedded bits when saved. Video output is therefore much larger than the input, and browsers cannot play it.

### Verify

Upload the stego file, the sender's public key, and the receiver's private key. The page shows one verdict. If the verdict is `Authentic`, the payload can be previewed or downloaded.

| Verdict | Meaning |
| --- | --- |
| `Authentic` | All checks passed. The media is unchanged. |
| `Tampered` | The signature is fine, but the media was changed. |
| `Signature Invalid` | Wrong sender key, or the hidden data was altered or moved. |
| `Payload Missing` | Your key cannot open the bootstrap: wrong key, or nothing is hidden. |
| `Wrong Start Location` | The hidden data points outside the file. |
| `Cannot Decrypt` | The encrypted record failed its integrity check. |
| `Cannot Verify` | The file cannot be read as a stego file. |

The [protocol guide](docs/protocol.md#verification-verdicts) gives the exact conditions.

### Where files go

| Folder | Contents | Deleted automatically? |
| --- | --- | --- |
| `instance/work/` | Temporary files for each request | Yes, when the request ends |
| `instance/stego-outputs/` | Stego files you created | No |
| `instance/recovered-payloads/` | Payloads from `Authentic` results, stored unencrypted | No |

Git ignores `instance/`. The server refuses any upload that would leave less than 3 GiB of free disk space.

## Demonstration notebook

`notebooks/FR1-12 Prototype.ipynb` runs the sender and receiver steps in order. Each step states the expected result, then prints the actual result. It covers PNG, WAV, and video; all seven verdicts; LSB counts 1 to 8; and format conversion. It needs extra packages:

```sh
pip install -r requirements-notebook.txt
```

## Project layout

| Path | Contents |
| --- | --- |
| `stego/` | Protocol library (usable from Python without the web app) |
| `stego_web/` | The Flask web app |
| `run.py` | Starts the web server |
| `test_stego.py`, `test_video.py`, `test_webapp.py` | Python tests |
| `notebooks/` | Demonstration notebook |
| `presentation/` | Slides, with a PDF copy |
| `demo/` | Demonstration files and keys |
| `docs/` | Guides and the assignment brief |
| `scripts/` | Link checker and JavaScript tests |

## Limits

- Only files made by this version (protocol version 3) can be verified.
- The check covers the image, sound, and video content, not metadata such as PNG text or video tags.
- On Windows, VLC may show stego videos with a yellow-green tint. The file is fine. Set VLC's video output to OpenGL.

See [known limitations](docs/known-limitations.md) for the full list.

## Documentation

| Guide | What it covers |
| --- | --- |
| [Docs index](docs/README.md) | Glossary and code map |
| [Protocol](docs/protocol.md) | The hidden data format, the cryptography, and the verdicts |
| [Web application](docs/web-application.md) | What each page and route does |
| [Carrier and payload flow](docs/carrier-and-payload-flow.md) | How files are read, converted, and written |
| [Video carrier](docs/video-carrier.md) | How video works and its limits |
| [Known limitations](docs/known-limitations.md) | What the app does not check or support |
| [History](docs/history/protocol-history.md) | Earlier protocol versions |
| [Assignment brief](docs/assignment/INF2005-ACW1-spec_v5-f2f.md) | The supplied specification |
