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
| Known behaviours | [Known behaviours](#known-behaviours) |
| Requirement coverage | [Web application guide](docs/web-application.md#requirement-coverage) |
| Demonstration files and keys | Supplied as a separate ZIP; see [`demo/`](demo/README.md) |
| End-to-end walkthrough | [Notebook](notebooks/stegoverify-demo.ipynb) ([how to run](#demonstration-notebook)) |
| Design | [Slides (PDF)](presentation/stego-slides.pdf), [guides](#documentation) |
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

## Known behaviours

| What you see | Why, and what to do |
| --- | --- |
| A stego video shows a yellow-green tint in VLC on Windows | VLC's default Direct3D11 output displays this format wrongly. The file is correct. In VLC, set **Tools > Preferences > Video > Output** to **OpenGL**. |
| The browser downloads the `.mkv` instead of playing it | Browsers cannot play lossless FFV1 video. Open the file in VLC or another desktop player. |
| A video output is much larger than the input, and encoding is slow | Output is lossless, at about 40 MB per second of 1080p video. Use clips of 30 seconds or less. |
| An older stego file gives `Cannot Verify` with `unsupported bootstrap version` | Only files made by protocol version 3 can be verified. |
| Editing PNG text, WAV `LIST` chunks, or video tags still gives `Authentic` | The check covers the image, sound, and video content, not metadata. |
| The page animations do not play | The animation library loads from the internet. Offline, or with reduced motion turned on, the pages still work without animation. |

See [known limitations](docs/known-limitations.md) for the full list.

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

[`notebooks/stegoverify-demo.ipynb`](notebooks/stegoverify-demo.ipynb) runs the sender and receiver steps in order. Each step states the expected result, then shows the actual result in a table of checks, with diagrams and charts where they help. It covers PNG, WAV, and video; all seven verdicts; LSB counts 1 to 8; format conversion; and the team's custom payload, a JPEG chart.

The notebook is saved with its outputs, so you can read every result on GitHub without running it. To run it again, install the extra packages:

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
| `notebooks/` | Demonstration notebook and its display helpers |
| `presentation/` | Slides, with a PDF copy |
| `demo/` | Where to extract the demonstration ZIP (contents not in the repository) |
| `docs/` | Guides and the assignment brief |
| `scripts/` | Link checker and JavaScript tests |

## Documentation

| Guide | What it covers |
| --- | --- |
| [Docs index](docs/README.md) | Glossary and code map |
| [Protocol](docs/protocol.md) | The hidden data format, the cryptography, and the verdicts |
| [Web application](docs/web-application.md) | What each page and route does |
| [Carrier and payload flow](docs/carrier-and-payload-flow.md) | How files are read, converted, and written |
| [Video carrier](docs/video-carrier.md) | How video works and its limits |
| [Known limitations](docs/known-limitations.md) | What the app does not check or support |
| [Protocol history](docs/history/protocol-history.md) | Earlier protocol versions and the decisions behind them |
| [Repository history](docs/history/repository-history.md) | The move to PyAV and the removal of old code |
| [Assignment brief](docs/assignment/INF2005-ACW1-spec_v5-f2f.md) | The supplied specification ([PDF](docs/assignment/INF2005-ACW1-spec_v5-f2f.pdf)) |

Other material:

| Item | Contents |
| --- | --- |
| [Slides (PDF)](presentation/stego-slides.pdf) | Technical-design presentation. [How to run the live slides](presentation/README.md). |
| [Demonstration notebook](notebooks/stegoverify-demo.ipynb) | Sender and receiver steps with expected and actual results |
| [Demonstration files](demo/README.md) | Covers, stego files, keys, and verdict screenshots, supplied as a separate ZIP |
