# Documentation

The [project README](../README.md) covers setup, tests, and basic use. The guides below give the details.

## Guides

| Guide | Contents |
| --- | --- |
| [Protocol](protocol.md) | Data layout, cryptography, media hash, and verdict conditions |
| [Web application](web-application.md) | Pages, routes, request fields, responses, and requirement coverage |
| [Carrier and payload flow](carrier-and-payload-flow.md) | How covers are read, converted, and written, and how payloads are staged |
| [Video carrier](video-carrier.md) | Video and audio handling, timing rules, and limits |
| [Known limitations](known-limitations.md) | What the app does not check or support |
| [Protocol history](history/protocol-history.md) | Protocol versions 1 to 3 |
| [Repository history](history/repository-history.md) | The move to PyAV and removed code |
| [Presentation](../presentation/README.md) | Slides and how to run them |
| [Assignment brief](assignment/INF2005-ACW1-spec_v5-f2f.md) | Text copy of the specification ([PDF](assignment/INF2005-ACW1-spec_v5-f2f.pdf)) |

## Glossary

| Term | Meaning |
| --- | --- |
| Cover | The original image, audio, or video file chosen by the sender. |
| Carrier | The cover in the form used for embedding: a PNG, a PCM WAV, or decoded video frames and audio samples. |
| Stego file | The output file that contains the embedded data. |
| Carrier unit | One byte position that can hold embedded bits: the low byte of one R, G, or B value, or of one audio sample. |
| LSB count (`k`) | How many of the lowest bits of each carrier unit are used, from 1 to 8. |
| Start unit | The carrier unit where the packet begins. It must be after the bootstrap. |
| Bootstrap | An RSA-OAEP-encrypted record in the lowest bit of the first 2,048 carrier units. It holds the start unit, LSB count, packet length, and AES key. |
| Packet | The encrypted payload record followed by the RSA-PSS signature. |
| Payload record | The data that is encrypted: media ID, timestamp, nonce, media hash, user payload, and metadata. |
| Media hash | A SHA-256 hash of the carrier, computed with the embedded bits masked out, so the sender and receiver get the same value. |
| Fixed bytes | Media bytes that embedding never changes, such as alpha values and the high bytes of 16-bit samples. They are included in the media hash. |
| Media code | The carrier type: 1 for PNG, 2 for WAV, 3 for video. |
| Media context | The carrier's dimensions and format (for example width, height, and channels). It is signed. |
| Canonical | The standard form a cover is converted to before embedding: 8- or 16-bit RGB or RGBA PNG, PCM WAV, or decoded RGB video with 16-bit audio samples. |
| Lossless | A format that stores values exactly, so embedded bits survive. PNG, PCM WAV, and FFV1 video are lossless. |
| Verdict | The single result of verification, for example `Authentic` or `Tampered`. |
| Staging | Temporary files written during encoding or verification, before the final file is published. |

## Code map

### Protocol library (`stego/`)

| File | Contents |
| --- | --- |
| `__init__.py` | Public API |
| `core.py` | Encoding and verification for any carrier, including the output read-back check |
| `layout.py` | Packet position, capacity, field encoding, and the media hash |
| `bootstrap.py` | The bootstrap record |
| `packet.py` | Payload records |
| `crypto.py` | RSA keys, signatures, and PEM loading |
| `bits.py` | Input checks and LSB read and write |
| `carrier.py` | Carrier interface and chunk size |
| `media.py` | PNG and WAV carriers |
| `sources.py` | Conversion of other image and audio formats to PNG or WAV |
| `video.py` | Video carrier |
| `storage.py` | Free disk space checks |
| `constants.py` | Protocol constants |

### Web application (`stego_web/`)

| File | Contents |
| --- | --- |
| `__init__.py`, `routes.py` | Flask app, upload handling, and routes |
| `services/current_protocol.py` | Connects the routes to the `stego` library |
| `templates/index.html`, `static/app.js` | Encode page and its six-step form |
| `templates/verify.html`, `static/verify.js` | Verify page |
| `static/api.js` | Shared request handling, time limits, and error messages |
| `static/capacity.js` | Capacity check on the encode page |

### Tests and tools

| Path | Contents |
| --- | --- |
| `test_stego.py` | Protocol, PNG, WAV, and source conversion tests |
| `test_video.py` | Video carrier tests |
| `test_webapp.py` | Web application tests |
| `scripts/test-api-js.cjs`, `scripts/test-capacity-js.cjs` | JavaScript tests (Node.js) |
| `scripts/check-docs.py` | Markdown link checker |
| `.github/workflows/tests.yml` | Runs all tests on Python 3.12, 3.13, and 3.14 |
