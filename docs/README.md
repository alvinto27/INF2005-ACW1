# Documentation

These guides explain how StegoVerify works, why it is designed the way it is, and where its limits are. Start with the [project README](../README.md) for setup and a quick tour, then read whichever guide below fits your question.

## Guides

| Guide | Read it to learn |
| --- | --- |
| [Protocol](protocol.md) | How a payload is laid out, encrypted, signed, and hashed, and what each verdict means |
| [Web application](web-application.md) | What the encode and verify pages send and receive, how payload previews work, and which requirement is met where |
| [Carrier and payload flow](carrier-and-payload-flow.md) | How files are read, converted, and rewritten in bounded chunks, with memory and speed measurements |
| [Video carrier](video-carrier.md) | How the optional video-plus-audio carrier works, its limits, and its performance |
| [Known limitations](known-limitations.md) | What the authenticity check does not cover, and which source formats are refused |
| [Protocol history](history/protocol-history.md) | How the protocol evolved from version 1 to version 3, and why |
| [Repository history](history/repository-history.md) | The move to PyAV and the removal of older code |
| [Presentation](../presentation/README.md) | The technical-design slides and how to run them |
| [Assignment brief](assignment/INF2005-ACW1-spec_v5-f2f.md) | A text version of the supplied specification. The [original PDF](assignment/INF2005-ACW1-spec_v5-f2f.pdf) is also included. |

## Code map

### Protocol library (`stego/`)

| File | What it does |
| --- | --- |
| `__init__.py` | The public API |
| `core.py` | Encoding and verification over any carrier, including the final read-back check |
| `layout.py` | Payload geometry, capacity, fixed-width fields, and the masked media hash |
| `bootstrap.py` | The receiver-only bootstrap envelope |
| `packet.py` | Payload records and their serialisation |
| `crypto.py` | RSA keys, signatures, and PEM loading |
| `bits.py` | Input checks and low-level LSB operations |
| `carrier.py` | The carrier interface and chunk size |
| `media.py` | PNG and WAV readers and writers |
| `sources.py` | Conversion of other image and audio formats into PNG or WAV |
| `video.py` | The video-plus-audio carrier |
| `storage.py` | Free-disk-space checks |
| `constants.py` | Protocol constants |

### Web application (`stego_web/`)

| File | What it does |
| --- | --- |
| `__init__.py`, `routes.py` | The Flask app, its upload handling, and its encode, verify, capacity, and download routes |
| `services/current_protocol.py` | The link between the web routes and the protocol library |
| `templates/index.html`, `static/app.js` | The encode page and its six-step wizard |
| `templates/verify.html`, `static/verify.js` | The verify page |
| `static/api.js` | Shared request handling, timeouts, and error messages for both pages |
| `static/capacity.js` | The early "will it fit?" check in the wizard |

### Tests and tools

| Path | What it does |
| --- | --- |
| `test_stego.py` | Protocol, PNG and WAV carrier, and source-conversion tests |
| `test_video.py` | Video carrier tests |
| `test_webapp.py` | Web application tests |
| `scripts/test-api-js.cjs`, `scripts/test-capacity-js.cjs` | JavaScript tests that run with Node.js alone |
| `scripts/check-docs.py` | Checks the Markdown links in these docs |
| `.github/workflows/tests.yml` | Runs all of the above on Python 3.12 to 3.14 |
