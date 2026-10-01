# Documentation

These guides help teammates and markers understand the application, its design, and its limits. This folder also contains the project history, assignment brief, and a short code map.

## Guides

- [Protocol](protocol.md) — wire format, cryptographic checks, compatibility, and verdicts.
- [Web application](web-application.md) — setup, browser workflow, requests, and requirement coverage.
- [Carrier and payload flow](carrier-and-payload-flow.md) — file-backed processing, payload handling, and storage.
- [Video carrier](video-carrier.md) — video and audio carrier format, limits, and measurements.
- [Known limitations](known-limitations.md) — supported sources and protocol limits.
- [Protocol history](history/protocol-history.md) and [repository history](history/repository-history.md) — design decisions and project changes.
- [Presentation](../presentation/README.md) — technical-design slides.
- [Assignment brief](assignment/INF2005-ACW1-spec_v5-f2f.md) — readable transcription of the supplied specification; the [original PDF](assignment/INF2005-ACW1-spec_v5-f2f.pdf) is also available.

## Code map

| Path | Purpose |
| --- | --- |
| `run.py` | Starts the local Flask application. |
| `stego/core.py` | Encodes and verifies PNG, WAV, and video payloads. |
| `stego/video.py` | Reads and writes the optional video carrier. |
| `stego_web/routes.py` | Handles browser requests and file downloads. |
| `stego_web/services/current_protocol.py` | Connects the web application to the protocol library. |
| `stego_web/static/app.js` | Runs the browser encoding workflow. |
| `stego_web/static/verify.js` | Runs the browser verification workflow. |
| `test_stego.py`, `test_video.py`, `test_webapp.py` | Test protocol, carrier, and web behavior. |
