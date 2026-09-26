# Agent Navigation Map — INF2005-ACW1

Use this map before editing an unfamiliar part of the repository.

## Documentation locations

| Content | Location |
| --- | --- |
| Documentation index | [AGENT_docs/README.md](README.md) |
| Supplied specification directory | `docs/` |
| Project-maintained records | `AGENT_docs/` |
| Repository instructions | [AGENTS.md](../AGENTS.md) |
| Public setup and protocol usage | [README.md](../README.md) |
| Assignment specification transcription | [INF2005-ACW1-spec_v5-f2f.md](../docs/INF2005-ACW1-spec_v5-f2f.md) |
| Current version-3 wire format, media hash, typed metadata, discovery, and verdicts | [CURRENT-PROTOCOL.md](CURRENT-PROTOCOL.md#verification-verdicts) |
| PyAV media migration stages and measured implementation evidence | [PYAV-MIGRATION-RECORD.md](PYAV-MIGRATION-RECORD.md) |
| Version-1 design history | [PROTOCOL-V1-HISTORY.md](PROTOCOL-V1-HISTORY.md#decisions-and-what-was-rejected) |
| Removal of imported legacy files, the old `STG1` stack, and duplicate assignment PDF | [MERGE-LEFTOVER-REMOVAL.md](MERGE-LEFTOVER-REMOVAL.md) |
| Historical protocol version 2 design; stages 0 through 6b complete; 6c cancelled | [LOCATION-CONFIDENTIALITY-PLAN.md](LOCATION-CONFIDENTIALITY-PLAN.md) |
| Completed version 2 stage outcomes and measurements | [PROTOCOL-V2-STAGE-RECORD.md](PROTOCOL-V2-STAGE-RECORD.md) |
| Chunked carrier access, payload APIs, staging cleanup, measurements, and known limits | [CARRIER-AND-PAYLOAD-FLOW.md](CARRIER-AND-PAYLOAD-FLOW.md#4-protocol-flow) |
| Video carrier design, implementation details, and measurements | [VIDEO-CARRIER-DESIGN.md](VIDEO-CARRIER-DESIGN.md) |
| Assignment work not built or assembled | [WORK-NOT-BUILT.md](WORK-NOT-BUILT.md#work-not-built) |
| Reduction specification and outcome | [REDUCTION-SPEC.md](REDUCTION-SPEC.md), [KISS-REDUCTION-RECORD.md](KISS-REDUCTION-RECORD.md) |
| Web request contracts, response handling, payload previews, and requirement coverage | [WEB-APPLICATION-GUIDE.md](WEB-APPLICATION-GUIDE.md) |
| Current and older protocol compatibility | [CURRENT-PROTOCOL.md](CURRENT-PROTOCOL.md#limits-and-compatibility) |

## Implementation locations

| Area | Start here |
| --- | --- |
| Public protocol API | [stego/__init__.py](../stego/__init__.py) |
| Constants and domain separators | [stego/constants.py](../stego/constants.py) |
| Validation and LSB primitives | [stego/bits.py](../stego/bits.py) |
| Public file-backed carrier backends; internal carrier interface and chunk size | [stego/carrier.py](../stego/carrier.py), [stego/media.py](../stego/media.py) |
| Layout, incremental masked hash (`MaskedMediaHasher`), and signing input | [stego/layout.py](../stego/layout.py) |
| Bootstrap envelope and authenticated data | [stego/bootstrap.py](../stego/bootstrap.py) |
| Payload records and serialisation | [stego/packet.py](../stego/packet.py) |
| RSA-PSS keys, signatures, fingerprints, and PEM | [stego/crypto.py](../stego/crypto.py) |
| Carrier capacity and fixed-width protocol fields | [stego/layout.py](../stego/layout.py) |
| Public `PngCarrier`, `WavCarrier`, WAV header reader, and PNG/WAV file adapters, including the writers that keep PNG ancillary chunks and WAV chunks outside the samples | [stego/media.py](../stego/media.py) |
| Public image/audio source conversion context managers and encode wrappers; canonical PNG/WAV snapshots | [stego/sources.py](../stego/sources.py) |
| Public video carrier reader/writer, canonical timing, bounded reads, and video APIs | [stego/video.py](../stego/video.py) |
| Two-pass encode, receiver-gated verification over a carrier backend, and file wrappers | [stego/core.py](../stego/core.py) |
| Flask application factory, disk-backed carrier and payload uploads, streaming encode/verify routes, validated downloads, and `/payload/<id>` recovered-payload downloads; runtime files use `instance/stego-outputs` and `instance/recovered-payloads` | [stego_web/__init__.py](../stego_web/__init__.py), [stego_web/routes.py](../stego_web/routes.py) |
| Flask-to-protocol-v3 streaming file adapter | [stego_web/services/current_protocol.py](../stego_web/services/current_protocol.py) |
| Browser UI and controllers | [index.html](../stego_web/templates/index.html), [app.js](../stego_web/static/app.js), [verify.js](../stego_web/static/verify.js), and [style.css](../stego_web/static/style.css) |
| Active Flask-to-protocol-v3 service | [stego_web/services/current_protocol.py](../stego_web/services/current_protocol.py) |
| FR1–FR12 demonstration notebook: running it produces PNG/WAV, source-conversion, and optional video demos, verdict/fidelity evidence, and payload API examples | [notebooks/FR1-12 Prototype.ipynb](../notebooks/FR1-12%20Prototype.ipynb) |
| Masked-media protocol and chunked-carrier tests | [test_stego.py](../test_stego.py), [test_video.py](../test_video.py) |
| Flask integration and current protocol tests | [test_webapp.py](../test_webapp.py) and [test_stego.py](../test_stego.py) |
| Sample media: PNG cover; GIF payload; 60-second 1080p30 H.264/AAC MP4 (above the 4 GiB carrier-unit video cap, so usable as a payload, not a video cover); its 20-second cut (a valid video cover) | [Banana.png](../samples/Banana.png), [nia-tweeking.gif](../samples/nia-tweeking.gif), [test.mp4](../samples/test.mp4), [test-20s.mp4](../samples/test-20s.mp4) |
| Required runtime and test dependencies (Pillow is test/notebook-only) | [requirements.txt](../requirements.txt) |
| Optional demonstration-notebook dependency | [requirements-notebook.txt](../requirements-notebook.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | This is an independent Git repository. Commit and push work from this directory. |
