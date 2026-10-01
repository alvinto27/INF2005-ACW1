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
| Protocol design history: v1, v2 plan and stages, KISS reduction, and transition to v3 | [PROTOCOL-HISTORY.md](PROTOCOL-HISTORY.md) |
| PyAV media migration and imported-legacy cleanup history | [REPOSITORY-HISTORY.md](REPOSITORY-HISTORY.md) |
| Chunked carrier access, payload APIs, staging cleanup, measurements, and known limits | [CARRIER-AND-PAYLOAD-FLOW.md](CARRIER-AND-PAYLOAD-FLOW.md#protocol-flow) |
| Video carrier design, implementation details, and measurements | [VIDEO-CARRIER-DESIGN.md](VIDEO-CARRIER-DESIGN.md) |
| Assignment work not built or assembled | [WORK-NOT-BUILT.md](WORK-NOT-BUILT.md#work-not-built) |
| Web request contracts, response handling, payload previews, requirement coverage, and disconnected Three.js map status/design | [WEB-APPLICATION-GUIDE.md](WEB-APPLICATION-GUIDE.md#threejs-carrier-map) |
| Current and older protocol compatibility | [CURRENT-PROTOCOL.md](CURRENT-PROTOCOL.md#limits-and-compatibility) |

## Implementation locations

| Area | Start here |
| --- | --- |
| Public protocol API | [stego/__init__.py](../stego/__init__.py) |
| Constants and domain separators | [stego/constants.py](../stego/constants.py) |
| Validation and LSB primitives | [stego/bits.py](../stego/bits.py) |
| Public file-backed carrier backends; internal carrier interface and chunk size | [stego/carrier.py](../stego/carrier.py), [stego/media.py](../stego/media.py) |
| Layout geometry, carrier capacity, fixed-width protocol fields, incremental masked hash (`MaskedMediaHasher`), and signing input | [stego/layout.py](../stego/layout.py) |
| Bootstrap envelope and authenticated data | [stego/bootstrap.py](../stego/bootstrap.py) |
| Payload records and serialisation | [stego/packet.py](../stego/packet.py) |
| RSA-PSS keys, signatures, fingerprints, and PEM | [stego/crypto.py](../stego/crypto.py) |
| Public `PngCarrier`, `WavCarrier`, WAV header reader, and PNG/WAV file adapters, including the writers that keep PNG ancillary chunks and WAV chunks outside the samples | [stego/media.py](../stego/media.py) |
| Public image/audio source conversion context managers and encode wrappers; canonical PNG/WAV snapshots | [stego/sources.py](../stego/sources.py) |
| Public video carrier reader/writer, canonical timing, bounded reads, and video APIs | [stego/video.py](../stego/video.py) |
| Carrier encoding, receiver-gated verification over a carrier backend, output read-back checks, and file wrappers | [stego/core.py](../stego/core.py) |
| Shared disk-space reserve and PNG output-size bound | [stego/storage.py](../stego/storage.py) |
| Flask application factory, work-directory multipart spooling, disk-backed image/audio/video encode and verify routes, `/capacity` payload-fit estimates, validated PNG/WAV/MKV downloads, and `/payload/<id>` recovered-payload downloads; runtime files use `instance/work`, `instance/stego-outputs`, and `instance/recovered-payloads` | [stego_web/__init__.py](../stego_web/__init__.py), [stego_web/routes.py](../stego_web/routes.py) |
| Separate encode and verify pages, six-step wizard, active browser controllers and capacity helpers, shared request-failure handling, protocol diagrams, and unconnected Three.js map assets | [index.html](../stego_web/templates/index.html), [verify.html](../stego_web/templates/verify.html), [app.js](../stego_web/static/app.js), [verify.js](../stego_web/static/verify.js), [api.js](../stego_web/static/api.js), [capacity.js](../stego_web/static/capacity.js), [stego-map.js](../stego_web/static/stego-map.js), [stego-map-geometry.js](../stego_web/static/stego-map-geometry.js), [navigation.js](../stego_web/static/navigation.js), [motion.js](../stego_web/static/motion.js), [feature-motion.js](../stego_web/static/feature-motion.js), [style.css](../stego_web/static/style.css), and the locally bundled [Three.js files](../stego_web/static/vendor/three/) with [LICENSE](../stego_web/static/vendor/three/LICENSE) and [VERSION.txt](../stego_web/static/vendor/three/VERSION.txt) |
| Active Flask-to-protocol-v3 service | [stego_web/services/current_protocol.py](../stego_web/services/current_protocol.py) |
| FR1–FR12 demonstration notebook: PNG/WAV flows, assignment payload sizes, `k=1..8` sweeps, simulated Party A-to-B folder transfer and resource refusals, 16-bit PNG, and optional video limits/demo | [notebooks/FR1-12 Prototype.ipynb](../notebooks/FR1-12%20Prototype.ipynb) |
| Masked-media protocol and chunked-carrier tests | [test_stego.py](../test_stego.py), [test_video.py](../test_video.py) |
| Flask integration and current protocol tests | [test_webapp.py](../test_webapp.py) and [test_stego.py](../test_stego.py) |
| Sample media: the notebook's PNG cover. Git ignores every other file in `samples/`; put local demo media there | [Banana.png](../samples/Banana.png) |
| Required runtime and test dependencies (Pillow is test/notebook-only) | [requirements.txt](../requirements.txt) |
| Optional demonstration-notebook dependency | [requirements-notebook.txt](../requirements-notebook.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Optional dependency-free JavaScript request-boundary and capacity-helper tests | [scripts/test-api-js.cjs](../scripts/test-api-js.cjs), [scripts/test-capacity-js.cjs](../scripts/test-capacity-js.cjs) |
| CI Python tests, dependency-free JavaScript request tests, and documentation check on Python 3.12–3.14 | [.github/workflows/tests.yml](../.github/workflows/tests.yml) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | This is an independent Git repository. Commit and push work from this directory. |
