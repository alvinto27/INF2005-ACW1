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
| Current protocol, fixed-width fields, typed-payload metadata, and design history | [PROTOCOL-DESIGN.md](PROTOCOL-DESIGN.md#protocol-design) |
| Historical protocol version 2 design; stages 0 through 6b complete; 6c cancelled | [LOCATION-CONFIDENTIALITY-PLAN.md](LOCATION-CONFIDENTIALITY-PLAN.md) |
| Completed version 2 stage outcomes and measurements | [PROTOCOL-V2-STAGE-RECORD.md](PROTOCOL-V2-STAGE-RECORD.md) |
| Chunked carrier access: design, invariants, file-backed backends, chunk size, memory claim, and web follow-up | [STREAMING-CARRIER-PLAN.md](STREAMING-CARRIER-PLAN.md#streaming-carrier-plan) |
| Assignment work not built or assembled | [WORK-NOT-BUILT.md](WORK-NOT-BUILT.md#work-not-built) |
| Reduction specification and outcome | [REDUCTION-SPEC.md](REDUCTION-SPEC.md), [KISS-REDUCTION-RECORD.md](KISS-REDUCTION-RECORD.md) |
| Active web integration status and verification flow | [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md), [DECODING-VERIFICATION.md](DECODING-VERIFICATION.md) |
| Current and legacy protocol boundary | [PROTOCOL-COMPATIBILITY.md](PROTOCOL-COMPATIBILITY.md) |

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
| Public `PngCarrier`, `WavCarrier`, WAV header reader, and PNG/WAV file adapters | [stego/media.py](../stego/media.py) |
| Two-pass encode, receiver-gated verification over a carrier backend, and file wrappers | [stego/core.py](../stego/core.py) |
| Flask application factory, disk-backed uploads, encode/decode routes, and validated stego downloads | [stego_web/__init__.py](../stego_web/__init__.py), [stego_web/routes.py](../stego_web/routes.py) |
| Flask-to-protocol-v2 byte/file adapter | [stego_web/services/current_protocol.py](../stego_web/services/current_protocol.py) |
| Browser UI and controllers | [index.html](../stego_web/templates/index.html), [app.js](../stego_web/static/app.js), [verify.js](../stego_web/static/verify.js), and [style.css](../stego_web/static/style.css) |
| Retained legacy web protocol | [payload_protocol.py](../payload_protocol.py) and legacy modules under [stego_web/services/](../stego_web/services/) |
| FR1–FR12 demonstration notebook: verdict/fidelity evidence; file-backed PNG and WAV carrier demonstrations | [notebooks/FR1-12 Prototype.ipynb](../notebooks/FR1-12%20Prototype.ipynb) |
| Masked-media protocol and chunked-carrier tests | [test_stego.py](../test_stego.py) |
| Flask integration and legacy-protocol tests | [test_webapp.py](../test_webapp.py) and [test_payload_protocol.py](../test_payload_protocol.py) |
| Runtime and test dependencies | [requirements.txt](../requirements.txt) |
| Optional demonstration-notebook dependency | [requirements-notebook.txt](../requirements-notebook.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | This is an independent Git repository. Commit and push work from this directory. |
