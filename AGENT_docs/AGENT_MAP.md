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
| Current masked-media integrity design and design history | [INTEGRITY-DESIGN.md](INTEGRITY-DESIGN.md) |
| Retained protocol boundary | [PROTOCOL-COMPATIBILITY.md](PROTOCOL-COMPATIBILITY.md) |
| Flask decoding and integrity design | [DECODING-VERIFICATION.md](DECODING-VERIFICATION.md) |
| Flask requirement status | [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md) |
| Outstanding assignment work | [OUTSTANDING-WORK.md](OUTSTANDING-WORK.md) |

## Implementation locations

| Area | Start here |
| --- | --- |
| Public protocol API | [stego/__init__.py](../stego/__init__.py) |
| Constants and domain separators | [stego/constants.py](../stego/constants.py) |
| Validation and LSB primitives | [stego/bits.py](../stego/bits.py) |
| Layout, masked hash, and signing input | [stego/layout.py](../stego/layout.py) |
| Packet records, framing, and scanning | [stego/packet.py](../stego/packet.py) |
| RSA-PSS keys, signatures, fingerprints, and PEM | [stego/keys.py](../stego/keys.py) |
| PNG and WAV adapters | [stego/media.py](../stego/media.py) |
| End-to-end encode and verification | [stego/core.py](../stego/core.py) |
| Flask web entry point | [run.py](../run.py) and [stego_web/](../stego_web/) |
| Flask payload protocol | [payload_protocol.py](../payload_protocol.py) |
| Flask encoding and verification controllers | [encoding_pipeline.py](../stego_web/services/encoding_pipeline.py) and [verification_pipeline.py](../stego_web/services/verification_pipeline.py) |
| Flask browser UI | [index.html](../stego_web/templates/index.html), [app.js](../stego_web/static/app.js), [verify.js](../stego_web/static/verify.js), [motion.js](../stego_web/static/motion.js), and [style.css](../stego_web/static/style.css) |
| Legacy FR1/FR5 compatibility facade | [FR1_FR5.py](../FR1_FR5.py) |
| FR1–FR12 demonstration notebook | [notebooks/FR1-12 Prototype.ipynb](../notebooks/FR1-12%20Prototype.ipynb) |
| Masked-media protocol tests | [test_stego.py](../test_stego.py) |
| Flask protocol and integration tests | [test_payload_protocol.py](../test_payload_protocol.py) and [test_webapp.py](../test_webapp.py) |
| Runtime and test dependencies | [requirements.txt](../requirements.txt) |
| Optional demonstration-notebook dependency | [requirements-notebook.txt](../requirements-notebook.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | This is an independent Git repository. Commit and push work from this directory. |
