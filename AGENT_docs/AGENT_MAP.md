# Agent Navigation Map — INF2005-ACW1

Use this map before editing an unfamiliar part of the repository.

## Map chain

| Scope | Map or rule |
| --- | --- |
| Current repository | This file: `AGENT_docs/AGENT_MAP.md` |
| Parent workspace checkout | [School Repos map](../../../docs/AGENT_MAP.md); this repository is a tracked submodule there. |

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
| Caller-added optional seal and content-type design | [PAYLOAD-ENVELOPE-DESIGN.md](PAYLOAD-ENVELOPE-DESIGN.md) |
| Protocol version 2 design and remaining implementation stages | [LOCATION-CONFIDENTIALITY-PLAN.md](LOCATION-CONFIDENTIALITY-PLAN.md) |
| Handoff brief for the version 2 build | [ORCHESTRATION-HANDOFF.md](ORCHESTRATION-HANDOFF.md) |
| Completed version 2 stage outcomes and measurements | [PROTOCOL-V2-STAGE-RECORD.md](PROTOCOL-V2-STAGE-RECORD.md) |
| Shelved chunked-carrier architecture note | [STREAMING-CARRIER-NOTE.md](STREAMING-CARRIER-NOTE.md) |
| Outstanding assignment work | [OUTSTANDING-WORK.md](OUTSTANDING-WORK.md) |

## Implementation locations

| Area | Start here |
| --- | --- |
| Public protocol API | [stego/__init__.py](../stego/__init__.py) |
| Constants and domain separators | [stego/constants.py](../stego/constants.py) |
| Validation and LSB primitives | [stego/bits.py](../stego/bits.py) |
| Layout, masked hash, and signing input | [stego/layout.py](../stego/layout.py) |
| Bootstrap envelope and authenticated data | [stego/bootstrap.py](../stego/bootstrap.py) |
| Payload records and serialisation | [stego/packet.py](../stego/packet.py) |
| RSA-PSS keys, signatures, fingerprints, and PEM | [stego/crypto.py](../stego/crypto.py) |
| Carrier-derived capacity and field widths | [stego/layout.py](../stego/layout.py) |
| PNG and WAV adapters | [stego/media.py](../stego/media.py) |
| End-to-end encrypted encode and receiver-gated verification (stage 4c) | [stego/core.py](../stego/core.py) |
| FR1–FR12 demonstration notebook | [notebooks/FR1-12 Prototype.ipynb](../notebooks/FR1-12%20Prototype.ipynb) |
| Masked-media protocol tests | [test_stego.py](../test_stego.py) |
| Runtime and test dependencies | [requirements.txt](../requirements.txt) |
| Optional demonstration-notebook dependency | [requirements-notebook.txt](../requirements-notebook.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | Independent Git repository on branch `yx`; commit and push its work from this directory. |
| Parent `School-Repos` checkout | It tracks this directory as a submodule or gitlink. Do not treat changes here as parent-repository changes unless its owner explicitly requests them. |
