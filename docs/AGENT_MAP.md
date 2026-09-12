# Agent Navigation Map — INF2005-ACW1

Use this map before editing an unfamiliar part of the repository.

## Map chain

| Scope | Map or rule |
| --- | --- |
| Current repository | This file: `docs/AGENT_MAP.md` |
| Parent workspace checkout | [School Repos map](../../../docs/AGENT_MAP.md); this repository is currently an untracked nested repository there. |

## Documentation locations

| Content | Location |
| --- | --- |
| Documentation index | [docs/README.md](README.md) |
| Repository instructions | [AGENTS.md](../AGENTS.md) |
| Public setup and protocol usage | [README.md](../README.md) |
| Assignment specification transcription | [INF2005-ACW1-spec_v5-f2f.md](INF2005-ACW1-spec_v5-f2f.md) |
| Current masked-media integrity design and design history | [INTEGRITY-DESIGN.md](INTEGRITY-DESIGN.md) |
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
| Parent `School-Repos` checkout | It does not track this directory as a submodule or gitlink. Do not treat changes here as parent-repository changes unless its owner explicitly adds this repository. |
