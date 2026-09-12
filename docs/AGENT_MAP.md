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
| Initial hashing and integrity design | [HASHING-INTEGRITY-DESIGN.md](HASHING-INTEGRITY-DESIGN.md) |
| Hashing, integrity, and partly superseded key-trust design | [Hashing_and_Integrity_Design_Revised.md](Hashing_and_Integrity_Design_Revised.md) |
| Obsolete FR1 and FR5 algorithm checklist | [TODO.md](TODO.md) |

## Implementation locations

| Area | Start here |
| --- | --- |
| Signed v1 steganography protocol | [stego_v1.py](../stego_v1.py) |
| FR1–FR12 prototype notebook | [notebooks/FR1-12 Prototype.ipynb](../notebooks/FR1-12%20Prototype.ipynb) |
| Signed v1 protocol tests | [test_stego_v1.py](../test_stego_v1.py) |
| Python dependencies | [requirements.txt](../requirements.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | Independent Git repository on branch `yx`; commit and push its work from this directory. |
| Parent `School-Repos` checkout | It does not track this directory as a submodule or gitlink. Do not treat changes here as parent-repository changes unless its owner explicitly adds this repository. |
