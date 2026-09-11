# Agent Navigation Map — INF2005-ACW1

Use this map before editing an unfamiliar part of the repository.

## Map chain

| Scope | Map or rule |
| --- | --- |
| Current repository | This file: `docs/AGENT_MAP.md` |
| Parent workspace checkout | The parent `School-Repos` map is outside this standalone repository; this repository is currently an untracked nested repository there. |

## Documentation locations

| Content | Location |
| --- | --- |
| Documentation index | [docs/README.md](README.md) |
| Repository instructions | [AGENTS.md](../AGENTS.md) |
| Public setup and protocol usage | [README.md](../README.md) |
| Assignment specification transcription | [INF2005-ACW1-spec_v5-f2f.md](INF2005-ACW1-spec_v5-f2f.md) |

## Implementation locations

| Area | Start here |
| --- | --- |
| Signed payload protocol | [payload_protocol.py](../payload_protocol.py) |
| FR1 and FR5 Python functions | [FR1_FR5.py](../FR1_FR5.py) |
| Flask web scaffold | [stego_web/](../stego_web/) and [run.py](../run.py) |
| Lower-level Flask/LSB example | [webapp/](../webapp/) |
| Protocol tests | [test_payload_protocol.py](../test_payload_protocol.py) |
| Python dependencies | [requirements.txt](../requirements.txt) |
| Documentation checker | [scripts/check-docs.py](../scripts/check-docs.py) |
| Git-hook installer | [scripts/install-hooks.sh](../scripts/install-hooks.sh) |

## Repository boundaries

| Boundary | Rule |
| --- | --- |
| This repository | Independent Git repository on branch `yx`; commit and push its work from this directory. |
| Parent `School-Repos` checkout | It does not track this directory as a submodule or gitlink. Do not treat changes here as parent-repository changes unless its owner explicitly adds this repository. |
