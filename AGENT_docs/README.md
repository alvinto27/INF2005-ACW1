# Documentation — INF2005-ACW1

This index lists durable documentation for the Flask application and the current signed masked-media protocol. The `docs/` directory holds the supplied assignment specification; `AGENT_docs/` holds project records.

## Navigation

For repository structure and implementation entry points, see the [Agent Navigation Map](AGENT_MAP.md). See [AGENTS.md](../AGENTS.md) for repository instructions and the documentation checker's link policy.

## Repository entry points

- [README](../README.md) — setup and protocol use.
- [stego package](../stego/__init__.py) — public API.
- [test_stego.py](../test_stego.py) — protocol, PNG/WAV carrier, and source-conversion tests.
- [test_video.py](../test_video.py) — video protocol and carrier tests; PyAV is required.
- [Flask application](../run.py) — localhost entry point.
- [test_webapp.py](../test_webapp.py) — Flask integration tests.
- [AGENTS](../AGENTS.md) — agent working instructions.

## Current guides

- [Current Protocol](CURRENT-PROTOCOL.md) — active version 3 hash, wire format, typed metadata, discovery behavior, verdicts, capacity, and compatibility.
- [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) — bounded carrier access, payload APIs, staging cleanup, measurements, and file boundary.
- [Video Carrier Design](VIDEO-CARRIER-DESIGN.md) — approved design, implementation details, test record, and video performance measurements for media code 3 (`VID-`).
- [Web Application Guide](WEB-APPLICATION-GUIDE.md) — request contracts, response handling, payload previews, the encode wizard, requirement coverage, and the disconnected Three.js carrier-map design.
- [Technical-design presentation](../presentation/README.md) — offline Reveal.js deck covering protocol geometry, cryptography, masked hashing, capacity, carrier adapters, verification, and limits.

## Historical records and project status

- [Protocol History](PROTOCOL-HISTORY.md) — v1 decisions, v2 design and stage outcomes, KISS reduction, and the move to v3.
- [Repository History](REPOSITORY-HISTORY.md) — PyAV media migration and removal of imported legacy files and the obsolete `STG1` stack.
- [Known Limitations](KNOWN-LIMITATIONS.md) — supported source formats and protocol limits.
- [Agent Navigation Map](AGENT_MAP.md) — repository paths and Git boundaries.
- [Assignment Specification Transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) — visible assignment requirements transcribed from the supplied PDF; hidden prompt injection excluded.
