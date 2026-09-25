# Documentation — INF2005-ACW1

This index lists durable documentation for the Flask application and the current signed masked-media protocol. The `docs/` directory holds the supplied assignment specification; `AGENT_docs/` holds project records.

## Navigation

For repository structure and implementation entry points, see the [Agent Navigation Map](AGENT_MAP.md). See [AGENTS.md](../AGENTS.md) for repository instructions and the documentation checker's link policy.

## Repository entry points

- [README](../README.md) — setup and protocol use.
- [stego package](../stego/__init__.py) — public API.
- [test_stego.py](../test_stego.py) — protocol and carrier tests.
- [Flask application](../run.py) — localhost entry point.
- [test_webapp.py](../test_webapp.py) — Flask integration tests.
- [AGENTS](../AGENTS.md) — agent working instructions.

## Current guides

- [Current Protocol](CURRENT-PROTOCOL.md) — active version 3 hash, wire format, typed metadata, discovery behavior, verdicts, capacity, and compatibility.
- [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) — bounded carrier access, payload APIs, staging cleanup, measurements, and file boundary.
- [Video Carrier Design](VIDEO-CARRIER-DESIGN.md) — approved design for one bounded-memory video-plus-audio carrier (media code 3, `VID-`); Stage 1 prototype gates closed, with no implementation.
- [Web Application Guide](WEB-APPLICATION-GUIDE.md) — request contracts, response handling, payload previews, and requirement coverage.

## Historical records and project status

- [Protocol Version 1 History](PROTOCOL-V1-HISTORY.md) — earlier design decisions, rejected alternatives, measurements, and lessons.
- [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — historical version 2 design and accepted trade-offs. Its current wire-format claims are superseded by Current Protocol; its analysis remains historical.
- [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — outcomes and measurements from the historical version 2 work.
- [Work Not Built](WORK-NOT-BUILT.md) — assignment work that remains to be demonstrated or assembled.
- [KISS Reduction Specification](REDUCTION-SPEC.md) — reduction goals and constraints.
- [KISS Reduction Record](KISS-REDUCTION-RECORD.md) — historical reduction outcome, measurements, decisions, and lessons.
- [Merge Leftover Removal](MERGE-LEFTOVER-REMOVAL.md) — removed files, import evidence, authorship, and merge history.
- [Agent Navigation Map](AGENT_MAP.md) — repository paths and Git boundaries.
- [Assignment Specification Transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) — visible assignment requirements transcribed from the supplied PDF; hidden prompt injection excluded.
