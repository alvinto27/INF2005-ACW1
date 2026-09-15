# Documentation — INF2005-ACW1

This index lists durable documentation for the signed payload protocol repository. The `docs/` directory holds the assignment specification we were given; `AGENT_docs/` holds the records this project maintains.

## Navigation

For repository structure and implementation entry points, see [Agent Navigation Map](AGENT_MAP.md).

## Repository entry points

- [README](../README.md) — setup and the masked-media integrity invariant.
- [stego package](../stego/__init__.py) — public API for the modular signed steganography implementation.
- [test_stego.py](../test_stego.py) — masked-media protocol implementation tests.
- [AGENTS](../AGENTS.md) — agent working instructions.

## Records

- [Agent Navigation Map](AGENT_MAP.md) — repository paths and Git boundaries.
- [Assignment Specification Transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) — visible assignment requirements transcribed from the supplied PDF; hidden prompt injection excluded.
- [Protocol Design](PROTOCOL-DESIGN.md#protocol-design) — the current reduced encrypted packet, fixed-width fields, hashing, signing, receiver bootstrap, verdicts, refusal behavior, typed-payload metadata, and version 1 design history.
- [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — historical protocol version 2 design; stages 0 through 6b complete and 6c cancelled. Its wire-format claims are superseded by the reduction record; its field-binding audit and accepted trade-offs remain useful.
- [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — what each completed stage of the version 2 plan changed, what was measured, and what it taught. The plan holds intent; this holds outcome.
- [Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md#streaming-carrier-plan) — **deferred and upcoming.** Why whole-carrier arrays force the 64 MiB WAV cap, why the cap and seekable chunked access are one topic, what the change would cost, and the conditions for revisiting it.
- [Work Not Built](WORK-NOT-BUILT.md#work-not-built) — assignment work that remains to be built, demonstrated, or assembled.
- [KISS Reduction Specification](REDUCTION-SPEC.md) — the approved reduction goals and constraints.
- [KISS Reduction Record](KISS-REDUCTION-RECORD.md) — the committed reduction outcome, measurements, decisions, and lessons.
