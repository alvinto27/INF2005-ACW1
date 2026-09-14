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
- [Masked Media Integrity Design](INTEGRITY-DESIGN.md) — the current packet, hashing, signing, discovery, verdict, and limitation design, followed by the design history: how the design was reached, what was rejected, and the known rough edges.
- [Payload Envelope Design](PAYLOAD-ENVELOPE-DESIGN.md) — the caller-side layers inside `user_payload`: the sealed encryption blob, the content-type header, the declared-against-actual cross-check, the handler table, capacity, and limitations.
- [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — **proposed, not built.** Protocol version 2: an encrypted bootstrap that hides the user-selected start location, length, and LSB depth from everyone except the intended receiver. Holds the field-binding audit, the decode-order invariant, the accepted trade-offs, and the staging plan.
- [Orchestration Handoff](ORCHESTRATION-HANDOFF.md) — orientation for whoever picks up the version 2 build: reading order, environment, why the stages are in this order, the working method, open decisions, the next action and its hazards, and the loose ends.
- [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — what each completed stage of the version 2 plan changed, what was measured, and what it taught. The plan holds intent; this holds outcome.
- [Streaming Carrier Note](STREAMING-CARRIER-NOTE.md) — **shelved, not planned.** Why whole-carrier arrays force the 64 MiB WAV cap, what seekable chunked access would fix, what it would cost, and the conditions for revisiting it.
- [Outstanding Work](OUTSTANDING-WORK.md) — assignment work that remains to be built, demonstrated, or assembled.
