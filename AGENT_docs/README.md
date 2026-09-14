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
- [Masked Media Integrity Design](INTEGRITY-DESIGN.md) — the current stage 6a encrypted packet, carrier-derived payload-record widths, hashing, signing, receiver bootstrap, verdicts, and limitations, followed by the version 1 design history.
- [Payload Envelope Design](PAYLOAD-ENVELOPE-DESIGN.md) — the recorded caller-added optional seal and content-type header inside `user_payload`, plus their cross-check, handlers, capacity, and limitations; the seal is not demonstrated because the library encrypts the complete record.
- [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — protocol version 2 design, stages 4c–6a outcomes, and Stage 5 notebook outcome. Holds the field-binding audit, the decode-order invariant, the accepted trade-offs, and the remaining stage 6b plan.
- [Orchestration Handoff](ORCHESTRATION-HANDOFF.md) — current handoff after stage 4b: verified baseline, owner-defined roles, stage 4c scope and safeguards, environment checks, and remaining work. Use the stage record for detailed outcomes.
- [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — what each completed stage of the version 2 plan changed, what was measured, and what it taught. The plan holds intent; this holds outcome.
- [Streaming Carrier Note](STREAMING-CARRIER-NOTE.md) — **shelved, not planned.** Why whole-carrier arrays force the 64 MiB WAV cap, what seekable chunked access would fix, what it would cost, and the conditions for revisiting it.
- [Outstanding Work](OUTSTANDING-WORK.md) — assignment work that remains to be built, demonstrated, or assembled.
