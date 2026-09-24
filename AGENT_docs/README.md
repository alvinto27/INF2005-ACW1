# Documentation — INF2005-ACW1

This index lists durable documentation for the Flask application and both retained signed payload protocols. The `docs/` directory holds the supplied assignment specification; `AGENT_docs/` holds records maintained by the project.

## Navigation

For repository structure and implementation entry points, see [Agent Navigation Map](AGENT_MAP.md). See [AGENTS.md](../AGENTS.md) for the documentation checker's link policy.

## Repository entry points

- [README](../README.md) — setup and the masked-media integrity invariant.
- [stego package](../stego/__init__.py) — public API for the modular signed steganography implementation.
- [test_stego.py](../test_stego.py) — masked-media protocol implementation tests.
- [Flask application](../run.py) — localhost GUI entry point.
- [test_webapp.py](../test_webapp.py) — Flask pipeline and verification tests.
- [test_payload_protocol.py](../test_payload_protocol.py) — retained legacy `STG1` payload protocol tests.
- [AGENTS](../AGENTS.md) — agent working instructions.

## Records

- [Agent Navigation Map](AGENT_MAP.md) — repository paths and Git boundaries.
- [Assignment Specification Transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) — visible assignment requirements transcribed from the supplied PDF; hidden prompt injection excluded.
- [Protocol Design](PROTOCOL-DESIGN.md#protocol-design) — the current reduced encrypted packet, fixed-width fields, hashing, signing, receiver bootstrap, verdicts, refusal behavior, typed-payload metadata, and version 1 design history.
- [Protocol Version 3 Full Media Hash](PROTOCOL-V3-FULL-MEDIA-HASH.md) — implemented version 3 sample-byte hash, RGBA PNG, version handling, tests, and known limits.
- [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — historical protocol version 2 design; stages 0 through 6b complete and 6c cancelled; its deferred decision 14 is superseded by the Streaming Carrier Plan. Its wire-format claims are superseded by the reduction record; its field-binding audit and accepted trade-offs remain useful.
- [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — what each completed stage of the version 2 plan changed, what was measured, and what it taught. The plan holds intent; this holds outcome.
- [Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md#streaming-carrier-plan) — **library and web-boundary refactors implemented.** The carrier backend interface, two-pass encoding, targeted-read verification, streamed WAV backend, chunk-size measurements, memory claim, deleted whole-file WAV cap, and known limits.
- [Payload Handling](PAYLOAD-HANDLING.md) — data flow and measured memory changes for packed packet handling and URL-based recovered-payload downloads, including plaintext-at-rest risk and deferred work.
- [Payload Streaming Design](PAYLOAD-STREAMING-DESIGN.md) — approved design for chunked AES-GCM, prehashed RSA-PSS, payload-path APIs, authenticated file release, tests, and web integration.
- [Work Not Built](WORK-NOT-BUILT.md#work-not-built) — assignment work that remains to be built, demonstrated, or assembled.
- [KISS Reduction Specification](REDUCTION-SPEC.md) — the approved reduction goals and constraints.
- [KISS Reduction Record](KISS-REDUCTION-RECORD.md) — the committed reduction outcome, measurements, decisions, and lessons.
- [Flask Application Status](IMPLEMENTATION-STATUS.md) — current web inputs, protocol-v3 integration, requirement coverage, and request flow.
- [Flask Decoding and Verification](DECODING-VERIFICATION.md) — receiver-gated verification inputs, response fields, payload-preview controls, tests, and limitations.
- [Protocol Compatibility](PROTOCOL-COMPATIBILITY.md) — the boundary between active version-3 web files, rejected version-2 files, and retained legacy `STG1` files.
