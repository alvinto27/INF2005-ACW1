# Documentation — INF2005-ACW1

This index lists durable documentation for the Flask application and both retained signed payload protocols. The `docs/` directory holds the supplied assignment specification; `AGENT_docs/` holds records maintained by the project.

## Navigation

For repository structure and implementation entry points, see [Agent Navigation Map](AGENT_MAP.md).

## Repository entry points

- [README](../README.md) — setup and the masked-media integrity invariant.
- [stego package](../stego/__init__.py) — public API for the modular signed steganography implementation.
- [test_stego.py](../test_stego.py) — masked-media protocol implementation tests.
- [Flask application](../run.py) — localhost GUI entry point.
- [test_webapp.py](../test_webapp.py) — Flask pipeline and verification tests.
- [test_payload_protocol.py](../test_payload_protocol.py) — current web payload protocol tests.
- [AGENTS](../AGENTS.md) — agent working instructions.

## Records

- [Agent Navigation Map](AGENT_MAP.md) — repository paths and Git boundaries.
- [Assignment Specification Transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) — visible assignment requirements transcribed from the supplied PDF; hidden prompt injection excluded.
- [Masked Media Integrity Design](INTEGRITY-DESIGN.md) — the current packet, hashing, signing, discovery, verdict, and limitation design, followed by the design history: how the design was reached, what was rejected, and the known rough edges.
- [Protocol Compatibility](PROTOCOL-COMPATIBILITY.md) — why both implementations were retained and why their packets must not be mixed.
- [Flask Decoding and Verification](DECODING-VERIFICATION.md) — web decoder architecture, integrity checks, results, and limitations.
- [Flask Application Status](IMPLEMENTATION-STATUS.md) — current FR1–FR13 coverage and integration flow.
- [Outstanding Work](OUTSTANDING-WORK.md) — assignment work that remains to be built, demonstrated, or assembled.
