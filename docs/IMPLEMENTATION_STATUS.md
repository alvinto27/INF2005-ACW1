# Implementation status

This repository has one web entry point: `run.py` creates the Flask application
from `stego_web`. The web package delegates payload creation, signing, packet
framing, and packet verification to `payload_protocol.py`; it delegates PNG and
PCM/WAV LSB operations to `stego_web/services/steganography.py`.

## Requirement coverage

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| FR1 image input | Implemented | PNG upload and RGB decoding. |
| FR2 audio input | Implemented | Uncompressed PCM/WAV upload and parsing. |
| FR3 payload generation | Implemented | Media ID, media type, timestamp, SHA-256 hash, nonce, and signed team metadata. |
| FR4 digital signature | Implemented | RSA-2048 RSA-PSS/SHA-256 signing and public-key verification. |
| FR5 image LSB embedding | Implemented | PNG engine supports 1-8 LSBs and framed packet storage. |
| FR6 audio LSB embedding | Implemented | PCM sample-byte engine supports 1-8 LSBs. |
| FR7 variable start location | Implemented | PBKDF2-HMAC-derived non-zero location; the shared secret is required for extraction. Document the security rationale in the demo report. |
| FR8 extraction and decoding | Implemented | Framing header identifies packet length; PNG and WAV extraction are registered engines. |
| FR9 hash verification | Implemented with original-cover requirement | Verify the signed original-file hash, then compare expected re-embedded media with received pixels/PCM data. See [limitations](DECODING_VERIFICATION.md). |
| FR10 verdict generation | Implemented | Authentic, Tampered, Signature Invalid, Payload Missing, Wrong Start Location, and Cannot Verify. |
| FR11 positive/negative cases | Automated coverage present | Current-encoder PNG/WAV round trips at all LSB depths, media/payload/signature tampering, malformed data, missing payloads, wrong keys/secrets, and upload limits are tested. Captured demo evidence is still needed. |
| FR12 evidence/reproducibility | Partially implemented | README, setup commands, tests, and API are present; add sample original/stego/tampered files, screenshots/logs, and key instructions for submission. |
| FR13 innovation | Candidate implemented | Keyed start-location derivation plus selectable 1-8 LSB depth; explain trade-offs and limitations in the report. |

## Integration flow

1. `run.py` calls `stego_web.create_app()` and serves the GUI.
2. `/encode` parses the request and delegates to `EncodingPipeline`.
3. `CoverMediaHandler` detects and fully validates PNG or PCM/WAV bytes.
4. `CryptoManager` computes the SHA-256 cover hash.
5. `PayloadBuilder` creates canonical JSON from the precomputed hash and metadata.
6. `CryptoManager` loads the uploaded encrypted private key, signs the payload, and frames the signed packet.
7. `HmacStartLocation` derives a non-zero carrier-unit index from the shared secret and stable carrier properties.
8. `LSBEncoder` and the selected media engine embed at that exact location and export PNG/WAV bytes.
9. `/decode` delegates to `VerificationPipeline`: validates received media, recovers LSB count and location, extracts STG1, validates packet lengths and signed schema, and verifies the signature.
10. With an original cover, verify its signed hash and re-embed the extracted packet to compare expected and received decoded-media hashes. The GUI displays each check separately.

Encoding loads a pre-existing encrypted PEM key and does not return private-key
material. `/keys/generate` is an explicit localhost setup helper; production use
still requires persistent key management, access control, rotation, and auditing.
