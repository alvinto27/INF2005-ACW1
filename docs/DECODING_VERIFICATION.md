# Decoding and verification

## Compatibility and architecture

The current encoder and its payload schema, RSA-PSS/SHA-256 algorithm, secret
derivation, RGB order, and PCM-byte order are unchanged. The existing image and
audio extractors now share a bounded frame parser. Media loaders additionally
reject invalid PNG checksums, oversized decoded PNGs, and empty/truncated PCM.

`POST /decode` in `stego_web/routes.py` delegates to
`stego_web/services/verification_pipeline.py`. `VerificationPipeline` uses:

- `CoverMediaHandler` for content-based media detection and validation.
- `SteganographyRegistry` and its existing PNG/WAV engines for extraction.
- `HmacStartLocation` and `LSBEncoder.read` to reverse embedding.
- `CryptoManager.verify_signed_packet` and the existing byte-only
  `payload_protocol.py` signature verification functions.
- The same engine's `embed` method, using the extracted packet, to reconstruct
  expected media. No private key or new signature is needed for this operation.

The browser controller is `stego_web/static/verify.js`; the section shares the
existing template and stylesheet. It uses text-only DOM insertion for result
values, handles JSON/non-JSON failures and timeouts, and prevents duplicate submits.

## Existing format

Embedding begins at the secret-derived non-zero carrier-unit index and wraps
at the end of the flat carrier array:

```text
STG1 (4 bytes) | LSB count (1 byte) | packet length (4 bytes, big endian)
    packet = JSON length (4 bytes, big endian) | UTF-8 JSON | RSA signature
```

STG1 is the frame version; the JSON has no separate version field. An unsupported
STG version is rejected. The signature length comes from the supplied public RSA
key (256 bytes for RSA-2048). Packet reads must fit the carrier and the existing
4 MiB packet limit. Unlike the low-level protocol's permissive buffer API, the
web verifier rejects trailing bytes inside a declared STG1 packet.

The signature covers the exact extracted JSON bytes. After signature validation,
the verifier checks the existing required fields: media ID/type, timestamp,
SHA-256 hex hash, 128-bit nonce, and team/sender metadata. It never reconstructs
JSON before checking the signature. Malformed but signed JSON is Cannot Verify.

Media type is detected from content. In automatic LSB mode, counts 1 through 8
are tried at the existing derived position. Exactly one recognizable, bounded
STG1 frame is required. Multiple candidates require manual LSB selection; header
recognition alone is not authentication. A missing header cannot prove whether
the secret is wrong, the LSB count is wrong, the header was damaged, or the file
never contained a packet. Those cases return Payload Missing with an explanation.
The Wrong Start Location category remains available, but is not asserted without
evidence that distinguishes it from absence.

## Integrity semantics

The encoder signs SHA-256 of the **exact original cover file bytes**. Embedding
overwrites bits, so those bytes cannot be recovered losslessly from the stego
alone. Full verification therefore requires the original file as an additional
input, without changing the current format:

1. Validate the signature and payload schema.
2. Hash the supplied original file with the existing `CryptoManager.hash_cover`.
3. Compare against the signed `media_hash`. Mismatch is Tampered.
4. Re-embed the extracted packet into that verified original using the current
   engine, shared secret, and recovered LSB count. Reuse the exact signature;
   generating a fresh PSS signature would produce different embedded bits.
5. Hash and compare expected and received decoded media representations.
   PNG uses dimensions plus RGBA bytes (the encoder emits opaque RGB). WAV uses
   channel count, sample width, sample rate, frame count, and PCM frame bytes.
6. Only matching signature, original hash, and decoded-media hash yield Authentic.

The result distinguishes `stored_hash`/`computed_hash` (original-file hashes)
from `expected_media_hash`/`received_media_hash` (decoded-media comparisons).
If received media changes outside the packet, the signature may remain valid
while `received_media_valid` and `integrity_valid` become false: Tampered.
If the embedded signature is corrupted, Signature Invalid takes precedence.

## API and result fields

`POST /decode` accepts multipart uploads `stego`, `public_key`, and optional
`original_cover`; form fields are `start_secret`, optional `media_type`
(`auto`, `image`, `audio`), and optional `lsb_bits` (`auto` or 1-8).
It shares the app's 32 MiB request limit. Missing fields/invalid form values use
HTTP 400, missing payload uses 422, oversize uploads use 413, and processed
verification results use 200. Check the JSON verdict, not just HTTP success.

Results include verdict and explanation, extraction/signature/integrity status,
media type, file name/size, LSB count, recovered position and unit name, capacity,
packet/payload/signature sizes, frame version, authenticated payload and nonce,
and both hash comparisons. Unperformed checks are null, distinct from false.
Private keys and shared secrets are never included in decoder results.

## Tests and limitations

Run `python -m unittest -v`. `test_webapp.py` generates covers in memory and
encodes them with the current `/encode` endpoint. Tests cover manual/automatic
decoding of PNG and WAV at all eight LSB depths; changes outside the payload;
wrong keys, secrets and LSB settings; invalid/truncated files and keys; malformed
signed JSON/schema; corrupt signatures/payloads; impossible packet lengths,
unsupported frame versions, and oversized requests. Existing encoder/protocol
tests remain in the suite.

- Without the original file, report a valid signature but Cannot Verify integrity.
- Authentic means matching decoded media, not byte-for-byte identical container
  serialization. PNG ancillary metadata/compression and WAV ancillary chunks
  are outside the received-media comparison.
- A destroyed header cannot reliably distinguish tampering from no payload.
- Authenticity is relative to a trusted public key supplied by the receiver.
  There is no key directory or certificate trust system.
- The current format does not enforce replay protection or encrypt payloads.
- Carrier indices remain RGB channel bytes and PCM bytes, preserving existing
  files. The decoder does not reinterpret them as whole pixels or PCM samples.
- The older historical location algorithm that included LSB count is not the
  current encoder format; this add-on does not silently migrate old files.
