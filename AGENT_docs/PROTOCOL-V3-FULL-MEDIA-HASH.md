# Protocol Version 3: Full Media Hash and RGBA PNG

**Status: implemented.** This note defines the protocol version 3 change. It replaces version 2; it does not add a second encode or verify format. The legacy `STG1` module is separate and remains unchanged.

## 1. Goals and unchanged rules

Version 3 hashes all picture and sound sample bytes that belong to the media data. It also accepts 8-bit RGBA PNG covers. The PNG alpha channel is never changed, but it is included in the hash.

These rules stay unchanged:

- The bootstrap fields and layout stay the same, except the version byte is `3`.
- The encrypted record, RSA-OAEP bootstrap, AES-GCM encryption, RSA-PSS signature, capacity math, and verdict meanings stay the same.
- One PNG carrier unit is still one 8-bit R, G, or B value. RGB and RGBA have three carrier units per pixel.
- One WAV carrier unit is still the least-significant byte of one PCM sample.
- The active protocol does not encode or verify version 2 files after this change.
- The legacy `STG1` protocol is not part of this change.

## 2. Version 3 media-hash rule

The hash has two streams. The hasher treats both streams as bytes and does not know which medium produced them.

1. `unit_digest` is SHA-256 over the carrier-unit bytes in order, after the current masking rules are applied:
   - clear the lowest bit in units `[0, bootstrap_span)`;
   - clear the lowest `lsb_count` bits in units `[start_unit, start_unit + footprint)`; this includes alignment padding.
2. `fixed_digest` is SHA-256 over all fixed bytes in media-data order. A fixed byte is a media-data byte that embedding never writes. Empty input has the normal SHA-256 empty digest.
3. `fixed_byte_count` is the number of bytes supplied to `fixed_digest`. It must match the backend's declared count and fit in an unsigned 64-bit protocol field.
4. The final media hash is:

```python
media_hash = SHA256(
    b"INF2005-ACW1\x00MEDIA-HASH-V3\x00"
    + struct.pack(">BB", media_code, lsb_count)
    + encode_protocol_field(total_units, "total_units")
    + encode_protocol_field(fixed_byte_count, "fixed_byte_count")
    + encode_protocol_field(start_unit, "start_unit")
    + encode_protocol_field(footprint, "footprint")
    + encode_protocol_field(bootstrap_span, "bootstrap_span")
    + unit_digest
    + fixed_digest
)
```

All integer fields are unsigned 64-bit big-endian values. The two stream digests are exactly 32 bytes each. The new domain string separates version 3 hashes from version 2 hashes. The fixed-byte count is part of the final hash, so an empty fixed stream and a stream with a different length cannot be confused.

The `>BB` context prefix remains media code followed by LSB count. The fixed PNG or WAV `media_context` remains in the RSA-PSS signing input, as it is today. It is not appended to either sample-byte stream.

The unit stream and fixed stream are processed together for each carrier chunk. Chunk size and chunk boundaries do not change either digest. The hasher checks the number of units and fixed bytes at the end.

## 3. Fixed-byte definitions and backend interface

Add a bounded backend operation that yields `(unit_chunk, fixed_bytes)` from the same media read. `unit_chunk` is a `uint8` NumPy array. `fixed_bytes` is a `bytes` value in media-data order for that chunk. The core sends both values to the media-neutral hasher.

Keep `read_units()` and `iter_chunks()` as bounded unit-only operations. Add `iter_chunks_with_fixed_bytes()` to `CarrierSource`; its default result pairs each unit chunk with `b""`. `ArrayCarrier` uses this default and declares zero fixed bytes. `PngCarrier` and `WavCarrier` provide their fixed bytes while reading the corresponding chunk. This avoids another carrier pass and does not make the hasher medium-specific.

| Backend | Carrier units | Fixed bytes supplied with each chunk | Total fixed-byte count |
| --- | --- | --- | ---: |
| RGB PNG | R, G, and B, in pixel order | none | `0` |
| RGBA PNG | R, G, and B, in pixel order | one alpha byte per pixel, in pixel order | `width * height` |
| 8-bit PCM WAV | the one byte in each sample | none | `0` |
| 16-, 24-, or 32-bit PCM WAV | the first, least-significant byte of each sample | every other byte of each declared sample, in sample-byte order | `frame_count * channels * (sample_width - 1)` |

For PNG, chunks supplied to the paired operation are pixel-aligned. A small requested chunk size still yields at least one complete pixel. For WAV, chunks remain whole PCM frames. The backend reads each chunk's media data once to produce both outputs. `rewrite_to_path()` uses that same read to hash original bytes and write the changed carrier units. It accepts an optional fixed-byte callback for the second-pass hash; the existing two-argument unit transform stays unchanged.

Encoding keeps its current two full media passes: one hash/plan pass and one embed/write pass. Verification keeps its bootstrap read, packet read, and one full media pass for the hash. The new fixed stream is read during those existing passes; it adds no pass over the file.

## 4. PNG inputs and media contexts

Accept only single-frame, 8-bit PNG images in `RGB` or `RGBA` mode. Refuse palette, grayscale, 16-bit, animated, and other PNG modes. Keep `UnSupportedFileType` for a file that is not a PNG.

The adapter must not hide a specific format error behind a general "unreadable or unsupported" message. Preserve clear errors through the file API and web response. Use these messages for input failures:

| Input failure | Error text |
| --- | --- |
| PNG mode is not RGB or RGBA, including palette and grayscale | `PNG must be RGB or RGBA; palette and grayscale images are not supported` |
| PNG IHDR does not describe 8-bit RGB or RGBA samples | `PNG must use 8-bit RGB or RGBA samples` |
| PNG has more than one frame | `animated PNG images are not supported` |
| PNG pixel count exceeds twice Pillow's configured limit | `PNG image is too large: {pixels:,} pixels exceeds the limit of {limit:,}` |
| File is not a PNG | Keep `UnSupportedFileType` and its `unsupported file type: ...` message. |

Do not catch these known `ValueError` messages and replace them with a generic RGB-only error. The verify adapter reports a clear carrier-format failure as `Cannot Verify` with that detail.

PNG media context changes from `struct.pack(">II", width, height)` to exactly:

```python
struct.pack(">IIB", width, height, channel_count)
```

The field order is width, height, channel count. `channel_count` is `3` for RGB or `4` for RGBA. `PngCarrier.channel_count` exposes this value as a read-only property. RGB and RGBA images with equal width and height therefore have different signed contexts.

WAV context does not change. It remains `struct.pack(">HBIQ", channels, sample_width, frame_rate, frame_count)`. It already binds the sample width.

## 5. Version handling and version 2 files

`PROTOCOL_VERSION` is `3`. The encoder writes that value in the bootstrap and the signing input. Bootstrap serialization and parsing both require the current constant. Verification must not try a version 2 fallback.

A version 2 file addressed to the supplied receiver reaches this path:

1. RSA-OAEP opens the bootstrap. This step does not reject its version.
2. `parse_bootstrap()` calls the bootstrap-field validator.
3. The validator compares the byte with `PROTOCOL_VERSION` and raises `ValueError("unsupported bootstrap version")`.
4. `decode_carrier_source()` catches that error and returns `Cannot Verify`, with detail `unsupported bootstrap version`.

The verifier stops before reading the packet, checking the signature, decrypting the record, or comparing the media hash. A version 2 file therefore returns `Cannot Verify`, never `Tampered`. A bootstrap that cannot be opened keeps the existing `Payload Missing` result; it is not classified as a readable version 2 bootstrap.

## 6. On-disk effect and known limits

| Input | Version 3 change |
| --- | --- |
| RGB PNG | PNG context gains channel count `3`; the hash domain and final hash structure change. The alpha stream is empty. |
| RGBA PNG | New accepted format. RGB units are embedded; alpha is preserved byte-for-byte and included in the fixed-byte hash. |
| 8-bit PCM WAV | WAV context and carrier units stay the same. The media-hash domain and final hash structure change; the fixed stream is empty. |
| 16-, 24-, and 32-bit PCM WAV | The context and carrier units stay the same. The high bytes of every declared sample enter the fixed-byte hash. Changing one gives `Tampered`. |

The hash does not detect a tool that clears or changes RGB colour values in fully transparent RGBA pixels. Those colour values are carrier units, and changing them can cause `Tampered` or make the bootstrap unreadable (`Payload Missing`). RGB PNG `tRNS` transparency is not supported as an alpha channel; PNG ancillary chunks, including `tRNS`, are outside the hash scope.

The hash covers decoded PNG pixel samples and declared WAV PCM sample bytes only. It does not cover PNG ancillary chunks or WAV chunks outside the declared PCM `data` samples, including `LIST` data. It does not cover PNG file encoding choices. The verification race remains: if media data changes between targeted reads and the final hash pass, one verification can observe more than one file state.

## 7. Validation record

Stage 2 added these checks to `test_stego.py`:

- Use test-local reference helpers that read raw pixel/sample bytes and calculate both streams without calling the production hasher.
- Compare the two-stream result across chunk sizes, including chunks with fixed bytes; check both unit and fixed-byte counts.
- Verify an alpha change in an encoded RGBA PNG gives `Tampered`; verify RGBA encode/decode is `Authentic` and every alpha byte is unchanged.
- Verify RGB and RGBA contexts differ for the same width and height.
- Extend the multi-byte WAV test with a changed high sample byte and require `Tampered`.
- Make a receiver-readable bootstrap with version byte `2`; require `Cannot Verify` and exact detail `unsupported bootstrap version`, not `Tampered`.
- Keep the optional large-WAV test and its bounded-memory limit.

Stage 3 added these checks to `test_webapp.py`:

- Require the protocol-version fields in successful encode and verify responses to equal the library constant.
- Upload an RGBA PNG through the web route, verify it as `Authentic`, and preserve its alpha bytes.
- Require the exact palette-PNG format error during both encode and verify.
- Keep the existing RGB and WAV web round trips and invalid-key tests.

Stage 3 updated and re-executed the demonstration notebook:

- Keep the committed `samples/Banana.png` RGB image as the main carrier without converting it.
- Build a separate RGBA carrier in `DEMO_DIR` from that sample. Add a fully transparent border and a half-transparent band. Do not read from `~/Downloads` or add a sample file.
- Show RGBA encode/verify as `Authentic`, alpha bytes unchanged, then one alpha change as `Tampered`.
- Show a multi-byte WAV high-byte change as `Tampered`.

## 8. Stage file boundaries

Stage 2 changed the library and its tests only:

- `stego/constants.py`, `stego/bootstrap.py`, `stego/layout.py`, `stego/carrier.py`, `stego/media.py`, `stego/core.py`, and `stego/__init__.py`;
- `test_stego.py`.

Stage 3 changed the web, notebook, current documentation, and project instructions:

- Web: `stego_web/routes.py`, `stego_web/services/current_protocol.py`, `stego_web/static/app.js`, `stego_web/static/verify.js`, `stego_web/templates/index.html`, and `test_webapp.py`.
- Notebook: `notebooks/FR1-12 Prototype.ipynb`.
- Current docs and instructions: `AGENTS.md`, `README.md`, `AGENT_docs/README.md`, `AGENT_docs/AGENT_MAP.md`, `AGENT_docs/PROTOCOL-DESIGN.md`, `AGENT_docs/PROTOCOL-COMPATIBILITY.md`, `AGENT_docs/DECODING-VERIFICATION.md`, `AGENT_docs/IMPLEMENTATION-STATUS.md`, and `AGENT_docs/STREAMING-CARRIER-PLAN.md`.
- Current-state records checked and updated: `AGENT_docs/WORK-NOT-BUILT.md` and `AGENT_docs/REDUCTION-SPEC.md`.
- Keep `payload_protocol.py` and `test_payload_protocol.py` unchanged. Keep historical records, including `KISS-REDUCTION-RECORD.md`, `PROTOCOL-V2-STAGE-RECORD.md`, and `LOCATION-CONFIDENTIALITY-PLAN.md`, unchanged.

Stages 1, 2, and 3 are complete. The active library and web application use protocol version 3. This record describes the implemented format and its known limits.
