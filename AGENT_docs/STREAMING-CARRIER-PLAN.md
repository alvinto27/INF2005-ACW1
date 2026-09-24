# Streaming Carrier Plan

**Status: library and web-boundary refactors implemented.** This record is the single source of truth for chunked carrier access and the removal of the whole-file WAV helpers and `MAX_WAV_FRAME_BYTES`. It supersedes the earlier deferred plan and [decision 14](LOCATION-CONFIDENTIALITY-PLAN.md#12-open-decisions) of the Location Confidentiality Plan.

The brief does not ask for this. It is an internal architecture change. It prepares a later video backend; video is not part of it.

## 1. What changed

Before, every path loaded the whole carrier into one NumPy array:

```text
file -> whole np.ndarray -> protocol
```

Now the protocol reads units through a carrier backend:

```text
file -> carrier backend -> bounded range and chunk reads -> protocol
```

| Medium | Backend | Why |
| --- | --- | --- |
| WAV | `WavCarrier` (streamed) | Reads whole PCM frames on demand. No part of it grows with the carrier size. |
| PNG | `PngCarrier` (file-backed) | Pillow decodes the image; bounded reads and rewrites keep protocol operations behind the backend. |

PNG and WAV use the same protocol core through file-backed carriers. The internal `CarrierSource` abstraction is not a public route for whole-carrier arrays.

## 2. Protocol invariants kept

The carrier refactor did not change the then-current version 2 wire format. Protocol version 3 later changed the hash domain, hash structure, bootstrap/signing version byte, and PNG context; see the [v3 full media hash record](PROTOCOL-V3-FULL-MEDIA-HASH.md). The payload record, bootstrap fields, AES-GCM data, media codes, capacity, preserved-bit calculations, and verdict meanings remain otherwise unchanged.

The layout and capacity functions in `stego/layout.py` still use only integers. The bit helpers in `stego/bits.py` still work on local array slices.

`test_stego.py` now uses independent raw-byte reference hashing for PNG pixels and WAV samples. It compares both hash streams across different chunk sizes.

## 3. Carrier abstraction

`stego/carrier.py` defines `CarrierSource`, an abstract base class:

| Member | Contract |
| --- | --- |
| `total_units` | The number of logical carrier units. |
| `fixed_byte_count` | Number of fixed media bytes paired with all chunks; defaults to zero. |
| `read_units(start_unit, count)` | A new uint8 array for one bounded range. An out-of-range request raises `CarrierAccessError`. |
| `iter_chunks()` | Every unit once, in fixed order, in bounded chunks. A storage failure raises `CarrierAccessError`. |
| `iter_chunks_with_fixed_bytes()` | Unit chunks paired with fixed bytes from the same media read; defaults to empty bytes. |

`CarrierAccessError` is a `ValueError`. The backend holds no payload, cryptography, or protocol policy. `PngCarrier` and `WavCarrier` are the public file-backed carrier classes, and `CarrierSource` is their public bounded-access interface. The array backend remains an implementation detail.

Writing is kept separate from reading. File-backed carriers provide a sequential `rewrite_to_path` method. It reads every chunk once, in order, gives each unit chunk to the existing two-argument transform, and writes the result. An optional fixed-byte callback hashes fixed bytes from that same read. No backend must support random-access writes.

## 4. Protocol flow

`stego/core.py` owns the protocol order. Backends supply units.

### Encode: two full passes

1. Check the inputs and plan the geometry before reading carrier data. The media hash has a fixed size, so the record length, ciphertext length, and footprint are known first.
2. **Pass 1.** `prepare_carrier_encoding` hashes every chunk with the bootstrap region and the future packet footprint masked. Then it builds the record, encrypts it, signs it, and seals the bootstrap. It returns a `CarrierEncoding`.
3. **Pass 2.** The backend reads the original carrier again. For each chunk, `CarrierEncoding.embed_chunk` hashes the original units, then writes the bootstrap and packet bits that overlap the chunk. It finds the overlap from global unit ranges, so no state carries over from one chunk to the next.
4. `CarrierEncoding.finish` makes sure that pass 2 saw exactly `total_units` units and that its hash of the original units equals the pass-1 hash. If they differ, the carrier changed between the passes, and the encode fails. `encode_wav` then deletes the incomplete output.

### Verify: two targeted reads and one full pass

1. Open the carrier and check its structure.
2. Read `[0, bootstrap_span)`, extract the envelope, and open it with RSA-OAEP.
3. Get the start unit, LSB count, ciphertext length, and AES material, and make the layout.
4. Read `[start_unit, start_unit + footprint)`, check the padding, and verify RSA-PSS.
5. Decrypt with AES-GCM and parse the record.
6. Make one full chunked pass for the masked media hash and compare it with the recovered hash.

The packet position is known only after the bootstrap is opened. So the backend must be seekable. Forward-only streaming cannot do this.

## 5. Incremental masked hash

`MaskedMediaHasher` in `stego/layout.py` streams two SHA-256 digests: masked carrier units and fixed media bytes. At the end, it checks both declared stream lengths and hashes the domain, media/LSB prefix, u64 fields, and two digests. For each unit chunk, it finds the overlap with the two mask regions:

| Region | Range | Bits cleared |
| --- | --- | --- |
| Bootstrap | `[0, bootstrap_span)` | lowest 1 |
| Packet | `[start_unit, start_unit + footprint)`, alignment padding included | lowest `lsb_count` |

It copies the chunk only when a region overlaps it, clears the bits in the overlapping slice, and updates the unit digest. The paired fixed bytes update the fixed digest. Chunk boundaries have no effect on the final digest. `calculate_masked_media_hash` keeps its signature and uses an empty fixed stream.

### Unit accounting

The hasher knows `total_units` and counts the units it receives. More units than `total_units` fail at once. Fewer units fail at `digest()`. So a hash over fewer units can never be accepted under a larger signed `total_units`.

For WAV, bytes after the declared data chunk are not carrier units. A carrier unit exists only for each sample in the declared frame count.

## 6. Failure mapping

| Failure | Result |
| --- | --- |
| WAV header invalid, compressed, or data shorter than the declared frame count, found when the file is opened | `verify_wav`: `Cannot Verify`, before any protocol read. `encode_wav`: `ValueError`. |
| Read failure, early end of data, or changed WAV header after opening | `CarrierAccessError`. During verification this gives `Cannot Verify`. |
| Wrong unit count from any backend | `ValueError` from the hasher. During verification this gives `Cannot Verify`. |
| Carrier changed between encode passes | `ValueError`; the output file is deleted. |

Raw `OSError`, `EOFError`, `wave.Error`, and `struct.error` do not escape from the public verification functions.

## 7. WAV backend

One carrier unit is the least-significant byte of one PCM sample, as before. WAV samples are little-endian, so that byte is at offset 0 of each sample. The other bytes of the sample are fixed media bytes. The writer preserves them, and the version 3 hash covers them. For N frames, a chunk has `N x channels` units for all sample widths.

| Item | Behaviour |
| --- | --- |
| Header check | `read_pcm_wav_info` reads only the header. Then it reads the last declared frame, so a short file fails early. It allocates nothing in proportion to the frame count. |
| Chunk | `frames_per_chunk = max(1, chunk_bytes // (channels x sample_width))`. A chunk never splits a sample or a frame. |
| Range read | `wave.setpos` goes to the first frame that holds the range, and only the frames that hold the range are read. |
| Reopen check | Each read opens the file again and confirms that the header is unchanged. |
| Output | `wave` writer with the frame count set first. The header is written once. Chunked output with no change is byte-identical to the old whole-file writer, and a test checks this. |

## 8. Chunk size

`DEFAULT_CHUNK_BYTES = 1 MiB` of raw PCM data, in `stego/carrier.py`. Tests use very small chunks, so the bootstrap and the packet cross chunk edges.

Measured hash-pass throughput on a 96 MiB 16-bit stereo WAV (warm page cache, one machine):

| Chunk | Throughput (MiB of PCM per second) | Traced peak memory |
| --- | --- | --- |
| 16 KiB | 1,420 | 0.17 MiB |
| 64 KiB | 1,733 | 0.28 MiB |
| 256 KiB | 1,834 | 0.75 MiB |
| **1 MiB** | **1,906** | **2.63 MiB** |
| 4 MiB | 1,758 | 10.13 MiB |
| 16 MiB | 1,414 | 40.13 MiB |

Why 1 MiB:

- It is the fastest size in this measurement.
- Its working memory is a few MiB.
- It is larger than the largest possible PCM frame (65,535 channels x 4 bytes), so each chunk holds at least one frame.

## 9. Memory claim

Memory is **not** constant. The carrier working memory does not grow with the carrier size. The total working memory grows with the packet size.

Packet embedding and extraction still hold `footprint x lsb_count` bits as one byte per bit. The loop in `read_lsb_bits` and `write_lsb_bits` runs one Python step per bit. This refactor did not change that.

Measured on the same 96 MiB WAV, `k = 3`:

| Payload | Encode | Encode peak | Verify | Verify peak |
| --- | --- | --- | --- | --- |
| 673 B | 0.19 s | 4.3 MiB | 0.06 s | 2.7 MiB |
| 1 MiB | 18.4 s | 20.0 MiB | 4.5 s | 34.7 MiB |

The second row is packet-bit cost, not carrier cost. Make packet bits faster only if a real payload needs it, and do it as a separate change.

## 10. Whole-file WAV cap

The whole-file WAV helpers `WavPcmData` and `load_pcm_wav_from_path` and the `MAX_WAV_FRAME_BYTES` cap have been removed from the public API and implementation. `WavCarrier` and `read_pcm_wav_info` provide bounded carrier access and header validation without allocating memory in proportion to the declared frame count. The optional 72 MiB WAV test passes through the file-backed path with a traced peak below 16 MiB.

## 11. Known limits

| Limit | Detail |
| --- | --- |
| Web request bound | Flask accepts requests up to 256 MiB. Carrier uploads are saved to temporary files, and encoded carriers are written to persistent output files instead of being returned as base64. PNG decoding still uses Pillow's full-image decode; its working memory grows with image dimensions. See [section 12](#12-web-boundary-follow-up). |
| Verification race | If the file changes between the targeted reads and the hash pass, the verdict can mix two versions. A reopened header is checked, but frame data is not taken as a snapshot. A local attacker who can write to the file during verification is out of scope. |
| Packet-proportional cost | See [section 9](#9-memory-claim). |
| WAV sample high bytes were not hashed by the earlier format | **Closed by version 3.** Every non-LSB byte of each declared 16-, 24-, or 32-bit PCM sample enters the fixed-byte hash. Changing one gives `Tampered`. See the [v3 full media hash record](PROTOCOL-V3-FULL-MEDIA-HASH.md#2-version-3-media-hash-rule). |

## 12. Web boundary follow-up

This follow-up is complete. Carrier files move through the web boundary by path; the Flask service does not load or return the complete carrier file as bytes.

| Area | Implemented behaviour |
| --- | --- |
| Request limit | `MAX_CONTENT_LENGTH = 256 MiB`, overridable through `create_app(test_config)`. |
| Carrier uploads | Encode covers and decode stego files are saved from `FileStorage` to temporary files. Missing and empty uploads keep their existing errors. Key PEMs and payload files remain byte inputs. |
| Carrier detection and report size | `detect_carrier` reads only the first 12 file bytes. Verification reports use `stat().st_size`. WAV headers use `read_pcm_wav_info`. |
| Encode output | `encode_png` and `encode_wav` write directly to `STEGO_OUTPUT_DIR` as `<token>.png` or `<token>.wav`. Failed encodes remove partial files. |
| Response and download | Encode JSON returns `stego_url`, `filename`, and `mime_type`; it does not include stego bytes or base64. `GET /download/<id>.<ext>` checks the token and extension, then streams the file inline. |
| Stored-file lifetime | Files remain in `instance/stego-outputs` with no expiry. Users delete them manually. The verify report keeps `user_payload_base64`. |
| Browser caching | All responses retain `Cache-Control: no-store`. |

## 13. Tests

`TestChunkedCarrier` in `test_stego.py` covers:

- equality with an independent raw-byte v3 hash reference for RGB/RGBA PNG and PCM WAV
- the same digest for different chunk sizes
- bootstrap and packet masks that cross one chunk edge and many chunk edges
- `k` = 1, 3, and 8
- the padding footprint
- short and long unit streams
- range checks
- chunk order
- changes between the encode passes, including WAV fixed bytes, for arrays and files
- WAV units, ranges, and both hash streams compared with raw sample bytes for 8-bit mono, 16-bit mono/stereo, 24-bit, and 32-bit
- unchanged chunked output compared with the whole-file writer
- round trips across WAV chunk edges
- a truncated WAV and failures during a pass
- large WAV round trips through the bounded file-backed path
- memory that does not grow with the carrier size
- the optional WAV test larger than 64 MiB
- web tests for upload-to-disk, download URLs, strict identifiers, output retention, failed-encode cleanup, and the 256 MiB limit
- an optional web round trip for a WAV larger than 32 MiB

The demonstration notebook uses `PngCarrier` and `WavCarrier` for carrier reads and rewrites. Pillow image arrays are used only to display cover, stego, and difference images.

The regression suite passes with the file-backed carrier and public-API coverage listed above.

## 14. History

This plan was first deferred for three reasons:

- The brief sets no carrier-size requirement.
- The change touches every module.
- Protocol version 2 had to come first.

Its preconditions were these:

1. Version 2 is complete. This was true.
2. There is a real carrier that the cap rejects. The planned video work is the reason to do the change now.
3. The chunk size has a stated reason. See [section 8](#8-chunk-size).

The earlier plan correctly said that the task needs seekable chunked access, not forward-only streaming, and that encoding needs two passes. Both statements hold in the implementation.
