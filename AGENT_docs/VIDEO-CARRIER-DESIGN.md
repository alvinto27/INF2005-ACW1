# Video Carrier Design

**Status: Implemented (library + notebook) — CP-A/CP-B/CP-C and V8 complete; protocol v3 remains unchanged**

The user approved one combined video-plus-audio carrier, media code 3 with `VID-`, protocol v3 with no wire-format or version change, FFV1 `bgr0` and PCM s16le output in Matroska, streamed carrier processing, and library/notebook work before optional web work. The v3 wire format, cryptography, and packet placement stay unchanged; the core gets one additive read-back check (see PASS 3). Video is optional in the assignment. See [Current Protocol](CURRENT-PROTOCOL.md) and [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) for the existing hash, carrier, and payload rules.

This design builds on the PyAV work by **smn-sit10 / Sitt Min Naing**, commit `c56e0ea` (“Add video frame and audio steganography support”).

## Authenticity boundary

`Authentic` covers decoded RGB values, canonical video frame-start presentation timestamps, decoded canonical s16 samples, canonical audio timing, the signed context, and the encrypted payload and metadata.

It does **not** cover the last frame's display duration, stream duration, container duration, or the FFV1 stream's nominal `rate=25`. The canonical frame-start ticks are signed; a changed last-frame display duration or duration field alone is outside this boundary. It also does not cover container bytes, tags, titles, comments, chapters, subtitles, attachments, rotation/display matrix, sample aspect ratio, colour metadata, or unselected tracks. These are like PNG ancillary chunks and WAV non-sample chunks: they are outside the authenticity model. The current video carrier drops container and stream tags. A later video carrier version may keep a small, defined tag whitelist, but tags will remain unauthenticated.

## Carrier and context

One file has one carrier, in this exact unit order:

1. Every 8-bit R, G, and B byte of every decoded frame in the only video stream, in presentation order.
2. Then the low byte of every decoded, interleaved 16-bit little-endian sample in the only audio stream.

No audio stream means no audio units. The corresponding audio high byte is fixed data and is hashed. Frame timing and audio timing are also fixed bytes: the encoder never writes them.

Media code **3** and prefix **`VID-`** are approved. Use the v3 wire format and version unchanged. The exact media context is 30 bytes, big-endian:

```python
struct.pack(">IIQIHQ", width, height, frame_count,
            audio_sample_rate, audio_channels, audio_frames_per_channel)
```

The fields are width u32, height u32, frame count u64, audio sample rate u32, audio channel count u16, and audio frames per channel u64. All audio fields are zero together when audio is absent; otherwise all are valid and non-zero. RGB24, millisecond timing, and the one-video/at-most-one-audio rule are fixed by media code 3, not repeated in context.

The current video carrier accepts one channel only with FC identity or unspecified identity (`NONE`), and two channels only with FL, FR identities in that order or two unspecified identities (`NONE`, `NONE`). Matroska PCM stores channel count but not the channel mask, so the library's own FFV1/PCM output reads back with unspecified identities. Treat unspecified one- and two-channel layouts as mono and stereo. Refuse a specified non-mono/non-stereo identity, swapped order, mixed specified/unspecified identities, or other channel layout with `unsupported audio channel layout`. Refuse counts other than one or two with `unsupported audio channel count`. Channel identities are not in the signed media context. Future multichannel support needs canonical channel identity in the context.

## Timing and audio rules

Do not sign source PTS integers or source time bases. For each timestamp, calculate `pts * time_base` as an exact rational, then round to the nearest millisecond, with ties away from zero. Do not use floats. Refuse missing timestamps, non-increasing video ticks, and distinct video times that round to the same tick.

### Audio before video: Stage 1 result

The Matroska muxer may shift absolute timestamps, including when audio starts before video. Every reader uses its own first decoded video timestamp as time zero. PASS 3 does not copy the source's absolute video origin: it checks output frame-start ticks from the output's own origin and audio-start time relative to that same origin. The tested FFV1/PCM path kept relative offsets exact at -40 ms, -1 ms, and +40 ms, so it retains a negative audio-start tick when needed. The current video carrier uses only this mux path. PASS 3 compares the read-back ticks, so a muxer change that alters the relative offset makes encode fail instead of publishing wrong timing. Matroska quantizes audio frame timestamps to milliseconds. Audio frame timestamp deviations of at most half a millisecond (rounded up to a whole sample) are treated as container timestamp quantization. A real gap or overlap within that tolerance cannot be distinguished and is accepted; larger ones are refused.

### Audio continuity

For decoded audio frame `i`:

```text
actual_start_i   = pts_i * time_base_i
expected_start_i = audio_start + samples_before_i / sample_rate
```

Use exact rational arithmetic. Convert each value to its nearest sample position at the declared sample rate, with ties away from zero. The audio frame is continuous when its timestamp is within half a millisecond (rounded up to a whole sample) of the expected sample position. Audio frame timestamp deviations of at most half a millisecond (rounded up to a whole sample) are treated as container timestamp quantization. A real gap or overlap within that tolerance cannot be distinguished and is accepted; larger ones are refused. Do not insert, remove, or resample samples.

Convert decoded sample format to signed 16-bit PCM only. Do not resample or change channel sample order. Check the channel identities in the stream header and every decoded frame. Refuse a sample-rate or accepted channel-layout change during a stream. Store the audio start tick once in fixed bytes. The canonical audio sample clock then advances by exactly `1 / sample_rate` per sample.

### Timing evidence

A generated H.264 MP4 at 30 fps used time base `1/15360` and PTS `0, 512, 1024, 1536, ...`; FFV1 Matroska used `1/1000` and PTS `0, 33, 67, 100, ...`. Raw PTS integers differ. The Sitt 12-fps sample used `1/1000` on both sides (`0, 83, 167, 250, ...`). PyAV 15.1.0 produced these results. Stage 1 confirmed VFR and negative-offset read-back (G1, G2).

## `VideoCarrier` and chunking

`VideoCarrier` follows the existing `CarrierSource` interface in `stego/carrier.py` and the `PngCarrier`/`WavCarrier` rules in `stego/media.py`. The v3 wire format and cryptography remain unchanged.

- `total_units = frame_count * width * height * 3 + audio_frames_per_channel * audio_channels`.
- `fixed_byte_count = 8 * frame_count`, plus 8 audio-start bytes and one high byte per audio sample when audio exists.
- `media_code` is 3; `media_context` is the 30-byte value above. `read_units` returns bounded ranges, including across the track boundary.
- `iter_chunks_with_fixed_bytes` yields ordered units and matching fixed bytes from the same decode. `rewrite_to_path` calls `embed_chunk` and `fixed_bytes_callback` in order and directly encodes FFV1/PCM frames into one Matroska output.

One video frame is not one chunk. A 1920×1080 RGB frame is 6,220,800 bytes; a 3840×2160 frame is about 23.7 MiB. Decode one frame, then yield bounded RGB slices (target about 1 MiB). For normal decoder frame sizes, memory does not grow in proportion to total duration; the 640×360 video-plus-audio RSS test measured 182,648 KiB at 5 seconds and 219,328 KiB at 15 seconds (about 36 MiB more). This is not an absolute guarantee against hostile media: dimensions are capped at 1920×1080, but there is no explicit cap on audio sample rate, samples per decoded audio frame, or compressed packet size before FFmpeg/PyAV allocates decoded data. Put the frame's 8-byte timestamp with its **first** slice; later slices have empty fixed bytes. The first audio chunk carries the 8-byte audio-start tick plus its sample high bytes; later audio chunks carry only high bytes.

This is valid because the v3 core hashes units and fixed bytes as two separate incremental streams. Chunk boundaries do not need to match. The order and total counts must match exactly.

Frame count and audio sample count come from decoding, not container duration or declared counts. PASS 0 below counts and validates them. It also builds context and checks resource limits.

### Bounded random reads

Do not use indexed/seek-efficient FFV1 decoding, seekable intermediates, or temporary verification copies in the current video carrier. Keep a bounded monotonic-read cache:

- If a read continues from the previous range, continue the current decoder.
- Otherwise reopen the input, decode from the start, and discard units up to `start`.
- Keep packet reads sequential after the first packet range.

Verification first counts/validates the carrier, reads bootstrap units `0..span`, reopens once, scans to the packet start, reads packet chunks sequentially, then lets the core make its full hash pass. A packet near the end can require a long scan. This cost is accepted for an optional feature; optimise only after measurement.

## Encode and verify flows

CP-C implements the path-based encode APIs. Video output uses an exclusively created `.stego-staging-*` Matroska file in the destination directory; the payload-file API uses a private `.stego-staging-*` directory there. Both paths perform read-back validation and `finish()` before `os.replace` publishes the output. Failures remove staging artifacts and leave the destination unpublished. Every decoder open uses FFmpeg automatic threading (`thread_count=0`, `AUTO`), approved after profiling; this changes speed only. Audio timestamps permit only half-millisecond container quantization. The reader converts to s16 without resampling or changing sample order; it validates canonical or wholly unspecified mono/stereo channel identities on the stream header and every decoded frame.

### Encode

1. **PASS 0 — count and validate.** Refuse first, before any decode work, when the file has more than one video stream, more than one audio stream, or any subtitle, attachment, or data stream: `unsupported additional stream`. Decode the streams. Check dimensions, timestamps, audio continuity and channels, counts, duration, and limits. Build `media_context`, `total_units`, and `fixed_byte_count`.
2. **PASS 1 — hash.** Run the existing v3 media hash over ordered units and fixed bytes.
3. **Build packet.** Use the existing v3 core unchanged.
4. **PASS 2 — embed and mux.** Re-decode the source, re-hash original units and fixed bytes, embed the bootstrap and packet, and encode FFV1 `bgr0` plus PCM s16le directly into one staged `.mkv`. `finish()` must confirm the source matches PASS 1. There are no temporary track files and no second remux pass; the input has no extra streams or tags to carry.
5. **PASS 3 — read back.** The encoder has no receiver private key, so it cannot call `verify`. Make one bounded sequential decode of the staged `.mkv` and check:
   - rebuilt `media_context` equals the input context;
   - recomputed masked media hash equals the payload record's media hash;
   - bootstrap-region bits equal the generated OAEP envelope bits;
   - packet-region bits equal `ciphertext || signature || zero padding`.
6. **Publish.** Any mismatch or error removes all temporary files and never publishes output. On success, atomically publish with `os.replace`, like the existing file APIs.

These checks cover the complete selected-media representation: the masked hash covers preserved carrier bits and fixed bytes; exact region comparisons cover the embedded bits; context comparison covers the signed interpretation.

`CarrierEncoding.check_output(source)` runs after the writer closes the staged Matroska and before `finish()`. It checks context, embedded transforms, exact unit/fixed-byte counts, and masked media hash. The video output reader avoids a separate count-only decode: it checks dimensions, timing, stream layout/rate, and counts while yielding the same single full pass consumed by `check_output`. PNG/WAV retain their no-check default. This additive core hook does not change the wire format or cryptography.

### Verify

Count and validate, read the bootstrap, reopen and scan to the packet start, read packet chunks in order, then let the unchanged v3 core make the full masked-hash pass. It checks the signature and decrypts the payload as it does for PNG/WAV. Read failures map to `Cannot Verify`.

A lossless re-mux verifies only if decoded RGB, canonical timing, s16 samples, audio timing, context, and the embedded regions remain unchanged. Lossy re-encoding, frame/sample changes, or changed canonical timing fails. Container tags and excluded tracks do not affect the verdict.

## Output and limits

Output is `.mkv` with FFV1 `bgr0` video and PCM s16le audio. A local experiment decoded FFV1 `bgr0` back to exactly the same RGB bytes. Other streams and tags are not carried by the current video carrier.

Implemented limits: **1920×1080**, **15 seconds nominal**, **16 seconds maximum selected span including decoder tail**, **450 frames**, audio channels **0/1/2** under the identity rule above, **1 GiB final Matroska output**, and **3 GiB minimum free space**. The video-only last frame-start tick must be at or before 15 seconds. During the audio scan, require `max(last_video_tick, audio_end_tick) - min(0, audio_start_tick) ≤ 16 seconds`; stop the scan when it exceeds this span. Dimensions, duration, frame count, and channels are enforced during the scan; the output size is checked during mux. The planned 2 GiB intermediate-byte cap was removed: direct mux has no media intermediates, so the one final-output cap is sufficient. A cap trip aborts, cleans up, and never publishes. Embedding makes FFV1 output larger, because changed LSBs are harder to compress: G6 measured 139,729,881 bytes for 5 seconds without embedding, but G7 measured 217,163,362 bytes for 5 seconds with LSB changes (about 1.55×). At 15 seconds the G7 figure gives about 651 MB (about 621 MiB), below the 1 GiB cap for this test content. Complex video may exceed the cap.

## Performance evidence and targets

A generated 5-second 1920×1080, 30-fps H.264/AAC MP4 had 150 frames and size 4,261,819 bytes.

Decode took 0.386 s and 0.371 s on repeat, with identical RGB/s16 arrays. FFV1 `bgr0` + PCM s16le encode took 4.094 s; output decode took 3.52–4.04 s across three runs. All 150 RGB frames read back exactly. Input/output sizes were 4,261,819/138,461,527 bytes (about 32.5×).

Including PASS 3: `3 × 0.386 + 4.094 + (3.52..4.04) ≈ 8.77–9.29 s` per 5-second clip, before hash work, packet work, mux overhead, and I/O. Linear extrapolation is about **105–112 seconds for 60 seconds at 30 fps**; expect more in practice. A 60-fps estimate is roughly twice this, but has not been measured. The target demo clip is **5–10 seconds**.

CP-C profiled the complete API on a deterministic 5-second 1920×1080 30-fps H.264/AAC input (150 frames; 5,019,557 bytes). With the earlier one-thread decoder setting, a separate run took 18.907 s to encode and 25.014 s to verify; it wrote 197,180,825 bytes and peaked at 748,920 KiB RSS. With approved `thread_count=0`/`AUTO`, encode took **6.677 s** and verify **2.838 s**, returned `Authentic`, wrote **197,180,817 bytes**, and peaked at **888,560 KiB RSS**. Fixture generation ran in a separate process and is excluded. Automatic threading increased peak RSS by about 136 MiB over the one-thread CP-C run. G7's prototype reported 420.6 MiB; its measurement harness differs, and the remaining memory gap is not isolated. RSS sampling shows that the AUTO run peaks transiently during PASS 2 (about 866 MiB sampled) and falls to about 491 MiB current RSS after that pass. Treat this as a host-specific peak, not a memory guarantee.

### CP-C profile and optimization

Wall times below are from separate profiled 5-second runs with `cyber_venv/bin/python`; values vary slightly by run. PASS 0 scans both video and audio. PASS 3 originally decoded output once to build `VideoCarrier` context and a second time for `check_output`. `open_rewritten_output()` now seeds the expected context and validates streams, dimensions, timing, rates, channel layout, and counts during the same full iteration that `check_output()` hashes. This removed one full FFV1 decode without weakening the comparisons.

| Encode phase | Before (s) | After (s) |
| --- | ---: | ---: |
| PASS 0 source scan | 0.241 (one-thread run) | 0.168–0.182 (AUTO) |
| PASS 1 hash and packet preparation | 0.964 (one-thread run) | 0.970–0.982 (AUTO) |
| PASS 2 source decode, transform, FFV1/PCM encode | 4.017 (one-thread run) | 4.118–4.145 (AUTO) |
| PASS 3 output check, including output count scan | 25.264 (12.166 scan + 13.098 check; one-thread) | 1.378–1.423 (AUTO) |
| Encode total | 30.487 (one-thread, before single-pass check) | 6.677–6.730 (AUTO, single-pass check) |

| Verify phase | After (s) |
| --- | ---: |
| PASS 0 constructor scan | 1.284 (AUTO) |
| Bootstrap read | 0.147 (AUTO) |
| Packet read | <0.001 (AUTO) |
| Full masked hash | 1.370 (AUTO) |
| Verify total | 2.803–2.857 (AUTO) |

The packet is near the start in this benchmark, so packet extraction is quick. A packet near the end can require a longer sequential range read. `cProfile` with AUTO threads showed largest costs in `_rewrite_checked` (5.541 s inclusive), `rewrite_to_path` (4.094 s), `verify_video` (2.857 s), FFV1 `VideoStream.encode` (2.520 s), `_hash_carrier_source` (2.385 s across two calls), and `_iter_video` (2.120 s). `VideoFrame.to_ndarray` used about 1.311 s; hashlib updates used 1.978 s; `_scan` was about 1.48 s across two constructors. Generator cumulative time includes decode work between yields; it is not exclusive Python CPU time. AUTO threading mainly reduces decode/scan and PASS 3 time; FFV1 encode remains about 4.1 s.

A separate output-only decode/thread trial on the same 150-frame FFV1 file converted every frame to RGB:

| Decoder threads | Thread type | Run 1 (s) | Run 2 (s) |
| ---: | --- | ---: | ---: |
| 1 | SLICE | 12.138 | 12.081 |
| 0 (auto) | SLICE | 1.709 | 1.683 |
| 0 (auto) | AUTO | 1.105 | 1.136 |
| 4 | AUTO | 3.159 | 3.144 |
| 8 | AUTO | 1.653 | 1.640 |

The user approved automatic decoder threads in V6. `_configure_decoder` now sets `thread_count=0` and `thread_type="AUTO"` on every decode open. The comparison shows a large speedup with a higher peak RSS. The equality test reads both a tiny H.264/AAC source and this library's FFV1/PCM output under `1`/`SLICE` and `0`/`AUTO`; media context, carrier units, and fixed bytes are identical.

Decoder threading changes speed only in the tested files: FFV1 is lossless, and H.264/AAC decodes to identical RGB, s16, fixed bytes, and context under both tested thread settings. A difference at any decode pass fails safe: PASS 1/PASS 2 rehashing or PASS 3 output validation stops encoding before publication.

## API and dependency

Implemented library API: `VideoCarrier`, `encode_video`, `verify_video`, `encode_video_from_payload_path`, and `verify_video_to_payload_path`. There is no password-authentication API; the video encode API accepts RSA keys. File APIs use existing v3 payload streaming and add no protocol or crypto code. `av==15.1.0` is a normal install dependency in `requirements.txt`; the manylinux wheel includes FFmpeg libraries (local libavcodec 61.19.101, libavformat 61.7.100). PyAV imports are lazy, so `import stego` works without it and the video tests skip when it is absent.

## Refusals and tests

Final V8 validation with `cyber_venv/bin/python`: **198 tests ran; 191 passed and 7 skipped**. `test_video.py` ran **56 tests in 2.491 seconds** (52 passed, 4 skipped). New real encodes verify `Authentic` when video starts at +5 seconds with no audio, with later audio, and with audio before video; the latter also confirms Matroska rebases output timestamps. The pre-fix +5-second no-audio encode failed PASS 3 with `output masked media hash does not match the encoded carrier`. The V8 channel tests accept FC and unspecified mono, FL/FR and unspecified stereo, preserve mono s16 samples exactly, and reject FL+LFE. Matroska PCM reads back with layout `2 channels` and identities `NONE/NONE` in both the stream header and decoded frame. PyAV 15.1's AVI writer normalizes FR+FL to NONE/NONE, so the swapped-order media test is skipped; a direct identity test confirms refusal. The opt-in RSS test now uses audio matching video duration: 640×360 encode+verify peaked at **182,648 KiB** for 5 seconds and **219,328 KiB** for 15 seconds, a **36,680 KiB** increase; fixture generation is outside the measured child process. PyAV duration writing remains skipped: container/stream duration is read-only, and FFV1 does not preserve an assigned final-frame duration. Rotation writing remains skipped because its Matroska writer API is unavailable. Tests include all LSB counts, no-audio and mono round trips, non-zero video origins and audio offsets, selected-span refusal, channel identities, tampering, lossless/lossy remux cases, and publication cleanup. The RSS test is opt-in with `STEGO_LARGE_VIDEO_TEST=1`. PyAV is a normal dependency; imports stay lazy and its backend tests skip when absent. There is no password API.

Refuse no video stream, zero/invalid or changing dimensions, non-RGB24 conversion, alpha or high-bit-depth video, missing/invalid timestamps, unsupported audio channel count or layout, audio sample-rate/layout changes, discontinuous audio, malformed/short streams, insufficient capacity, limit trips, read-back mismatch, or an unsupported extra stream. Missing audio is allowed. Missing container duration alone is not a refusal; count decoded frames and samples under active limits.

The PyAV video tests skip when PyAV is absent; API import and PNG/WAV tests do not import PyAV. A title change and lossless packet-copy remux remain `Authentic`; lossy transcoding and decoded carrier changes do not. A test for duration-only changes skips because PyAV 15.1 does not expose a supported Matroska duration writer. The video demonstration notebook is implemented. Optional web integration is not implemented; video remains a library and notebook feature, not a web feature.

## Stage 1 results

**Environment:** PyAV 15.1.0; bundled FFmpeg libraries libavcodec 61.19.101 and libavformat 61.7.100. Synthetic inputs were deterministic H.264/AAC MP4 and small PCM/Matroska files, all at or below 10 seconds and 1080p30.

| Gate | Result and key numbers | Decision |
| --- | --- | --- |
| G1 — time origin | PASS. FFV1/PCM Matroska read back relative audio offsets exactly: −40 ms (video PTS 40 ms, audio 0), −1 ms (video 1 ms, audio 0), +40 ms (video 0, audio 40 ms). | Keep first-video-frame origin. Matroska shifted absolute PTS for negative starts but preserved the relative offset. |
| G2 — VFR | PASS. Source H.264 MP4 time base `1/15360`; input PTS decoded to 0, 33, 70, 71, 200 ms. FFV1 MKV time base `1/1000`; read-back ticks matched. Collision PTS 309 and 313 at `1/15360` became 20 and 20 ms and were rejected. | Keep exact rational conversion and collision refusal. |
| G3 — audio continuity | PASS. PCM frames at 0/10/20 ms passed. A synthetic gap read at sample 1008 instead of 960; overlap at 912 instead of 960; both failed the nearest-sample test. AAC decoded frames passed. | Keep the specified continuity rule; count decoded output, not nominal stream duration. |
| G4 — channels | PASS. Accept FC mono and FL/FR stereo, plus fully unspecified mono/stereo identities required by Matroska PCM read-back. Refuse FL+LFE and other specified non-canonical orders. PyAV 15.1's AVI writer normalizes FR+FL to NONE/NONE, so the swapped-order media test is skipped; the identity helper rejects it. | Keep one FC-or-unspecified channel or FL/FR-or-unspecified stereo; channel identity is not in context. |
| G5/V6 — decoder threading | PASS. The tiny H.264/AAC source and FFV1/PCM rewrite produced identical RGB units, fixed bytes, and context under `1`/SLICE and `0`/AUTO. | Use approved automatic threads (`thread_count=0`, `thread_type="AUTO"`) for speed. A decode difference fails safe through hash/read-back checks before output publication. |
| G6 — FFV1 | PASS. All six settings decoded RGB-exact over 150 frames. See measurements below. The level 3 option is accepted by the bundled encoder. | Use 16 slices, AUTO threads, level 3, GOP 1; fastest tested encode. FFV1 is intra-frame, so GOP 1 is not expected to change its prediction. |
| G7 — memory profile | PASS. The 640×360 video-plus-audio RSS test peaked at 182,648 KiB for 5 s and 219,328 KiB for 15 s, about 36 MiB more for 3× duration. | For normal decoder frame sizes, process memory does not grow in proportion to total duration. This is not a hostile-media memory guarantee; see the limits below. |
| G8 — PASS 3 | PASS. One sequential scan of the 5-second FFV1 file rebuilt 150 frames, dimensions, and ticks in 2.41–2.44 s. The 4-frame idempotence probe had 0 mismatches normally; one flipped embedded LSB produced 1 mismatch in under 1 ms. | `CarrierEncoding.check_output(source)` is feasible; retain it before `finish()` and publication. |
| G9 — limits | PASS. Dimensions, selected-span duration, frame count, minimum disk, and output size caps were forced in tests; failed writes removed staging and did not publish. | Keep 1920×1080, 15 s nominal/16 s total selected span including decoder tail, 450 frames, 1 GiB final output, and 3 GiB free. Direct mux makes a separate intermediate-byte cap unnecessary. |
| G10 — tags | PASS. Changing the Matroska title left decoded RGB, s16, and PTS unchanged. Leaving output metadata unset dropped the source title; Matroska added its own `ENCODER` tag. | Tags/rotation remain outside the authenticity model; do not copy source metadata. |

### G6 FFV1 settings

Each run used `bgr0`, level 3 requested, GOP 1, and a 5-second 1080p30 H.264 input. Encode time includes input decode and mux; matching decode time compares all source/output frames.

| Slices | Threads | Encode s | Decode/compare s | Output bytes | RGB exact |
| ---: | --- | ---: | ---: | ---: | --- |
| 4 | 1 | 10.581 | 3.805 | 137,616,375 | Yes |
| 4 | AUTO | 4.110 | 3.960 | 137,616,375 | Yes |
| 16 | 1 | 11.029 | 2.015 | 139,729,881 | Yes |
| 16 | AUTO | 2.631 | 2.032 | 139,729,881 | Yes |
| 24 | 1 | 11.182 | 3.073 | 141,324,536 | Yes |
| 24 | AUTO | 2.666 | 3.027 | 141,324,536 | Yes |

The `slices` option changed output size. FFprobe did not report an FFV1 profile for these files, but the bundled encoder accepted `level=3` during CP-C encode and the output decoded RGB-exactly. Slice/thread results are one local run; repeat before treating small timing differences as stable.

### G3 AAC details

The generated MP4 AAC stream declared 240,000 samples per channel (5 seconds). Its first AAC packet had PTS −1024 and `Skip Samples: 1024`; the first decoded audio frame began at PTS 0 and had 1,024 samples. PyAV decoded 235 frames × 1,024 = **240,640 samples per channel**, with no discard-padding side data. All decoded frame timestamps passed continuity. PCM s16le Matroska read back all **481,280 interleaved values** exactly; the PCM muxer added or dropped none. This file includes 640 decoded tail samples beyond the nominal stream duration, so the carrier count must use decoded samples.

### G9 implementation record

The implementation checks stream count before decode and rechecks decoded dimensions, pixel format, audio rate/layout, timing, duration, frame count, units, and continuity during the scan. It checks the 1 GiB final Matroska size while muxing and requires 3 GiB free before staging. Forced cap trips verify cleanup and no publication. The planned 2 GiB working-intermediate limit was removed because direct mux creates no media intermediates.

## Implementation status

Stage 1 design experiments, CP-A/CP-B/CP-C library work, and the V7 notebook demonstration are complete. V8 fixes the PASS 3 origin, audio-layout identity checks, and total selected-span cap. Optional web integration remains future work; video is optional in the assignment. The bundled FFV1 encoder accepted the requested level 3 option: the 5-second output encoded and decoded exactly with `level=3`, 16 slices, and AUTO encoder threads. Each enforced cap has cleanup coverage. PyAV 15.1 cannot write Matroska display-matrix rotation metadata through its supported API, so that test is explicitly skipped; title metadata is tested and remains outside the hash.

**Notebook:** The optional demo builds and removes a temporary 5-second H.264/AAC clip and shows carrier facts, encode/verify, tampering, metadata, lossy re-encode, stream refusal, limits, and verdicts.

## References

- Historical implementation and credit: `origin/sitt-vid-emb`, commit `c56e0ea`.
- [PyAV packet remux example](https://pyav.org/docs/stable/cookbook/basics.html#remuxing) and [PyAV time bases](https://pyav.org/docs/stable/api/time.html).
