# Video Carrier Design

**Status: Implemented (library + notebook) — CP-A/CP-B/CP-C, V8, V10, and V11 CP-D2 complete; protocol v3 remains unchanged**

The approved video-plus-audio carrier uses media code 3 with `VID-`, protocol v3 with no wire-format or version change, and Matroska output. Video carriers with the experimental pre-`ff4ab39` 30-byte context are development files and are not supported by the current 32-byte format. V11 supports canonical integer video depths from 8 through 16 bits, with or without alpha; 8-bit no-alpha output remains FFV1 `bgr0`, and other video formats use matching canonical FFV1 output. Audio remains PCM s16le. Carrier processing is streamed, and the core has one additive read-back check (see PASS 3). Video is optional in the assignment. See [Current Protocol](CURRENT-PROTOCOL.md) and [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) for hash, carrier, and payload rules.

This design builds on the PyAV work by **smn-sit10 / Sitt Min Naing**, commit `c56e0ea` (“Add video frame and audio steganography support”).

## Authenticity boundary

`Authentic` covers decoded canonical RGB and alpha values, canonical video frame-start presentation timestamps, decoded canonical s16 samples, canonical audio timing, the signed context, and the encrypted payload and metadata.

It does **not** cover the last frame's display duration, stream duration, container duration, or the FFV1 stream's nominal `rate=25`. The canonical frame-start ticks are signed; a changed last-frame display duration or duration field alone is outside this boundary. It also does not cover container bytes, tags, titles, comments, chapters, subtitles, attachments, rotation/display matrix, sample aspect ratio, colour primaries, transfer characteristics, colour range, or unselected tracks. These are like PNG ancillary chunks and WAV non-sample chunks: they are outside the authenticity model. The current video carrier drops container and stream tags and colour metadata. HDR PQ/HLG video may display with incorrect colours in players. A later video carrier version may keep a small, defined tag whitelist, but tags will remain unauthenticated.

## Carrier and context

One file has one carrier, in this exact unit order:

1. The low byte of each canonical R, G, and B value, in row-major pixel order and video presentation order.
2. Then the low byte of every decoded, interleaved 16-bit little-endian sample in the only audio stream.

Alpha is never a carrier unit. Fixed bytes follow the video carrier stream: for each frame, its signed millisecond tick, all RGB high bytes in R/G/B order when the canonical depth exceeds 8 bits, then alpha values (one byte at 8 bits, otherwise two-byte little-endian values). If alpha exists, its fixed bytes are emitted in bounded chunks with no carrier units after that frame's RGB bytes. Audio fixed bytes follow all video fixed bytes: the audio-start tick, then one high byte per audio sample. No audio stream means no audio units or audio fixed bytes.

Media code **3** and prefix **`VID-`** are approved. Use the v3 wire format and version unchanged. The exact media context is 32 bytes, big-endian:

```python
struct.pack(">IIQBBIHQ", width, height, frame_count,
            canonical_video_depth, video_channel_count,
            audio_sample_rate, audio_channels, audio_frames_per_channel)
```

The fields are width u32, height u32, frame count u64, canonical video depth u8, video channel count u8 (3 without alpha, 4 with alpha), audio sample rate u32, audio channel count u16, and audio frames per channel u64. All audio fields are zero together when audio is absent; otherwise all are valid and non-zero. The source component depth is the maximum depth across all components, including alpha. Reject float and greater-than-16-bit formats. Select the smallest supported canonical depth at least as large as source depth: no-alpha supports 8, 9, 10, 12, 14, 16; alpha supports 8, 10, 12, 14, 16 (9-bit alpha promotes to 10). The decoder converts each source frame to the selected canonical RGB or RGBA format. The encoder keeps the resulting canonical integer values, except for the selected RGB low bits; it does not normalize them to the full range of the canonical depth. The canonical values can differ from the source component values, for example after a YUV-to-RGB conversion or a 9-bit-to-10-bit promotion. A source-depth or alpha-presence change during decode is refused.

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

- `total_units = frame_count * width * height * 3 + audio_frames_per_channel * audio_channels`; bit depth and alpha do not add carrier units.
- `fixed_byte_count` includes 8 tick bytes per frame, three RGB high bytes per pixel when depth exceeds 8, alpha bytes per pixel when present, and—when audio exists—8 audio-start bytes plus one high byte per audio sample.
- `media_code` is 3; `media_context` is the 32-byte value above. `read_units` returns bounded ranges, including across the track boundary.
- `iter_chunks_with_fixed_bytes` yields ordered units and matching fixed bytes from the same decode. `rewrite_to_path` calls `embed_chunk` and `fixed_bytes_callback` in order and directly encodes FFV1/PCM frames into one Matroska output.

One video frame is not one chunk. Decode one frame, then yield bounded RGB low-byte slices (target at most 1 MiB). High bytes and alpha values are separately emitted as bounded fixed-byte chunks. A canonical decoded frame is limited to 256 MiB; frame-sized working memory is bounded by this limit times a small number of working copies. The measured 640×360 video-plus-audio RSS was 182,648 KiB at 5 seconds and 219,328 KiB at 15 seconds (about 36 MiB more); these are measurements, not a guarantee. Hostile-media memory is not fully bounded: audio sample rate, samples per decoded audio frame, and compressed packet size have no explicit caps before FFmpeg/PyAV allocates decoded data. Put each frame's 8-byte timestamp with its **first** RGB slice; high RGB bytes accompany that slice. Alpha fixed bytes follow the frame RGB chunks and carry no units. The first audio chunk carries the 8-byte audio-start tick plus its sample high bytes; later audio chunks carry only high bytes.

This is valid because the v3 core hashes units and fixed bytes as two separate incremental streams. Chunk boundaries do not need to match. The order and total counts must match exactly.

Frame count and audio sample count come from decoding, not container duration or declared counts. PASS 0 below counts and validates them. It adds each decoded frame's three RGB units per pixel and each audio frame's interleaved sample units to a running total, and stops as soon as the carrier-unit limit is exceeded. This cap counts carrier units only; fixed bytes (RGB high bytes, alpha, ticks, and audio high bytes) are extra, so a 16-bit RGBA file hashes about 8/3 as many bytes as its unit count. It also checks the canonical frame-byte limit on the stream header before decoding and on every decoded frame, and checks the source depth and alpha presence on every frame; verify runs the same constructor scan.

### Bounded random reads

Do not use indexed/seek-efficient FFV1 decoding, seekable intermediates, or temporary verification copies in the current video carrier. Keep a bounded monotonic-read cache:

- If a read continues from the previous range, continue the current decoder.
- Otherwise reopen the input, decode from the start, and discard units up to `start`.
- Keep packet reads sequential after the first packet range.

Verification first counts/validates the carrier, reads bootstrap units `0..span`, reopens once, scans to the packet start, reads packet chunks sequentially, then lets the core make its full hash pass. A packet near the end can require a long scan. This cost is accepted for an optional feature; optimise only after measurement.

## Encode and verify flows

CP-C implements the path-based encode APIs. Video output uses an exclusively created `.stego-staging-*` Matroska file in the destination directory; the payload-file API uses a private `.stego-staging-*` directory there. Both paths perform read-back validation and `finish()` before `os.replace` publishes the output. Failures remove staging artifacts and leave the destination unpublished. Every decoder open uses FFmpeg automatic threading (`thread_count=0`, `AUTO`), approved after profiling; this changes speed only. Audio timestamps permit only half-millisecond container quantization. The reader converts to s16 without resampling or changing sample order; it validates canonical or wholly unspecified mono/stereo channel identities on the stream header and every decoded frame.

### Encode

1. **PASS 0 — count and validate.** Refuse first, before any decode work, when the file has more than one video stream, more than one audio stream, or any subtitle, attachment, or data stream: `unsupported additional stream`. Decode the streams. Check frame bytes, timestamps, audio continuity and channels, counts, and carrier-unit limits. Build `media_context`, `total_units`, and `fixed_byte_count`.
2. **PASS 1 — hash.** Run the existing v3 media hash over ordered units and fixed bytes.
3. **Build packet.** Use the existing v3 core unchanged.
4. **PASS 2 — embed and mux.** Re-decode the source, re-hash original units and fixed bytes, embed the bootstrap and packet, and encode FFV1 at the canonical pixel format plus PCM s16le directly into one staged `.mkv`. The 8-bit no-alpha path remains FFV1 `bgr0`; alpha-bearing 8-bit output uses `bgra`. `finish()` must confirm the source matches PASS 1. There are no temporary track files and no second remux pass; the input has no extra streams or tags to carry.
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

A lossless re-mux verifies only if decoded canonical RGB and alpha values, canonical timing, s16 samples, audio timing, context, and the embedded regions remain unchanged. Lossy re-encoding, frame/sample changes, or changed canonical timing fails. Container tags, colour metadata, and excluded tracks do not affect the verdict.

## Output and limits

Output is `.mkv` with FFV1 video at the selected canonical format and PCM s16le audio. The 8-bit no-alpha path remains `bgr0`; alpha output uses `bgra` at 8 bits and canonical `gbrap` formats at higher depths. FFV1 read-back is exact for the tested supported formats. Other streams, tags, and colour metadata are not carried by the current video carrier.

Implemented resource limits: total carrier units (three RGB low-byte units per pixel plus interleaved audio sample units; high bytes and alpha are fixed bytes) must not exceed **4 GiB = 4 × 1024³ units**; each decoded frame must be at or below **256 MiB of canonical frame bytes**, calculated as width × height × 3 or 4 channels × 1 byte at depth 8 or 2 bytes at higher depths; final Matroska output must not exceed **2 GiB**; and at least **3 GiB** of free disk space is required before staging. The payload-path API also requires free space equal to this reserve plus the payload file size. The frame-byte cap accepts 8K (7680×4320) in every supported format; 16-bit RGBA uses 265,420,800 bytes (253.1 MiB). PASS 0 checks the stream-header frame size when its format is known, or checks the first decoded frame otherwise, then checks each decoded frame. There is no duration, selected-span, or frame-count cap. Audio remains limited to zero, one, or two channels under the identity rule above. PASS 0 increments the carrier-unit count after each video and audio frame, stopping immediately on overflow. Verify uses the same constructor scan. The 4 GiB unit cap corresponds to about **690 frames of 1080p** (about **23 seconds at 30 fps** or **11.5 seconds at 60 fps**), **172 frames of 4K** (about **5.8 seconds at 30 fps**), or **1,553 frames of 720p**, before accounting for audio units. Linear scaling from the measured 197,180,817-byte, 150-frame encode gives about **900 MB** of FFV1 output at the 1080p maximum; the **2 GiB** output cap leaves room for detailed or noisy content. Output size is checked while muxing; a cap trip aborts, cleans up, and never publishes.

## Performance evidence and targets

A generated 5-second 1080p, 30-fps H.264/AAC MP4 had 150 frames and size 4,261,819 bytes.

Decode took 0.386 s and 0.371 s on repeat, with identical RGB/s16 arrays. FFV1 `bgr0` + PCM s16le encode took 4.094 s; output decode took 3.52–4.04 s across three runs. All 150 RGB frames read back exactly. Input/output sizes were 4,261,819/138,461,527 bytes (about 32.5×).

Including PASS 3: `3 × 0.386 + 4.094 + (3.52..4.04) ≈ 8.77–9.29 s` per 5-second clip, before hash work, packet work, mux overhead, and I/O. Linear extrapolation is about **105–112 seconds for 60 seconds at 30 fps**; expect more in practice. A 60-fps estimate is roughly twice this, but has not been measured. The target demo clip is **5–10 seconds**.

CP-C profiled the complete API on a deterministic 5-second 1920×1080 30-fps H.264/AAC 8-bit input (150 frames; 5,019,557 bytes). With the earlier one-thread decoder setting, a separate run took 18.907 s to encode and 25.014 s to verify; it wrote 197,180,825 bytes and peaked at 748,920 KiB RSS. With approved `thread_count=0`/`AUTO`, encode took **6.677 s** and verify **2.838 s**, returned `Authentic`, wrote **197,180,817 bytes**, and peaked at **888,560 KiB RSS**. Fixture generation ran in a separate process and is excluded. Automatic threading increased peak RSS by about 136 MiB over the one-thread CP-C run. G7's prototype reported 420.6 MiB; its measurement harness differs, and the remaining memory gap is not isolated. RSS sampling shows that the AUTO run peaks transiently during PASS 2 (about 866 MiB sampled) and falls to about 491 MiB current RSS after that pass. Treat this as a host-specific peak, not a memory guarantee.

CP-D2 measured a generated 5-second 1920×1080 30-fps H.264/AAC 10-bit source (150 frames; 13,345,593 bytes; decoded video format `yuv420p10le`). Before the performance fixes below, the complete API took **21.130 s to encode** and **8.381 s to verify**. After the fixes it took **17.912 s to encode** and **8.429 s to verify**, returned `Authentic`, wrote **588,282,415 bytes**, and peaked at **1,252,528 KiB RSS**. Fixture generation ran in a separate process. The final 8-bit run took **6.490 s to encode** and **2.765 s to verify**, near the committed CP-C results of 6.677 s and 2.838 s. On these runs, 10-bit output was about 3× larger and peak RSS about 1.4× the CP-C 8-bit run. The generated content and timings are host-specific; they are a measured comparison, not a guarantee.

### CP-C and CP-D2 phase profiles

Wall times below are from separate profiled 5-second runs with `cyber_venv/bin/python`; values vary slightly by run. PASS 0 scans both video and audio. PASS 3 validates the output context, embedded transforms, fixed-byte/unit counts, and masked hash in one pass. The CP-D2 measurements use the same generated 5-second 1080p30 H.264/AAC fixtures before and after the performance fixes. Each cell is `before → after` in seconds; wrapper overhead is included.

| Fixture | Encode PASS 0 scan | PASS 1 hash + packet prep | PASS 2 decode/embed/FFV1 | PASS 3 read-back | Encode total | Verify scan | Bootstrap | Packet | Full hash | Verify total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8-bit (5,019,557-byte source) | 0.229 → 0.174 | 0.933 → 0.666 | 3.998 → 4.037 | 1.368 → 1.360 | 6.591 → 6.298 | 1.274 → 1.241 | 0.146 → 0.147 | <0.001 → <0.001 | 1.338 → 1.396 | 2.763 → 2.787 |
| 10-bit (13,345,593-byte source) | 0.708 → 0.246 | 3.209 → 3.139 | 9.684 → 9.742 | 4.090 → 4.095 | 17.902 → 17.436 | 3.835 → 3.896 | 0.488 → 0.482 | <0.001 → <0.001 | 4.137 → 4.105 | 8.465 → 8.487 |

P1 moved the canonical conversion probe to the first decoded frame only; later frames still undergo the depth/alpha consistency check. The source-frame reads in later passes still convert to the selected canonical format, and conversion failures become `CarrierAccessError`. P2 removed the per-frame `pixels.max()` scan: the selected canonical format defines the sample range, while encode read-back checks exact decoded values and the normal masked hash checks carrier bytes. The 10-bit scan fell from 0.708 s to 0.246 s; 8-bit total encode stayed near CP-C's 6.677 s and verify near 2.838 s.

The remaining 10-bit time is mainly data work: each RGB component uses 16-bit array storage, fixed-byte hashing covers the additional RGB high bytes, source YUV-to-GBR conversion is required, and FFV1 stores 10-bit components in 16-bit planes. The measured 10-bit file is about 3× the 8-bit output size. RGB high-byte extraction now views each little-endian uint16 slice directly instead of allocating a shifted uint16 array and a cast uint8 array. This avoids those temporaries without changing the fixed-byte order. The 10-bit PASS 2 and PASS 3 remain the largest encode costs; decode, conversion, FFV1, and hashing scale with the larger frames and output. For verify, the FFV1 scan and full hash each take about 4.1 s; bootstrap reading is about 0.5 s and packet reading is under 1 ms because the packet is near the start. A packet near the end can require a longer sequential read.

The CP-C automatic-thread profile remains the reference for the original 8-bit implementation: encode **6.677 s**, verify **2.838 s**, output **197,180,817 bytes**, peak **888,560 KiB RSS**. Its detailed phases were PASS 0 0.168–0.182 s, PASS 1 0.970–0.982 s, PASS 2 4.118–4.145 s, PASS 3 1.378–1.423 s, and verify scan/bootstrap/packet/full hash 1.284/0.147/<0.001/1.370 s. Earlier one-thread and single-pass read-back comparisons are retained in the V8 history below.

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

Implemented library API: `VideoCarrier`, `encode_video`, `verify_video`, `encode_video_from_payload_path`, and `verify_video_to_payload_path`. There is no password-authentication API; the video encode API accepts RSA keys. File APIs use existing v3 payload streaming and add no protocol or crypto code. `av==15.1.0` is a normal install dependency in `requirements.txt`; the manylinux wheel includes FFmpeg libraries (local libavcodec 61.19.101, libavformat 61.7.100). PyAV is required and imported at module load; the video tests run with the required dependency.

## Refusals and tests

Final V8 validation (historical) with `cyber_venv/bin/python`: **198 tests ran; 191 passed and 7 skipped**. `test_video.py` ran **56 tests in 2.491 seconds** (52 passed, 4 skipped). New real encodes verify `Authentic` when video starts at +5 seconds with no audio, with later audio, and with audio before video; the latter also confirms Matroska rebases output timestamps. The pre-fix +5-second no-audio encode failed PASS 3 with `output masked media hash does not match the encoded carrier`. The V8 channel tests accept FC and unspecified mono, FL/FR and unspecified stereo, preserve mono s16 samples exactly, and reject FL+LFE. Matroska PCM reads back with layout `2 channels` and identities `NONE/NONE` in both the stream header and decoded frame. PyAV 15.1's AVI writer normalizes FR+FL to NONE/NONE, so the swapped-order media test is skipped; a direct identity test confirms refusal. The opt-in RSS test now uses audio matching video duration: 640×360 encode+verify peaked at **182,648 KiB** for 5 seconds and **219,328 KiB** for 15 seconds, a **36,680 KiB** increase; fixture generation is outside the measured child process. PyAV duration writing remains skipped: container/stream duration is read-only, and FFV1 does not preserve an assigned final-frame duration. Rotation writing remains skipped because its Matroska writer API is unavailable. Tests include all LSB counts, no-audio and mono round trips, non-zero video origins and audio offsets, selected-span refusal, channel identities, tampering, lossless/lossy remux cases, and publication cleanup. The RSS test is opt-in with `STEGO_LARGE_VIDEO_TEST=1`. PyAV is required; media modules import it at module load and backend tests do not skip when it is absent. There is no password API.

CP-D2 validation with `cyber_venv/bin/python`: **211 tests ran; 204 passed and 7 skipped**. `test_video.py` ran **69 tests; 65 passed and 4 skipped**. Exact payload round trips passed for BGRA 8-bit, GBRP 9/10/12/14/16-bit, GBRAP 10/16-bit, and YUVA444P 9-bit promoted to GBRAP 10-bit. Distinct channel-value probes confirmed BGRA, RGBA, and GBRAP `to_ndarray()` use RGBA order; tests verify RGB low-byte unit order and the high-byte/alpha fixed-byte order. RGB low-byte, RGB high-byte, and alpha tampering are all detected. Tests also cover independent fixed-byte counts, canonical context fields, one-time PASS 0 conversion probing, float/>16-bit refusal, mid-stream format changes, and unchanged 8-bit no-alpha `bgr0` output. The 5-second 1080p30 10-bit encode/verify measurement is recorded above. The user-provided samples directory was not accessed.

Refuse no video stream, zero/invalid or changing dimensions, float or greater-than-16-bit formats, formats that cannot convert to the selected canonical representation, source depth or alpha changes during decode, missing/invalid timestamps, unsupported audio channel count or layout, audio sample-rate/layout changes, discontinuous audio, malformed/short streams, insufficient capacity, limit trips, read-back mismatch, or an unsupported extra stream. Missing audio is allowed. Missing container duration alone is not a refusal; count decoded frames and samples under active limits.

PyAV is required at runtime for PNG, WAV, and video media I/O. A title change and lossless packet-copy remux remain `Authentic`; lossy transcoding and decoded carrier changes do not. A test for duration-only changes skips because PyAV 15.1 does not expose a supported Matroska duration writer. The video demonstration notebook is implemented. Optional web integration is not implemented; video remains a library and notebook feature, not a web feature.

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
| G9 — initial limits (superseded by V10) | PASS. The V8 dimension, selected-span, frame-count, minimum-disk, and output caps were forced in tests; failed writes removed staging and did not publish. | V10 replaces the initial limits with incremental carrier-unit and canonical frame-byte caps, while retaining an output-size cap and free-space check. |
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

The implementation checks stream count before decode and rechecks canonical frame bytes, pixel format, audio rate/layout, timing, carrier-unit counts, and continuity during the scan. It enforces the configured final Matroska size while muxing and the free-space requirement before staging. Forced cap trips verify cleanup and no publication. Direct mux creates no media intermediates.

## Implementation status

Stage 1 design experiments, CP-A/CP-B/CP-C library work, and the V7 notebook demonstration are complete. V8 fixed the PASS 3 origin and audio-layout identity checks. V10 removes dimension, duration, frame-count, and selected-span caps; it adds incremental carrier-unit and canonical frame-byte limits and raises the output cap. V11 CP-D2 adds higher-depth and alpha video, the 32-byte media context, fixed-byte accounting, canonical format output, and exact encode/verify coverage without changing the protocol version or wire layout. Optional web integration remains future work; video is optional in the assignment. The bundled FFV1 encoder accepted the requested level 3 option: the 5-second output encoded and decoded exactly with `level=3`, 16 slices, and AUTO encoder threads. Each enforced cap has cleanup coverage. PyAV 15.1 cannot write Matroska display-matrix rotation metadata through its supported API, so that test is explicitly skipped; title metadata is tested and remains outside the hash.

**Notebook:** The optional demo builds and removes a temporary 5-second H.264/AAC clip and shows carrier facts, encode/verify, tampering, metadata, lossy re-encode, stream refusal, limits, and verdicts.

## References

- Historical implementation and credit: `origin/sitt-vid-emb`, commit `c56e0ea`.
- [PyAV packet remux example](https://pyav.org/docs/stable/cookbook/basics.html#remuxing) and [PyAV time bases](https://pyav.org/docs/stable/api/time.html).
