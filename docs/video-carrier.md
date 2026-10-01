# Video carrier

Video is optional in the assignment, but we added it as an extension. This guide explains how the video-plus-audio carrier works: which parts of a video are protected, how frames and audio samples become carrier units, how timing is handled, what limits apply, and how fast it runs. The library, the notebook, and the Flask app all support it, and it fits into protocol version 3 without changing the wire format.

The main idea is that we embed into the *decoded* pixels and samples, not into the compressed file. Compressed video (such as H.264) would destroy hidden bits the next time it is re-encoded, so the output is always written in a lossless format: FFV1 video with PCM audio in a Matroska (`.mkv`) file. This makes outputs much larger than their sources.

The carrier uses media code 3 with prefix `VID-` and writes Matroska files. Its context is 32 bytes; files made with the earlier 30-byte context are not supported. It supports canonical integer video depths from 8 through 16 bits, with or without alpha. Eight-bit output without alpha uses FFV1 `bgr0`; other formats use matching canonical FFV1 output. Audio uses PCM s16le. Processing is streamed, and the encoder checks the staged output before publishing it. See [Protocol](protocol.md) and [Carrier and Payload Flow](carrier-and-payload-flow.md) for hash, carrier, and payload rules.

## Authenticity boundary

`Authentic` covers decoded canonical RGB and alpha values, canonical video frame-start presentation timestamps, decoded canonical s16 samples, canonical audio timing, the signed context, and the encrypted payload and metadata.

It does **not** cover the last frame's display duration, stream duration, container duration, or the FFV1 stream's nominal `rate=25`. The canonical frame-start ticks are signed; a changed last-frame display duration or duration field alone is outside this boundary. It also does not cover container bytes, tags, titles, comments, chapters, subtitles, attachments, rotation/display matrix, sample aspect ratio, colour primaries, transfer characteristics, colour range, or unselected tracks. Like PNG ancillary chunks and WAV chunks outside the samples, they are outside what the verdict proves. The video carrier drops container and stream tags and colour metadata, so HDR (PQ/HLG) video may show incorrect colours in players. A future version could keep a small, fixed list of tags, but those tags would still not be authenticated.

## Carrier and context

One file has one carrier, in this exact unit order:

1. The low byte of each canonical R, G, and B value, in row-major pixel order and video presentation order.
2. Then the low byte of every decoded, interleaved 16-bit little-endian sample in the only audio stream.

Alpha is never a carrier unit. Fixed bytes follow the video carrier stream: for each frame, its signed millisecond tick, all RGB high bytes in R/G/B order when the canonical depth exceeds 8 bits, then alpha values (one byte at 8 bits, otherwise two-byte little-endian values). If alpha exists, its fixed bytes are emitted in bounded chunks with no carrier units after that frame's RGB bytes. Audio fixed bytes follow all video fixed bytes: the audio-start tick, then one high byte per audio sample. No audio stream means no audio units or audio fixed bytes.

We use media code **3** and prefix **`VID-`** while keeping the version-3 wire format unchanged. The media context is exactly 32 bytes, in big-endian order:

```python
struct.pack(">IIQBBIHQ", width, height, frame_count,
            canonical_video_depth, video_channel_count,
            audio_sample_rate, audio_channels, audio_frames_per_channel)
```

The fields are width u32, height u32, frame count u64, canonical video depth u8, video channel count u8 (3 without alpha, 4 with alpha), audio sample rate u32, audio channel count u16, and audio frames per channel u64. When there is no audio, all three audio fields are zero; otherwise all three are valid and non-zero. The source component depth is the largest depth of any component, including alpha. Floating-point formats and formats deeper than 16 bits are refused. Otherwise, the carrier picks the smallest supported canonical depth that is at least the source depth: no-alpha supports 8, 9, 10, 12, 14, 16; alpha supports 8, 10, 12, 14, 16 (9-bit alpha promotes to 10). The decoder converts each source frame to the selected canonical RGB or RGBA format. The encoder keeps the resulting canonical integer values, except for the selected RGB low bits; it does not normalize them to the full range of the canonical depth. The canonical values can differ from the source component values, for example after a YUV-to-RGB conversion or a 9-bit-to-10-bit promotion. A source-depth or alpha-presence change during decode is refused.

The video carrier accepts one channel only with FC identity or unspecified identity (`NONE`), and two channels only with FL, FR identities in that order or two unspecified identities (`NONE`, `NONE`). Matroska PCM stores channel count but not the channel mask, so the library's own FFV1/PCM output reads back with unspecified identities. Unspecified one- and two-channel layouts are therefore treated as mono and stereo. Any other specified identity, a swapped order, a mix of specified and unspecified identities, or any other layout is refused with `unsupported audio channel layout`. Channel counts other than one or two are refused with `unsupported audio channel count`. Channel identities are not part of the signed media context, so supporting more than two channels in future would mean adding them to the context.

## Timing and audio rules

Different containers store the same moment with different integers and time bases (see [Timing evidence](#timing-evidence)), so we never sign raw source PTS values or time bases. Instead, each timestamp is calculated as `pts * time_base` using exact fractions (never floating point) and rounded to the nearest millisecond, with ties away from zero. Missing timestamps, video ticks that do not increase, and different video times that round to the same tick are all refused.

### Audio before video

The Matroska muxer may shift absolute timestamps, including when audio starts before video. Each reader treats its first decoded video timestamp as time zero. The read-back pass checks output frame-start ticks and audio-start time against that origin rather than copying the source's absolute video origin. The tested FFV1/PCM path kept relative offsets exact at -40 ms, -1 ms, and +40 ms, including a negative audio-start tick when needed. If a muxer changes the relative offset, encoding fails instead of publishing incorrect timing. Matroska quantizes audio frame timestamps to milliseconds. Audio frame timestamp deviations of at most half a millisecond (rounded up to a whole sample) are treated as container timestamp quantization. A real gap or overlap within that tolerance cannot be distinguished and is accepted; larger ones are refused.

### Audio continuity

For decoded audio frame `i`:

```text
actual_start_i   = pts_i * time_base_i
expected_start_i = audio_start + samples_before_i / sample_rate
```

Both values are calculated with exact fractions and converted to the nearest sample position at the declared sample rate, with ties away from zero. The audio frame is continuous when its timestamp is within half a millisecond (rounded up to a whole sample) of the expected sample position. Audio frame timestamp deviations of at most half a millisecond (rounded up to a whole sample) are treated as container timestamp quantization. A real gap or overlap within that tolerance cannot be distinguished and is accepted; larger ones are refused. Samples are never inserted, removed, or resampled.

Decoded audio is converted to signed 16-bit PCM only, without resampling or changing the order of channel samples. The channel identities are checked in the stream header and in every decoded frame, and a change of sample rate or channel layout partway through a stream is refused. The audio start tick is stored once in the fixed bytes. The canonical audio sample clock then advances by exactly `1 / sample_rate` per sample.

### Timing evidence

A generated H.264 MP4 at 30 fps used time base `1/15360` and PTS `0, 512, 1024, 1536, ...`; FFV1 Matroska used `1/1000` and PTS `0, 33, 67, 100, ...`. Raw PTS integers differ. The 12-fps sample used `1/1000` on both sides (`0, 83, 167, 250, ...`). PyAV 15.1.0 produced these results. Tests confirmed variable-frame-rate handling and negative audio-offset read-back.

## `VideoCarrier` and chunking

`VideoCarrier` implements the same `CarrierSource` interface (`stego/carrier.py`) as `PngCarrier` and `WavCarrier` (`stego/media.py`), so the version 3 wire format and cryptography work with it unchanged.

- `total_units = frame_count * width * height * 3 + audio_frames_per_channel * audio_channels`; bit depth and alpha do not add carrier units.
- `fixed_byte_count` includes 8 tick bytes per frame, three RGB high bytes per pixel when depth exceeds 8, alpha bytes per pixel when present, and—when audio exists—8 audio-start bytes plus one high byte per audio sample.
- `media_code` is 3; `media_context` is the 32-byte value above. `read_units` returns bounded ranges, including across the track boundary.
- `iter_chunks_with_fixed_bytes` yields ordered units and matching fixed bytes from the same decode. `rewrite_to_path` calls `embed_chunk` and `fixed_bytes_callback` in carrier order. It accepts an optional `preview_transform` for stateful embedding callbacks; direct callers may omit it when their transform is pure. It first writes transformed audio PCM to a bounded disk spool beside the output, then writes FFV1 video and PCM audio packets interleaved by presentation time into one Matroska output. The spool uses the shared free-space reserve check and is removed on success or failure.

One video frame is not one chunk. The carrier decodes one frame, then yields bounded RGB low-byte slices (at most about 1 MiB each). High bytes and alpha values are separately emitted as bounded fixed-byte chunks. A canonical decoded frame is limited to 256 MiB; frame-sized working memory is bounded by this limit times a small number of working copies. The measured 640×360 video-plus-audio RSS was 182,648 KiB at 5 seconds and 219,328 KiB at 15 seconds (about 36 MiB more); these are measurements, not a guarantee. Hostile-media memory is not fully bounded: audio sample rate, samples per decoded audio frame, and compressed packet size have no explicit caps before FFmpeg/PyAV allocates decoded data. Each frame's 8-byte timestamp travels with its **first** RGB slice; high RGB bytes accompany that slice. Alpha fixed bytes follow the frame RGB chunks and carry no units. The first audio chunk carries the 8-byte audio-start tick plus its sample high bytes; later audio chunks carry only high bytes.

This is valid because the v3 core hashes units and fixed bytes as two separate incremental streams. Chunk boundaries do not need to match. The order and total counts must match exactly.

Frame and audio sample counts come from decoding, not container duration or declared counts. The initial scan validates them, adds each decoded frame's three RGB units per pixel and each audio frame's interleaved sample units to a running total, and stops when the carrier-unit limit is exceeded. This cap counts carrier units only; fixed bytes (RGB high bytes, alpha, ticks, and audio high bytes) are extra, so a 16-bit RGBA file hashes about 8/3 as many bytes as its unit count. It also checks the canonical frame-byte limit on the stream header before decoding and on every decoded frame, and checks the source depth and alpha presence on every frame; verify runs the same constructor scan.

### Bounded random reads

The reader uses a bounded monotonic-read cache. It does not use indexed FFV1 decoding, seekable intermediates, or temporary verification copies:

- If a read continues from where the previous one ended, the current decoder carries on.
- Otherwise, the reader reopens the input, decodes from the start, and discards units up to `start`.
- After the first packet range, packet reads stay sequential.

Verification first counts and validates the carrier, reads bootstrap units `0..span`, reopens once, scans to the packet start, and reads packet chunks sequentially before the core makes its full hash pass. A packet near the end requires a long scan.

## Encode and verify flows

Video output uses an exclusively created `.stego-staging-*` Matroska file in the destination directory; the payload-file API uses a private `.stego-staging-*` directory there. Both paths perform read-back validation and `finish()` before `os.replace` publishes the output. Failures remove staging artifacts and leave the destination unpublished. Every decoder uses FFmpeg automatic threading (`thread_count=0`, `AUTO`). Profiling found this setting faster, and it changes only speed, not results. Audio timestamps permit only half-millisecond container quantization. The reader converts to s16 without resampling or changing sample order; it validates canonical or wholly unspecified mono/stereo channel identities on the stream header and every decoded frame.

### Encode

1. **Count and validate.** Before decoding, refuse files with more than one video or audio stream, or with any subtitle, attachment, or data stream: `unsupported additional stream`. Then decode the streams and check frame sizes, timestamps, audio continuity and channels, counts, and carrier-unit limits. Build `media_context`, `total_units`, and `fixed_byte_count`.
2. **Hash and build the packet.** Run the version 3 media hash over the ordered units and fixed bytes, then build the packet with the same core code as PNG and WAV.
3. **Embed and mux.** Before the video pass, decode audio and preview the bootstrap and packet transforms over bounded chunks. After checking free space, write the resulting s16 PCM to a spool beside the output. Decode the source again, re-hash the original units and fixed bytes, and call `embed_chunk` and `update_fixed_bytes` in the same order as before: all video units, then all audio units. Mux spooled audio frames up to each video frame's presentation time, then mux any remaining audio at the end. Compare every audio transform with the spooled PCM; if they differ, fail and remove the output. This interleaves packet writes without changing hash or carrier order. Write FFV1 at the canonical pixel format with PCM s16le to one staged `.mkv`. The 8-bit format without alpha is FFV1 `bgr0`; alpha-bearing 8-bit output uses `bgra`. `finish()` confirms that the source still matches the original hash. The audio spool is the only track spool; there is no video spool or second remux pass.
4. **Read back.** The encoder has no receiver private key, so it cannot call `verify`. Decode the staged `.mkv` once in bounded order and check:
   - rebuilt `media_context` equals the input context;
   - the recomputed masked media hash equals the payload record's media hash;
   - bootstrap-region bits equal the generated OAEP envelope bits;
   - packet-region bits equal `ciphertext || signature || zero padding`.
5. **Publish.** Any mismatch or error removes all temporary files and leaves the output unpublished. On success, publish it atomically with `os.replace`, as the other file APIs do.

These checks cover the complete selected-media representation: the masked hash covers preserved carrier bits and fixed bytes; exact region comparisons cover the embedded bits; context comparison covers the signed interpretation.

`CarrierEncoding.check_output(source)` runs after the writer closes the staged Matroska and before `finish()`. It checks context, embedded transforms, exact unit/fixed-byte counts, and masked media hash. The video output reader avoids a separate count-only decode: it checks dimensions, timing, stream layout/rate, and counts while yielding the same single full pass consumed by `check_output`. PNG and WAV skip this check. The hook does not change the wire format or cryptography.

### Verify

Verification counts and validates the file, reads the bootstrap, reopens and scans to the packet start, and reads the packet chunks in order. The same version 3 core used for PNG and WAV then makes the full masked-hash pass. It checks the signature and decrypts the payload as it does for PNG/WAV. Read failures map to `Cannot Verify`.

A lossless re-mux verifies only if decoded canonical RGB and alpha values, canonical timing, s16 samples, audio timing, context, and the embedded regions remain unchanged. Lossy re-encoding, frame/sample changes, or changed canonical timing fails. Container tags, colour metadata, and excluded tracks do not affect the verdict.

## Output and limits

Output is `.mkv` with FFV1 video at the selected canonical format and PCM s16le audio. The 8-bit format without alpha is `bgr0`; alpha output uses `bgra` at 8 bits and canonical `gbrap` formats at higher depths. FFV1 read-back is exact for the tested supported formats. Other streams, tags, and colour metadata are not carried over. The 8-bit `bgr0` Matroska output has no colour tags. VLC 3 on Windows can show a yellow/green tint with its default Direct3D11 output, although FFmpeg and PyAV decode the pixels identically. To see the correct colours, set **Tools > Preferences > Video > Output** to **OpenGL** in VLC. This is a player setting; nothing in the file needs fixing.

The carrier enforces these resource limits: total carrier units (three RGB low-byte units per pixel plus interleaved audio sample units; high bytes and alpha are fixed bytes) must not exceed **512 Gi = 512 × 1024³ units**; each decoded frame must be at or below **256 MiB of canonical frame bytes**, calculated as width × height × 3 or 4 channels × 1 byte at depth 8 or 2 bytes at higher depths; final Matroska output must not exceed **1280 GiB (1.25 TiB)**; and at least **3 GiB** of free disk space is required before staging. The payload-path API also requires free space equal to this reserve plus the payload file size. The frame-byte cap accepts 8K (7680×4320) in every supported format; 16-bit RGBA uses 265,420,800 bytes (253.1 MiB). The initial scan checks the stream-header frame size when its format is known, or checks the first decoded frame otherwise, then checks every decoded frame. There is no separate duration or frame-count cap. Audio is limited to zero, one, or two channels under the identity rule above. The initial scan increments the carrier-unit count after each video and audio frame, stopping immediately on overflow. Verify uses the same constructor scan. With no audio, the 512 Gi unit limit allows **22,093 frames of 4K** (**12.27 minutes at 30 fps**), **88,373 frames of 1080p** (**49.10 minutes at 30 fps**), or **198,841 frames of 720p** (**110.47 minutes at 30 fps**). A 10-minute 4K30 video uses **447,897,600,000 units (417.14 Gi)** before audio units.

Before every Matroska packet write, the mux checks free space. It requires the **3 GiB** reserve, the packet size, and **1 MiB** of fixed mux slack. A failed check aborts encoding, closes the output, removes staging, and does not publish the destination. The output-size check also runs after every packet write. Linear scaling from the measured 197,180,817-byte, 150-frame encode gives about **900 MB** of FFV1 output at the 1080p maximum; the **1280 GiB** output cap allows much larger lossless output.

Large videos are allowed, but not advised. The limits accept, for example, a 10-minute 4K video at 30 fps with 16-bit RGBA. That is about 1.2 TB of uncompressed image data, and the lossless MKV output can be close to that size. Verifying it means uploading it again, which needs the same amount of space again. Processing can take many hours. A file of this size cannot be sent by email. For demonstrations, use short clips (30 seconds or less at 1080p). The application refuses the encode when free disk space falls below the 3 GiB reserve.

## Performance evidence and targets

A generated 5-second 1080p, 30-fps H.264/AAC MP4 had 150 frames and size 4,261,819 bytes.

Decode took 0.386 s and 0.371 s on repeat, with identical RGB/s16 arrays. FFV1 `bgr0` + PCM s16le encode took 4.094 s; output decode took 3.52–4.04 s across three runs. All 150 RGB frames read back exactly. Input/output sizes were 4,261,819/138,461,527 bytes (about 32.5×).

Including the read-back pass: `3 × 0.386 + 4.094 + (3.52..4.04) ≈ 8.77–9.29 s` per 5-second clip, before hash work, packet work, mux overhead, and I/O. Linear extrapolation is about **105–112 seconds for 60 seconds at 30 fps**; expect more in practice. A 60-fps estimate is roughly twice this, but has not been measured. The target demo clip is **5–10 seconds**.

The 8-bit API profile used a deterministic 5-second 1920×1080 30-fps H.264/AAC input (150 frames; 5,019,557 bytes). With the earlier one-thread decoder setting, a separate run took 18.907 s to encode and 25.014 s to verify; it wrote 197,180,825 bytes and peaked at 748,920 KiB RSS. With automatic decoder threads (`thread_count=0`/`AUTO`), encode took **6.677 s** and verify **2.838 s**, returned `Authentic`, wrote **197,180,817 bytes**, and peaked at **888,560 KiB RSS**. Fixture generation ran in a separate process and is excluded. Automatic threading increased peak RSS by about 136 MiB over the one-thread run. A separate prototype memory test reported 420.6 MiB; its measurement harness differs, and the remaining memory gap is not isolated. RSS sampling shows that the AUTO run peaks transiently during the embed-and-mux pass (about 866 MiB sampled) and falls to about 491 MiB current RSS after that pass. Treat this as a host-specific peak, not a memory guarantee.

The 10-bit profile used a generated 5-second 1920×1080 30-fps H.264/AAC source (150 frames; 13,345,593 bytes; decoded video format `yuv420p10le`). Before the performance fixes below, the complete API took **21.130 s to encode** and **8.381 s to verify**. After the fixes it took **17.912 s to encode** and **8.429 s to verify**, returned `Authentic`, wrote **588,282,415 bytes**, and peaked at **1,252,528 KiB RSS**. Fixture generation ran in a separate process. The final 8-bit run took **6.490 s to encode** and **2.765 s to verify**, near the 8-bit profile results of 6.677 s and 2.838 s. On these runs, 10-bit output was about 3× larger and peak RSS about 1.4× the 8-bit run. The generated content and timings are host-specific; they are a measured comparison, not a guarantee.

### Encode and verify phase measurements

These timings come from separate profiled 5-second runs; values vary slightly between runs. The initial scan covers video and audio, and the read-back pass checks output context, embedded transforms, fixed-byte and unit counts, and the masked hash. The 10-bit comparison uses the same generated 5-second 1080p30 H.264/AAC fixture before and after the performance changes. Each cell shows `before → after` in seconds, including wrapper overhead.

| Fixture | Encode scan | Hash and packet preparation | Decode, embed, and FFV1 | Read-back | Encode total | Verify scan | Bootstrap | Packet | Full hash | Verify total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8-bit (5,019,557-byte source) | 0.229 → 0.174 | 0.933 → 0.666 | 3.998 → 4.037 | 1.368 → 1.360 | 6.591 → 6.298 | 1.274 → 1.241 | 0.146 → 0.147 | <0.001 → <0.001 | 1.338 → 1.396 | 2.763 → 2.787 |
| 10-bit (13,345,593-byte source) | 0.708 → 0.246 | 3.209 → 3.139 | 9.684 → 9.742 | 4.090 → 4.095 | 17.902 → 17.436 | 3.835 → 3.896 | 0.488 → 0.482 | <0.001 → <0.001 | 4.137 → 4.105 | 8.465 → 8.487 |

The conversion probe runs on the first decoded frame; later frames still undergo the depth/alpha consistency check. Source-frame reads in later passes still convert to the selected canonical format, and conversion failures become `CarrierAccessError`. The per-frame `pixels.max()` scan was removed: the selected canonical format defines the sample range, while encode read-back checks exact decoded values and the normal masked hash checks carrier bytes. The 10-bit scan fell from 0.708 s to 0.246 s; 8-bit total encode stayed near 6.677 s and verify near 2.838 s.

The remaining 10-bit time is mainly data work: each RGB component uses 16-bit array storage, fixed-byte hashing covers the additional RGB high bytes, source YUV-to-GBR conversion is required, and FFV1 stores 10-bit components in 16-bit planes. The measured 10-bit file is about 3× the 8-bit output size. RGB high-byte extraction views each little-endian uint16 slice directly instead of allocating a shifted uint16 array and a cast uint8 array. This avoids those temporaries without changing the fixed-byte order. The 10-bit embed-and-mux and read-back passes remain the largest encode costs; decode, conversion, FFV1, and hashing scale with the larger frames and output. For verify, the FFV1 scan and full hash each take about 4.1 s; bootstrap reading is about 0.5 s and packet reading is under 1 ms because the packet is near the start. A packet near the end can require a longer sequential read.

The automatic-thread 8-bit profile measured: encode **6.677 s**, verify **2.838 s**, output **197,180,817 bytes**, peak **888,560 KiB RSS**. Its detailed phases were: initial scan 0.168–0.182 s, hash and packet preparation 0.970–0.982 s, decode/embed/FFV1 4.118–4.145 s, read-back 1.378–1.423 s, and verification scan/bootstrap/packet/full hash 1.284/0.147/<0.001/1.370 s. The earlier one-thread run is reported above.

A separate output-only decode/thread trial on the same 150-frame FFV1 file converted every frame to RGB:

| Decoder threads | Thread type | Run 1 (s) | Run 2 (s) |
| ---: | --- | ---: | ---: |
| 1 | SLICE | 12.138 | 12.081 |
| 0 (auto) | SLICE | 1.709 | 1.683 |
| 0 (auto) | AUTO | 1.105 | 1.136 |
| 4 | AUTO | 3.159 | 3.144 |
| 8 | AUTO | 1.653 | 1.640 |

Based on this, we use automatic decoder threads: `_configure_decoder` sets `thread_count=0` and `thread_type="AUTO"` on every decode open. The comparison shows a large speedup with a higher peak RSS. The equality test reads both a tiny H.264/AAC source and this library's FFV1/PCM output under `1`/`SLICE` and `0`/`AUTO`; media context, carrier units, and fixed bytes are identical.

Decoder threading changes speed only in the tested files: FFV1 is lossless, and H.264/AAC decodes to identical RGB, s16, fixed bytes, and context under both tested thread settings. A difference at any decode pass fails safe: rehashing during the hash or embed-and-mux passes, or validation during read-back, stops encoding before publication.

## API and dependency

The library API for video is `VideoCarrier`, `encode_video`, `verify_video`, `encode_video_from_payload_path`, and `verify_video_to_payload_path`. There is no password-authentication API; the video encode API accepts RSA keys. The file APIs reuse the version 3 payload streaming and add no protocol or cryptography code of their own. `av==15.1.0` is a normal install dependency in `requirements.txt`; the manylinux wheel includes FFmpeg libraries (local libavcodec 61.19.101, libavformat 61.7.100). PyAV is required and imported at module load; the video tests run with the required dependency.

## Refusals and tests

The figures in this section are snapshots from when each feature was added, not counts for the current code. (The current suite has 308 tests; see the [README](../README.md#running-the-tests).)

When the timing and channel rules were added, the full suite had 198 tests: 191 passed and 7 were skipped. `test_video.py` ran **56 tests in 2.491 seconds** (52 passed, 4 skipped). Real encodes verify as `Authentic` when video starts at +5 seconds with no audio, with later audio, and with audio before video; the latter also confirms Matroska rebases output timestamps. Before the time-origin fix, the +5-second no-audio encode failed read-back validation with `output masked media hash does not match the encoded carrier`. The channel tests accept FC and unspecified mono, FL/FR and unspecified stereo, preserve mono s16 samples exactly, and reject FL+LFE. Matroska PCM reads back with layout `2 channels` and identities `NONE/NONE` in both the stream header and decoded frame. PyAV 15.1's AVI writer normalizes FR+FL to NONE/NONE, so the swapped-order media test is skipped; a direct identity test confirms refusal. The opt-in RSS test uses audio that matches the video duration: 640×360 encode+verify peaked at **182,648 KiB** for 5 seconds and **219,328 KiB** for 15 seconds, a **36,680 KiB** increase; fixture generation is outside the measured child process. The duration-writing test is skipped: container/stream duration is read-only, and FFV1 does not preserve an assigned final-frame duration. The rotation-writing test is skipped because its Matroska writer API is unavailable. Tests include all LSB counts, no-audio and mono round trips, non-zero video origins and audio offsets, selected-span refusal, channel identities, tampering, lossless/lossy remux cases, and publication cleanup. The RSS test is opt-in with `STEGO_LARGE_VIDEO_TEST=1`.

When higher depths and alpha were added, the full suite had 211 tests: 204 passed and 7 were skipped. `test_video.py` ran **69 tests; 65 passed and 4 skipped**. Exact payload round trips passed for BGRA 8-bit, GBRP 9/10/12/14/16-bit, GBRAP 10/16-bit, and YUVA444P 9-bit promoted to GBRAP 10-bit. Distinct channel-value probes confirmed BGRA, RGBA, and GBRAP `to_ndarray()` use RGBA order; tests verify RGB low-byte unit order and the high-byte/alpha fixed-byte order. RGB low-byte, RGB high-byte, and alpha tampering are all detected. Tests also cover independent fixed-byte counts, canonical context fields, one-time conversion probing during the initial scan, float/>16-bit refusal, mid-stream format changes, and unchanged 8-bit no-alpha `bgr0` output. The 5-second 1080p30 10-bit encode/verify measurement is recorded above.

The carrier refuses files with no video stream, zero, invalid, or changing dimensions, float or greater-than-16-bit formats, formats that cannot convert to the selected canonical representation, source depth or alpha changes during decode, missing/invalid timestamps, unsupported audio channel count or layout, audio sample-rate/layout changes, discontinuous audio, malformed/short streams, insufficient capacity, limit trips, read-back mismatch, or an unsupported extra stream. Missing audio is allowed. A missing container duration is not a reason to refuse, because frames and samples are counted by decoding them, within the limits.

A title change and lossless packet-copy remux remain `Authentic`; lossy transcoding and decoded carrier changes do not. There is no test for duration-only changes because PyAV 15.1 does not expose a supported Matroska duration writer. The demonstration notebook includes a video example, and the Flask web app uses the public video file APIs for encode and verify; it writes Matroska outputs as downloads because browsers do not play the FFV1 output inline.

## Validation results

**Environment:** PyAV 15.1.0; bundled FFmpeg libraries libavcodec 61.19.101 and libavformat 61.7.100. Synthetic inputs were deterministic H.264/AAC MP4 and small PCM/Matroska files, all at or below 10 seconds and 1080p30.

| Area | Evidence | Current rule |
| --- | --- | --- |
| Time origin | FFV1/PCM Matroska read back relative audio offsets exactly: −40 ms (video PTS 40 ms, audio 0), −1 ms (video 1 ms, audio 0), and +40 ms (video 0, audio 40 ms). Matroska shifted absolute PTS for negative starts but kept the relative offset. | Use the first video frame as time zero; compare audio against the same origin. |
| Variable frame rate | Source H.264 MP4 time base `1/15360`; decoded input PTS were 0, 33, 70, 71, and 200 ms. FFV1 Matroska time base `1/1000`; read-back ticks matched. PTS 309 and 313 at `1/15360` both rounded to 20 ms and were refused. | Convert exact rational timestamps to milliseconds and refuse collisions. |
| Audio continuity | PCM frames at 0/10/20 ms passed. A synthetic gap at sample 1008 instead of 960 and overlap at 912 instead of 960 both failed the nearest-sample test. AAC decoded frames passed. | Check decoded sample positions and continuity, not nominal stream duration. |
| Channel layout | FC mono and FL/FR stereo passed, as did unspecified mono/stereo identities required by Matroska PCM read-back. FL+LFE and other specified non-canonical orders were refused. PyAV 15.1's AVI writer normalizes FR+FL to NONE/NONE, so the swapped-order media test could not be built; a direct identity test confirms refusal. | Accept FC or unspecified mono, and FL/FR or unspecified stereo. Channel identity is not in the context. |
| Decoder threading | H.264/AAC decode and FFV1/PCM rewrite produced identical RGB units, fixed bytes, and context under `1`/SLICE and `0`/AUTO. | Use automatic threads (`thread_count=0`, `thread_type="AUTO"`). Hash and read-back checks refuse output if decoding differs. |
| FFV1 settings | All six tested settings decoded RGB-exact over 150 frames. The bundled encoder accepted level 3. | Use 16 slices, AUTO threads, level 3, and GOP 1; this was the fastest tested encode. FFV1 is intra-frame, so GOP 1 is not expected to change prediction. |
| Memory use | The 640×360 video-plus-audio RSS test peaked at 182,648 KiB for 5 seconds and 219,328 KiB for 15 seconds, about 36 MiB more for three times the duration. | This is a local measurement, not a hostile-media memory guarantee. See resource limits. |
| Output read-back | One sequential scan of a 5-second FFV1 file rebuilt 150 frames, dimensions, and ticks in 2.41–2.44 s. A four-frame idempotence probe had no mismatches normally; one flipped embedded LSB produced one mismatch in under 1 ms. | Check the staged output before publication. |
| Resource limits | Tests forced dimension, selected-span, frame-count, minimum-disk, and output-cap failures; writes removed staging and did not publish. | Incremental carrier-unit and canonical frame-byte caps, output-size cap, and free-space checks are enforced. |
| Container metadata | Changing the Matroska title left decoded RGB, s16, and PTS unchanged. Output metadata was unset, so the source title was dropped and Matroska added its own `ENCODER` tag. | Tags and rotation are outside the authenticity model; source metadata is not copied. |

### FFV1 settings measurements

Each run used `bgr0`, level 3 requested, GOP 1, and a 5-second 1080p30 H.264 input. Encode time includes input decode and mux; matching decode time compares all source/output frames.

| Slices | Threads | Encode s | Decode/compare s | Output bytes | RGB exact |
| ---: | --- | ---: | ---: | ---: | --- |
| 4 | 1 | 10.581 | 3.805 | 137,616,375 | Yes |
| 4 | AUTO | 4.110 | 3.960 | 137,616,375 | Yes |
| 16 | 1 | 11.029 | 2.015 | 139,729,881 | Yes |
| 16 | AUTO | 2.631 | 2.032 | 139,729,881 | Yes |
| 24 | 1 | 11.182 | 3.073 | 141,324,536 | Yes |
| 24 | AUTO | 2.666 | 3.027 | 141,324,536 | Yes |

The `slices` option changed output size. FFprobe did not report an FFV1 profile for these files, but the bundled encoder accepted `level=3` and the output decoded RGB-exactly. Slice/thread results are one local run; repeat before treating small timing differences as stable.

### AAC decoded-sample measurement

The generated MP4 AAC stream declared 240,000 samples per channel (5 seconds). Its first AAC packet had PTS −1024 and `Skip Samples: 1024`; the first decoded audio frame began at PTS 0 and had 1,024 samples. PyAV decoded 235 frames × 1,024 = **240,640 samples per channel**, with no discard-padding side data. All decoded frame timestamps passed continuity. PCM s16le Matroska read back all **481,280 interleaved values** exactly; the PCM muxer added or dropped none. This file includes 640 decoded tail samples beyond the nominal stream duration, so the carrier count must use decoded samples.

### Resource-limit checks

The implementation checks stream count before decode and rechecks canonical frame bytes, pixel format, audio rate/layout, timing, carrier-unit counts, and continuity during the scan. It enforces the configured final Matroska size while muxing and the free-space requirement before staging. Forced cap trips verify cleanup and no publication. Direct mux creates no media intermediates.

## Summary

The library, notebook, and Flask web integration are all complete. The reader checks timestamps and channel identity on read-back, applies incremental carrier-unit and canonical frame-byte limits, and supports higher-depth and alpha video with a 32-byte media context. The bundled FFV1 encoder accepted `level=3`; a 5-second output encoded and decoded exactly with 16 slices and automatic encoder threads. Tests cover cleanup after every enforced cap. PyAV 15.1 cannot write Matroska display-matrix rotation metadata through its supported API, so that test is skipped; title metadata is tested and remains outside the hash.

**Notebook:** the video demo builds and removes a temporary 5-second H.264/AAC clip and shows carrier facts, encode/verify, tampering, metadata, lossy re-encode, stream refusal, limits, and verdicts.

## References

- [PyAV packet remux example](https://pyav.org/docs/stable/cookbook/basics.html#remuxing) and [PyAV time bases](https://pyav.org/docs/stable/api/time.html).
