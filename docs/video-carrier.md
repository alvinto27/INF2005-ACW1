# Video carrier

Video is optional in the assignment; we added it as an extension. This guide describes how the video carrier works, what it checks, its limits, and its speed. Terms are defined in the [glossary](README.md#glossary).

We embed into the decoded pixels and audio samples, not into the compressed file. A lossy codec such as H.264 would destroy the embedded bits when re-encoding, so the output is always lossless: FFV1 video and PCM audio in a Matroska (`.mkv`) file. The output is therefore much larger than the input.

## Summary

| Item | Value |
| --- | --- |
| Media code | 3 (media ID prefix `VID-`) |
| Media context | 32 bytes |
| Video depth | 8 to 16 bits per component, with or without alpha |
| Audio | None, mono, or stereo, as 16-bit samples |
| Output | FFV1 video and PCM s16le audio in `.mkv` (8-bit RGB uses FFV1 `bgr0`) |
| Accepted input | MP4/MOV, Matroska/WebM, AVI with one video stream and at most one audio stream |
| Protocol | Version 3, unchanged |

## What the verdict covers

| Covered | Not covered |
| --- | --- |
| Decoded RGB and alpha values | Container bytes, tags, titles, chapters |
| Start time of each frame | Last frame's display duration, stream and container duration |
| Decoded 16-bit audio samples | Subtitles, attachments, extra tracks |
| Audio start time | Rotation, aspect ratio |
| The signed media context | Colour primaries, transfer, and range |
| The embedded payload | The FFV1 stream's nominal frame rate |

The carrier drops tags and colour metadata. HDR (PQ or HLG) video may therefore show wrong colours in players. A file with extra streams is refused, not silently trimmed.

## Carrier units and fixed bytes

Carrier units, in order:

1. The low byte of each R, G, and B value, pixel by pixel, row by row, frame by frame.
2. Then the low byte of each audio sample (16-bit, interleaved).

Fixed bytes, in order:

1. For each frame: its timestamp (signed 64-bit, milliseconds), then the RGB high bytes if the depth is over 8 bits, then the alpha values (1 byte at 8 bits, otherwise 2 bytes little-endian).
2. Then, if there is audio: the audio start time (signed 64-bit, milliseconds), then the high byte of each audio sample.

```text
total_units = frame_count × width × height × 3  +  audio_frames_per_channel × audio_channels
```

Alpha and bit depth add fixed bytes, not carrier units. A 16-bit RGBA video hashes about 8/3 as many bytes as it has carrier units.

## Media context

```python
struct.pack(">IIQBBIHQ", width, height, frame_count,
            video_depth, video_channels,
            audio_sample_rate, audio_channels, audio_frames_per_channel)
```

| Field | Type | Notes |
| --- | --- | --- |
| `width`, `height` | u32 | |
| `frame_count` | u64 | Counted by decoding, not from the container |
| `video_depth` | u8 | See the depth table below |
| `video_channels` | u8 | 3 without alpha, 4 with alpha |
| `audio_sample_rate` | u32 | 0 if there is no audio |
| `audio_channels` | u16 | 0, 1, or 2 |
| `audio_frames_per_channel` | u64 | 0 if there is no audio |

Files made with an early 30-byte development context do not verify.

### Video depth

The source depth is the largest bit depth of any component, including alpha. The carrier uses the smallest supported depth at least that large:

| Source depth | Without alpha | With alpha |
| ---: | ---: | ---: |
| 1–8 | 8 | 8 |
| 9 | 9 | 10 |
| 10 | 10 | 10 |
| 11–12 | 12 | 12 |
| 13–14 | 14 | 14 |
| 15–16 | 16 | 16 |

- Floating-point formats and formats over 16 bits are refused.
- Each frame is converted to RGB or RGBA at that depth, for example from YUV. The resulting values are used as they are.
- A change of depth or alpha partway through the video is refused.

### Audio channels

| Channels | Accepted layouts |
| ---: | --- |
| 1 | FC, or unspecified |
| 2 | FL then FR, or both unspecified |

Matroska PCM does not store channel positions, so our own output reads back as unspecified. Any other layout is refused with `unsupported audio channel layout`, and other channel counts with `unsupported audio channel count`. Channel positions are not in the signed context.

## Timing

Containers store the same moment with different numbers. For example, an H.264 MP4 used time base `1/15360` with timestamps `0, 512, 1024, ...`, while the FFV1 Matroska output used `1/1000` with `0, 33, 67, ...`. So we do not sign raw timestamps. Instead:

- Each timestamp is computed as `pts × time_base` with exact fractions (no floating point) and rounded to the nearest millisecond, with ties away from zero.
- The first decoded video frame is time zero. This keeps timing correct when Matroska shifts all timestamps, for example when audio starts before video.
- Missing timestamps, frame times that do not increase, and two frames that round to the same millisecond are refused.
- Audio is continuous if each audio frame starts within half a millisecond (rounded up to a whole sample) of where the previous samples end. Matroska rounds audio timestamps to milliseconds, so smaller differences are expected. Larger gaps or overlaps are refused.
- Audio is converted to 16-bit samples without resampling. A change of sample rate or channel layout partway through is refused.

## Encoding

1. **Scan.** Refuse files with more than one video or audio stream, or with any subtitle, attachment, or data stream (`unsupported additional stream`). Decode everything once to check frame sizes, timing, audio, and limits, and to count units.
2. **Hash.** Compute the media hash and build the packet, using the same core code as PNG and WAV.
3. **Embed and write.** Write the embedded audio to a temporary spool file. Decode the video again, embed the bits, and write FFV1 video and PCM audio, interleaved by time, to a staging `.mkv`. Check that the source still has the same hash.
4. **Read back.** Decode the staging file and check that the media context, the media hash, and the bootstrap and packet bits all match what was written. The encoder has no receiver key, so it cannot run a full verification.
5. **Publish.** Move the file into place with `os.replace`. If any step fails, all temporary files are deleted and nothing is published.

## Verification

Verification scans the file, reads the bootstrap, then reads forward to the packet. The same core code as PNG and WAV then checks the signature, decrypts, and makes the full media-hash pass. Read errors give `Cannot Verify`.

Video cannot be read at a random position cheaply. If a read does not continue from the last one, the reader reopens the file and decodes from the start. A packet near the end of a long video therefore takes longer to reach.

A lossless remux verifies as `Authentic` if the decoded values and timing are unchanged. A title change also stays `Authentic`. Lossy re-encoding, or any change to frames, samples, or frame times, does not.

## Output and limits

| Limit | Value | Error |
| --- | --- | --- |
| Carrier units | 512 Gi (512 × 1024³) | Capacity or limit message |
| One decoded frame | 256 MiB | `video frame exceeds configured frame-byte limit` |
| Output file | 1,280 GiB (1.25 TiB) | `video output exceeds configured byte limit` |
| Free disk before encoding | 3 GiB reserve, plus the payload size for file payloads | `insufficient free disk space for video output` |
| Free disk before each write | 3 GiB reserve, plus the packet size, plus 1 MiB | `insufficient free disk space for video output` |

- The frame limit allows 8K (7680 × 4320) in every format. 16-bit RGBA 8K uses 265,420,800 bytes (253.1 MiB).
- There is no separate duration or frame-count limit. Without audio, the unit limit allows:

| Resolution | Frames | Length at 30 fps |
| --- | ---: | ---: |
| 4K | 22,093 | 12.27 minutes |
| 1080p | 88,373 | 49.10 minutes |
| 720p | 198,841 | 110.47 minutes |

In our test, 5 seconds of 8-bit 1080p30 gave a 197 MB output, about 40 MB per second. Large videos are allowed but not advised: a 10-minute 4K 30 fps 16-bit RGBA video holds about 1.2 TB of image data, the output can be close to that size, verifying it needs the same space again, and processing can take hours. For demonstrations, use clips of 30 seconds or less at 1080p.

**VLC on Windows:** VLC 3's default Direct3D11 output can show the 8-bit `bgr0` output with a yellow-green tint. FFmpeg and PyAV decode the pixels correctly. To see the correct colours, set **Tools > Preferences > Video > Output** to **OpenGL**.

## Performance

Measured on one local machine with a 5-second 1080p30 H.264/AAC source (150 frames). These figures are not guarantees.

| Source | Encode | Verify | Output size | Peak memory |
| --- | ---: | ---: | ---: | ---: |
| 8-bit (5.0 MB) | 6.677 s | 2.838 s | 197,180,817 bytes | 868 MiB |
| 10-bit (13.3 MB) | 17.912 s | 8.429 s | 588,282,415 bytes | 1,223 MiB |

10-bit is slower and about 3 times larger, because each component is stored in 16 bits and the extra high bytes are hashed.

Time spent in each phase (8-bit, from a separate profiled run):

| Phase | Time |
| --- | ---: |
| Encode: scan | 0.17 s |
| Encode: hash and build packet | 0.67 s |
| Encode: decode, embed, and write FFV1 | 4.04 s |
| Encode: read back | 1.36 s |
| Verify: scan | 1.24 s |
| Verify: bootstrap and packet | 0.15 s |
| Verify: full hash | 1.40 s |

### Settings chosen

- **Decoder threads:** FFmpeg automatic (`thread_count=0`, `thread_type="AUTO"`). Decoding a 150-frame FFV1 file took 1.1 s, against 12.1 s with one thread. Tests confirm that both settings give identical values.
- **FFV1 encoder:** 16 slices, automatic threads, level 3, GOP 1. This was the fastest of six tested settings (2.6 s for 5 seconds of 1080p), and all six decoded back exactly.

## Tests

The video tests cover:

- round trips at every LSB count, with no audio, mono, and stereo;
- 8- to 16-bit depths, with and without alpha;
- videos that start at a non-zero time, and audio that starts before or after video;
- variable frame rates, refused timestamp collisions, and audio gaps;
- accepted and refused channel layouts;
- tampering with low bytes, high bytes, and alpha;
- lossless and lossy remuxing, and title changes;
- every resource limit, with cleanup and no published output;
- identical results with one thread and automatic threads.

Some tests are skipped because PyAV 15.1 cannot write the needed file:

| Skipped test | Reason |
| --- | --- |
| Changing only the duration | PyAV cannot write Matroska durations |
| Rotation metadata | PyAV cannot write Matroska rotation |
| Swapped stereo channels in a media file | PyAV's AVI writer resets the channel layout. A direct test of the layout check covers this instead. |

A memory test (`STEGO_LARGE_VIDEO_TEST=1`) measured peak memory of 178 MiB for a 5-second 640×360 clip and 214 MiB for 15 seconds.

## API

`VideoCarrier`, `encode_video`, `verify_video`, `encode_video_from_payload_path`, and `verify_video_to_payload_path`. They use RSA keys like the PNG and WAV functions. PyAV 15.1.0 is a required dependency, with bundled FFmpeg libraries (libavcodec 61.19.101, libavformat 61.7.100).

## References

- [PyAV remuxing example](https://pyav.org/docs/stable/cookbook/basics.html#remuxing)
- [PyAV time bases](https://pyav.org/docs/stable/api/time.html)
