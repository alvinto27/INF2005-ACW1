# Video support

The Python API offers independent `frames` and `audio` modes through
`stego.encode_video` and `stego.verify_video`. The wrappers in `stego/core.py`
choose a mode, while `stego/video.py` owns PyAV decoding, NumPy carrier
conversion, and lossless Matroska output. Both modes pass a one-dimensional
`uint8` carrier to the existing `encode_carrier` and `decode_carrier` functions.
No AES, RSA, bootstrap, packet, layout, or masked-hash implementation is copied.
The Flask routes remain PNG/WAV-only.

## Signed carrier interpretation

Media codes 1 and 2 retain the PNG and WAV meanings. Code 3 identifies decoded
video RGB frames and uses `VFR-` media IDs; code 4 identifies decoded video PCM
audio and uses `VAU-` IDs. All prefixes remain four bytes including the hyphen,
so the existing 36-byte generated media ID and packet format are unchanged.

- Frames: one carrier unit is one RGB24 channel byte, in decoded frame order.
  The signed context is `struct.pack(">IIBQ", width, height, 3, frame_count)
  + b"RGB24"`.
- Audio: one carrier unit is the low byte of one interleaved signed 16-bit
  little-endian PCM sample. The signed context is
  `struct.pack(">IHBQ", sample_rate, channels, 2, samples_per_channel)`.

The audio context deliberately uses channel count rather than a container
channel-layout label. PyAV can report the same mono PCM as `mono` before output
and `1 channels` after Matroska muxing. Channel count, interleaving, width, rate,
and sample count define the carrier bytes without relying on that label.

## Containers, codecs, and timing

PyAV decodes the first video stream for frame mode, or the first audio stream for
audio mode. Frame output is FFV1 in a Matroska `.mkv` file with `bgr0` pixel
storage, which round-trips the modified RGB24 bytes exactly. It carries frame
presentation timestamps through the encoder and copies the source audio packets
into the output without lossy recompression. Audio output is signed 16-bit PCM
in Matroska; source video packets are remuxed unchanged. Other audio tracks are
not selected in audio mode. An input with no required stream is rejected.

The selected carrier is authenticated. Frame mode does not authenticate unrelated
audio tracks; audio mode does not authenticate unrelated video tracks. A separate
payload is required if both tracks need protection. Verification with the wrong
mode cannot reinterpret the selected carrier's signed media code.

The current adapters collect decoded frames or audio samples in memory. This is
intentional for the present phase. Their media-to-carrier functions isolate the
conversion boundary so a future chunked implementation can replace whole-file
loading without changing the public mode API or cryptographic protocol.

The bundled [test cover](../samples/video-test-source.mkv) is a short MPEG-4/AAC
Matroska clip with enough frame and audio samples for a small payload. Run
`python -m scripts.try_video` from the repository root to produce and verify
both stego outputs in `samples/video-test-output/`. The demo generates disposable
RSA keys in memory each run; its output files are for viewing and comparison.
