# INF2005-ACW1

This project is a localhost Flask application for encrypting, signing, embedding,
decoding, and verifying payloads with protocol version 3 from the `stego`
package. The primary carriers are 8-bit or 16-bit RGB/RGBA PNG and uncompressed
PCM WAV. The library and Flask web app also support a video carrier. The web app
accepts common image and audio sources and rewrites video covers to lossless
FFV1/PCM Matroska (`.mkv`) before embedding.

The protocol encrypts the complete payload record with AES-256-GCM, authenticates
the ciphertext and embedding geometry with RSA-PSS, and encrypts a bootstrap to
the intended receiver with RSA-OAEP. The version 3 full media hash covers PNG RGB low-byte units and the fixed
high-byte and alpha values; the masked low byte and other bytes of each declared
PCM sample; and video frame units, fixed bytes, and audio, as [Current Protocol](AGENT_docs/CURRENT-PROTOCOL.md)
defines, including 16-bit sample and fixed-byte order. PNG ancillary chunks and WAV chunks outside the
declared samples are not covered. Strict PNG and PCM WAV rewrites keep their
supported metadata as described in [Carrier and Payload Flow](AGENT_docs/CARRIER-AND-PAYLOAD-FLOW.md#metadata-in-the-output).
Converted sources keep only metadata that applies to their canonical pixels or
samples. Metadata is not covered by the media hash, so a change to it does not
change the verdict. The strict PNG encoder sets an existing PNG `tIME` to the
encode time and drops `sBIT` and `hIST`. It refuses an RGB PNG with a `tRNS`
colour key. The source converter (`encode_image` and the web app) accepts that input and converts transparency
to RGBA. The protocol carrier accepts only single-frame 8-bit or 16-bit RGB/RGBA
PNG images. Its decoded image size cannot exceed 715,827,880 bytes; see [Current
Protocol](AGENT_docs/CURRENT-PROTOCOL.md) for sample and context rules.

Requires Python 3.12+ because NumPy 2.5.3 requires it.

## Setup and run

```sh
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`. Run all automated checks with:

```sh
python -m unittest -v
python scripts/check-docs.py
```

CI runs these same commands on Python 3.12, 3.13, and 3.14.

The optional demonstration notebook additionally needs:

```sh
python -m pip install -r requirements-notebook.txt
```

The notebook is a demonstration only. It shows the main flows: PNG, RGBA
and WAV encoding and verification, the failure verdicts, typed payloads,
basic source conversion (JPEG to PNG, MP3 to WAV), and an 8-bit video
example. It does not show every feature. The tests and the guides in
`AGENT_docs/` cover the rest, for example 16-bit PNG, metadata that the
output keeps, EXIF orientation and refused sources, high bit-depth and
alpha video, the PNG and video payload-file functions, the size limits,
and the web application. The library code, the tests, and those guides
are the reference for API behaviour, not the notebook.

## Web application flow

Encoding requires:

1. a still image (PNG, JPEG, WebP, AVIF, BMP, TIFF, or GIF), audio (WAV, MP3, AAC/M4A, FLAC, ALAC, or Ogg Vorbis/Opus), or video source with one video stream and zero or one audio stream; the output is lossless PNG, WAV, or FFV1/PCM Matroska (`.mkv`);
2. either a UTF-8 message or one arbitrary payload file, plus required team ID and sender values; its MIME and filename claims are generated automatically from the selected input and are read-only in the browser; the server ignores submitted claim overrides;
3. an encrypted sender RSA private key and its password;
4. the intended receiver's RSA public key;
5. a packet start unit at or after the 2,048-unit RSA-2048 bootstrap span; and
6. an LSB count from 1 through 8.

The server validates the inputs, converts non-strict sources once to a canonical
PNG or WAV snapshot in the request temporary directory, and saves uploaded payload
files to a private request-scoped temporary file (or writes a short message there).
It constructs typed authenticated metadata, builds the full media hash, encrypts and signs the payload
record, embeds the receiver bootstrap and packet, and returns the stego media plus
the sender public key. Payload bytes are processed in bounded chunks.

Verification accepts the received PNG, WAV, or Matroska video stego file, the
trusted sender public key, and the intended receiver private key and password.
The receiver bootstrap recovers the start unit, LSB count, record length, and
AES session material.
The original cover and the previous shared start-location secret are not inputs.

After an `Authentic` result, the protocol writes only the recovered payload to a
private temporary file, then publishes it in `instance/recovered-payloads` and
returns a download URL. It checks MIME signatures and text UTF-8 in bounded reads.
The browser previews text, PNG, JPEG, GIF, WebP, AVIF, BMP, WAV, MP3, Ogg,
FLAC, MP4, and WebM only when the signed MIME claim agrees with a bounded
signature check of the recovered bytes. Video payloads use a native controls
player. SVG, HTML, XML, PDF, Matroska, and other non-allowlisted formats remain
download-only. The verify JSON returns a URL, not payload bytes. These recovered
files stay without an expiry. Delete them manually. Anyone
who can read the server's instance folder can read the recovered payloads.

Payload verification uses temporary files under `.stego-staging-*` directories.
Normal exits remove them. A power loss or `SIGKILL` can leave unauthenticated
plaintext in these private directories. After a crash, stop the server and
manually delete `.stego-staging-*` directories under the instance folder.

The local server has no fixed request-size cap by default. It requires
`Content-Length` and keeps a shared 3 GiB free-space reserve before it reads an
encode or verify upload. It stores multipart streams and request temporary files
under `instance/work`, not `/tmp` (a RAM-backed tmpfs on this host). A configured
`MAX_CONTENT_LENGTH` still applies. Converted audio is limited to 2 GiB of
canonical PCM data. Video backend limits are 512 Gi carrier units, 256 MiB per
canonical decoded frame, a 1280 GiB (1.25 TiB) output, and a 3 GiB free-space
reserve before encode (plus payload size for file payloads). Before each
Matroska packet write, the encoder also checks room for that packet and 1 MiB of
mux slack above the reserve. It stores
encoded PNG, WAV, and MKV files in `instance/stego-outputs` and returns a download URL instead of sending
the media as base64. These files also stay without an expiry. Delete them
manually when they are no longer needed.

Allowed, but not advised. The limits accept a 10-minute 4K video at 30 fps with 16-bit RGBA. This video has about 1.2 TB of uncompressed image data. The lossless MKV output can be close to that size. To verify the output, you must upload it again, and the upload needs the same space again. Processing can take many hours. A file of this size cannot be sent by email. For demonstrations, use short clips (30 seconds or less at 1080p). The application refuses the encode when free disk space falls below the 3 GiB reserve.

## Protocol API

The public Python API includes `encode_png`, `verify_png`, `encode_wav`,
`verify_wav`, `PngCarrier`, `WavCarrier`, `VideoCarrier`, `encode_video`, and
`verify_video`. It also includes the source helpers `open_image_source`,
`open_audio_source`, `detect_source_family`, `encode_image`, and `encode_audio`,
plus their payload-file variants. The core provides PNG, WAV, and video
payload-file encode and verify functions. Source converters accept still
JPEG, PNG, WebP, GIF, TIFF, BMP, and AVIF images, and audio with exactly one
mono or stereo audio stream. They create temporary canonical PNG/WAV carriers;
strict PNG and PCM WAV inputs bypass conversion. Strict PCM WAV carriers accept
any positive channel count. Converted snapshots are removed
when the context or encode call ends. CMYK images are refused because a CMYK ICC
profile is not valid on an RGB PNG, and colour-managed conversion needs a library
outside PyAV. See [Source conversion](AGENT_docs/CARRIER-AND-PAYLOAD-FLOW.md#source-conversion).

Verification requires the sender public key and receiver private key. The
file-backed carriers provide bounded range reads, chunk iteration, and
sequential rewrites. `WavCarrier` reads whole PCM frames, so carrier working
memory does not grow with the WAV size.

The video API includes `VideoCarrier`, `encode_video`, `verify_video`,
`encode_video_from_payload_path`, and `verify_video_to_payload_path`. The Flask
web app also accepts supported video covers and verifies `.mkv` outputs. Video
encode writes lossless FFV1 video and PCM audio to Matroska; this output can be
much larger than the compressed input and browsers do not play it inline.
See the [video carrier design](AGENT_docs/VIDEO-CARRIER-DESIGN.md#output-and-limits)
for carrier-unit, canonical frame-byte, output-size, and disk-space limits. PyAV is a
required install dependency in `requirements.txt`; PNG, WAV, and video I/O use PyAV.
Pillow is used only by tests and the demonstration notebook. The public
`CarrierSource` abstraction and `prepare_carrier_encoding` /
`decode_carrier_source` entry points support backend-level operations. The public
`lsb_range_transform` helper prepares LSB changes for a carrier range. Whole-array
carrier APIs and whole-file WAV loading helpers are not public; the
`MAX_WAV_FRAME_BYTES` limit has been removed. For example:

```python
layout, payload = encode_png(
    "cover.png",
    "stego.png",
    sender_private_key,
    receiver_public_key,
    2048,
    3,
    b"message",
    b"mime=text/plain;name=message.txt",
)
result = verify_png("stego.png", sender_public_key, receiver_private_key)
```

All serialised protocol integers use unsigned 64-bit big-endian fields. Existing
version 1 and version 2 masked-media files are not accepted by the active
version-3 web routes. A readable version 2 bootstrap returns `Cannot Verify`
with `unsupported bootstrap version`. The separate legacy `STG1` implementation
has been removed and is not interoperable with this protocol. See [Protocol
Compatibility](AGENT_docs/CURRENT-PROTOCOL.md#limits-and-compatibility) and the [merge-leftover
removal record](AGENT_docs/MERGE-LEFTOVER-REMOVAL.md).

## Documentation

- [Agent instructions](AGENTS.md)
- [Documentation index](AGENT_docs/README.md)
- [Agent navigation map](AGENT_docs/AGENT_MAP.md)
- [Current protocol](AGENT_docs/CURRENT-PROTOCOL.md)
- [PyAV migration record](AGENT_docs/PYAV-MIGRATION-RECORD.md)
- [Carrier and payload flow](AGENT_docs/CARRIER-AND-PAYLOAD-FLOW.md)
- [Video carrier design](AGENT_docs/VIDEO-CARRIER-DESIGN.md)
- [Web application guide](AGENT_docs/WEB-APPLICATION-GUIDE.md)
- [Three.js steganography map](AGENT_docs/STEGANOGRAPHY-MAP.md)
- [Assignment specification](docs/INF2005-ACW1-spec_v5-f2f.md)
