# INF2005-ACW1

This project is a localhost Flask application for encrypting, signing, embedding,
decoding, and verifying payloads in 8-bit RGB or RGBA PNG images and uncompressed
PCM WAV audio. The retained web layout uses protocol version 3 from the `stego`
package.

The protocol encrypts the complete payload record with AES-256-GCM, authenticates
the ciphertext and embedding geometry with RSA-PSS, and encrypts a bootstrap to
the intended receiver with RSA-OAEP. The version 3 full media hash covers the masked RGB units and RGBA alpha of
PNG; the masked low byte and other bytes of each declared PCM sample; and video
frame units, fixed bytes, and audio, as [Current Protocol](AGENT_docs/CURRENT-PROTOCOL.md)
defines. PNG ancillary chunks and WAV chunks outside the
declared samples are not covered. The encoded file keeps this metadata: PNG
text, colour, EXIF, and other copyable ancillary chunks, and all WAV chunks
outside the samples. A change to this metadata does not change the verdict.
The encoder sets an existing PNG `tIME` to the encode time and drops `sBIT`
and `hIST`. It refuses an RGB PNG with a `tRNS` colour key; convert that image
to RGBA first.

Requires Python 3.10+.

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

The optional demonstration notebook additionally needs:

```sh
python -m pip install -r requirements-notebook.txt
```

## Web application flow

Encoding requires:

1. an 8-bit RGB or RGBA PNG, or uncompressed PCM WAV cover;
2. either a UTF-8 message or one arbitrary payload file;
3. an encrypted sender RSA private key and its password;
4. the intended receiver's RSA public key;
5. a packet start unit at or after the 2,048-unit RSA-2048 bootstrap span; and
6. an LSB count from 1 through 8.

The server validates the inputs, saves uploaded payload files to a private
request-scoped temporary file (or writes a short message there), constructs typed
authenticated metadata, builds the full media hash, encrypts and signs the payload
record, embeds the receiver bootstrap and packet, and returns the stego media plus
the sender public key. Payload bytes are processed in bounded chunks.

Verification requires only the received stego file, the trusted sender public
key, and the intended receiver private key/password. The receiver bootstrap
recovers the start unit, LSB count, record length, and AES session material.
The original cover and the previous shared start-location secret are not inputs.

After an `Authentic` result, the protocol writes only the recovered payload to a
private temporary file, then publishes it in `instance/recovered-payloads` and
returns a download URL. It checks MIME signatures and text UTF-8 in bounded reads.
The browser previews text, PNG, JPEG, WAV, and MP3 only when the signed MIME claim
agrees with the recovered bytes. The verify JSON returns a URL, not payload
bytes. These recovered files stay without an expiry. Delete them manually. Anyone
who can read the server's instance folder can read the recovered payloads.

Payload verification uses temporary files under `.stego-staging-*` directories.
Normal exits remove them. A power loss or `SIGKILL` can leave unauthenticated
plaintext in these private directories. After a crash, stop the server and
manually delete `.stego-staging-*` directories under the instance folder.

The local server accepts requests up to 256 MiB. It stores encoded PNG and WAV
files in `instance/stego-outputs` and returns a download URL instead of sending
the media as base64. These files also stay without an expiry. Delete them
manually when they are no longer needed.

## Protocol API

The public Python API includes `encode_png`, `verify_png`, `encode_wav`,
`verify_wav`, `PngCarrier`, `WavCarrier`, and the optional video API below.
Verification requires the sender public key and receiver private key. The
file-backed carriers provide bounded range reads, chunk iteration, and
sequential rewrites. `WavCarrier` reads whole PCM frames, so carrier working
memory does not grow with the WAV size.

The optional video library API includes `VideoCarrier`, `encode_video`,
`verify_video`, `encode_video_from_payload_path`, and
`verify_video_to_payload_path`. Video is available in the library and
notebook, not in the Flask web application. It writes lossless FFV1 video and
PCM audio to `.mkv`; this output can be much larger than the compressed input.
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
- [Carrier and payload flow](AGENT_docs/CARRIER-AND-PAYLOAD-FLOW.md)
- [Video carrier design](AGENT_docs/VIDEO-CARRIER-DESIGN.md)
- [Web application guide](AGENT_docs/WEB-APPLICATION-GUIDE.md)
- [Assignment specification](docs/INF2005-ACW1-spec_v5-f2f.md)
