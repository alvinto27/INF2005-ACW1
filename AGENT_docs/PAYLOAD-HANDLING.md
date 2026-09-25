# Payload handling and memory

## Scope

This change reduces packet-bit memory in the library and removes Base64 payload
bytes from verify JSON. It does not change protocol version 3 bytes. Given the
same carrier and same payload, keys, nonce, timestamp, and other inputs, packing
changes the way the bits are processed, not the packet, hash, signature, stego
bytes, or verdict.

## Library data flow

### Encode

The bytes API accepts payload bytes and keeps the caller's input in memory; the
carrier capacity check bounds its allowed size. The file API gets payload size
from the input file and reads it in bounded chunks. Both serialize and encrypt
the same record, sign the ciphertext, and build the same receiver bootstrap.
Packets stay packed. During each carrier chunk, the encoder reads only the
overlapping packed bit range, expands that bounded range, and writes it with the
vectorized LSB operation. Alignment bits are written as zero. No full
byte-per-bit packet copy is made.

### Verify

1. The decoder reads the bootstrap and recovers the packet geometry.
2. It reads the packet footprint in bounded carrier-unit ranges. Each range is
   extracted with vectorized operations and packed into memory or file staging.
   The decoder checks that alignment padding is zero.
3. The decoder verifies the signature before decrypting. It checks the media
   hash last. The bytes API releases payload bytes only for `Authentic`; the file
   API atomically publishes only the authenticated payload file.

The public `read_lsb_bits`, `write_lsb_bits`, and `lsb_range_transform` APIs keep
their signatures and bit order. A partial last unit still leaves unfilled low
bits unchanged. The packed transform is internal.

## Web payload flow

The encode route saves an uploaded payload file to the request's private
`TemporaryDirectory`; a UTF-8 message is written to a small temporary file. The
service passes the path to the library's file API. The file API reads payload
bytes in bounded chunks, so the web boundary does not make another complete
payload copy. Key PEM uploads remain byte inputs.

Verification also uses the file API. It writes unauthenticated plaintext only to
a mode-0600 staging file inside a mode-0700 `.stego-staging-*` directory. After
the signature, GCM tag, record parse, and full media hash all pass, it atomically
publishes only the recovered payload to `PAYLOAD_OUTPUT_DIR`, which defaults to
`instance/recovered-payloads`. A sidecar `<id>.json` stores only `download_name`,
`serve_mime`, and `preview_allowed`; if sidecar creation fails, the payload file
is removed. The verify JSON returns `payload_url`; it does not return Base64
payload bytes.

MIME sniffing reads only the first 12 payload bytes. For a `text/plain` claim,
the service validates UTF-8 with a 64 KiB incremental decoder. Staging
subdirectories do not match the download route's 22-character URL token, and a
route test confirms staged files cannot be served. Normal verification exits
remove staging. Power loss or `SIGKILL` can leave plaintext staging directories;
stop the server and remove `.stego-staging-*` directories manually after a crash.

`GET /payload/<id>` checks the same strict token format as the stego download
route and requires both the payload and sidecar. It serves only an allowlisted
MIME type inline when preview is allowed. Other payloads use
`application/octet-stream` and an attachment disposition. The response sets
`X-Content-Type-Options: nosniff`, a restrictive Content Security Policy, and
`Cache-Control: no-store`. Files have no expiry. The user must delete them.

**Recovered payloads are plaintext on disk.** Anyone who can read
`instance/recovered-payloads` can read those payloads. This local-storage design
needs host-level access controls for deployment beyond a trusted localhost.

## Measurements

Measurements below used the repository's `cyber_venv` on one local machine. They
are reference measurements, not performance guarantees.

### One million LSB operations

The reference column uses the original test-local Python loop. Each result is a
median of three runs on fixed-seed `uint8` input with `k = 1`.

| Operation | Per-bit reference | Vectorized | Change |
| --- | ---: | ---: | ---: |
| Write 1,000,000 bits | 1.4308 s | 0.0102 s | about 140x faster |
| Read 1,000,000 bits | 0.4403 s | 0.0026 s | about 169x faster |

### Payload sizes

The one-off encode/verify runs used an 8-bit mono WAV carrier and `k = 8`.

| Payload | Encode | Verify | Combined |
| --- | ---: | ---: | ---: |
| 1 MiB | 0.028 s | 0.052 s | 0.081 s |
| 16 MiB | 0.274 s | 0.684 s | 0.958 s |

The normal unit suite also encodes and verifies a 4 MiB payload at `k = 8`.
It took 0.247 s combined in a separate measurement. `tracemalloc` measured an
encode peak of 12.01 MiB. The test requires combined time below 10 s and encode
peak below `4 x payload size + 16 MiB`.

### Memory before and after packed packet handling

The previous measurement in the [Streaming Carrier Plan, section 9](STREAMING-CARRIER-PLAN.md#9-memory-claim)
used a 96 MiB WAV and a 1 MiB payload at `k = 3`. It recorded 20.0 MiB peak
for encode and 34.7 MiB peak for verify. The new 4 MiB, `k = 8` measurement
above recorded 12.01 MiB encode peak. These workloads differ in payload size,
LSB count, and verification measurement, so compare them as examples rather
than a controlled ratio.

| State | Packet working representation | Measured case | Encode peak | Verify peak |
| --- | --- | --- | ---: | ---: |
| Before | Packet bytes plus a byte per packet bit; the range transform copied that bit array | 1 MiB, `k = 3`, 96 MiB WAV | 20.0 MiB | 34.7 MiB |
| After | Packet bytes plus one bounded working chunk; no full packet-bit array | 4 MiB, `k = 8`, about 4 MiB WAV | 12.01 MiB | Not measured with `tracemalloc` |

For payload size `P`, the removed bit arrays each used about `8P` bytes.
Packet extraction now holds the packed output buffer and at most one chunk of
unit bits. The encoder's temporary expansion is bounded by
`chunk_units x lsb_count`; for `k = 8`, the packed writer can copy byte fields
directly without making a per-bit array.

## PNG carrier memory

`PngCarrier` keeps one read-only decoded pixel buffer (about one decoded image
size, D) after loading. Its RGBA alpha channel is a view, not a second image-sized
copy. Reads and protocol chunks are bounded. A rewrite allocates one output
image, so it uses about 2 x D image data while both source and output are live.
Loading copies public Pillow row bands into one backing buffer. Each temporary
band is limited to about 8 MiB, so no second full-image byte string is built.
Saving uses the output array directly.

The large-image measurements used the same 4341 x 26191 RGBA PNG (about 434 MiB
decoded) on the same machine. Encode and verify ran in separate processes. New
times are medians of three runs in separate processes, after the source file was
read once. The first encode run of each series was slower (about 9.5 s in two
series); the cause was not determined. Verify runs did not show this. Old times
are single runs and were not measured under the same rule. The old figures are
the `HEAD` reference; new figures are from this implementation. Peak RSS includes
Python and native Pillow allocations and is not a memory limit or guarantee.

| Operation | Old time | New time | Old peak RSS | New peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Encode | 8.1 s | 5.47 s | 1,571 MiB | 947.2 MiB |
| Verify | 1.9 s | 2.16 s | 1,350 MiB | 947.0 MiB |

A separate old/new check used fixed keys and the same payload on RGB and RGBA
covers. Both implementations encoded both covers. Since encoding uses random
nonce material, the encoded files were not compared byte-for-byte. Instead,
full carrier-unit reads and identity-rewrite PNG files matched exactly for both
modes.

## Payload streaming status

The file APIs stream AES-GCM encryption and decryption, RSA-PSS prehashing,
packet access, and payload parsing through private staging. The Flask routes now
save payload uploads to request-scoped files and call those file APIs. The bytes
APIs remain compatible and continue to return `bytes`; protocol version 3 bytes,
verdict ordering, MIME rules, and payload availability only for `Authentic` are
unchanged. See the [Payload Streaming Design](PAYLOAD-STREAMING-DESIGN.md) for
the API and staging contract.
