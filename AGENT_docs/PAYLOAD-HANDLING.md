# Payload handling and memory

## Scope

This change reduces packet-bit memory in the library and removes Base64 payload
bytes from verify JSON. It does not change protocol version 3 bytes. Given the
same carrier and same payload, keys, nonce, timestamp, and other inputs, packing
changes the way the bits are processed, not the packet, hash, signature, stego
bytes, or verdict.

## Library data flow

### Encode

1. The caller supplies payload bytes. The encoder keeps these bytes in memory;
   the carrier capacity check bounds their allowed size.
2. The protocol serializes and encrypts the record, then signs the ciphertext
   and builds the receiver bootstrap.
3. The packet stays as packed bytes. During each carrier chunk, the encoder
   reads only the overlapping packed bit range, expands that bounded range, and
   writes it with the vectorized LSB operation. The bootstrap uses the same
   packed-byte path.
4. Alignment bits are written as zero. The packet is not expanded into one
   byte per bit, and no second full packet-bit copy is made.

### Verify

1. The decoder reads the bootstrap and recovers the packet geometry.
2. It reads the packet footprint in bounded carrier-unit ranges. Each range is
   extracted with vectorized operations and packed into the output byte buffer.
   The decoder checks that alignment padding is zero.
3. The decoder verifies the signature before decrypting. It checks the media
   hash last and returns payload bytes only for `Authentic`.

The public `read_lsb_bits`, `write_lsb_bits`, and `lsb_range_transform` APIs keep
their signatures and bit order. A partial last unit still leaves unfilled low
bits unchanged. The packed transform is internal.

## Web payload flow

The encode upload remains a bounded byte input. After an `Authentic` result, the
Flask route writes the recovered bytes to `PAYLOAD_OUTPUT_DIR`, which defaults to
`instance/recovered-payloads`. The file name is `<token_urlsafe(16)>.bin`. A
sidecar `<id>.json` stores only `download_name`, `serve_mime`, and
`preview_allowed`. The verify JSON returns `payload_url`; it does not return
Base64 payload bytes.

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

## Deferred work

These items were not implemented:

- streamed AES-GCM encryption or decryption through temporary files;
- prehashed signing;
- embedding from a ciphertext file; and
- streamed payload upload.

They can be implemented without changing protocol version 3 bytes if they
preserve the same serialized record, ciphertext, signing input, packet order,
and verdict checks. They were deferred because payload size is bounded by
carrier capacity and the current demonstration scale does not justify the extra
file-management and failure-handling paths. The Flask payload upload remains a
byte input. Verification still decrypts the payload in memory before it stores
the authenticated bytes.
