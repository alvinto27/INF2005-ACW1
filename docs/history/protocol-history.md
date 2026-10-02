# Protocol history

Record of how the protocol reached version 3: what each version tried to do, what was measured, which ideas were rejected, and what was learned.

Numbers in this file belong to the commit or stage of measurement. Later changes replaced many of those numbers. The current rules are in the [protocol guide](../protocol.md), [carrier and payload flow](../carrier-and-payload-flow.md), and [web application guide](../web-application.md). The original, longer text of this record is in Git history at commit `c412ad7`.

## Timeline

| Period | Protocol version | Main change |
| --- | ---: | --- |
| [Version 1](#version-1-integrity-protocol) | 1 | Rebuilt an oversized codebase into a small integrity-only protocol. The payload was signed but not encrypted. |
| [Version 2 stages](#version-2-hiding-the-packet-location) | 2 | Hid the packet location behind an encrypted bootstrap that only the receiver can open, and encrypted the whole record. Built in stages 1 to 6b. |
| [Simplification review](#simplification-review) | 2 | Removed extra format machinery that the assignment did not need. The version number did not change. |
| [Move to version 3](#move-to-version-3) | 3 | Commit `3e6c34a` (2026-09-24): full media hash and RGBA PNG covers. |

## Terms used in this history

These terms appear only in this file. Terms shared with the other guides are in the [glossary](../README.md#glossary).

| Term | Meaning |
| --- | --- |
| Marker | A fixed 16-byte value that version 1 placed in front of the packet so the verifier could find the packet. |
| Discovery (scan) | Version 1's method of finding the packet by searching the carrier for the marker. |
| Stage | One reviewed step of the version 2 work, numbered 1 to 6 (some split into a, b, c). Each stage has a separate commit. |
| `W` | A field width in bytes that version 2 calculated from the carrier size, so that integer fields were only as wide as needed. Later replaced by fixed 8-byte fields. |
| AAD | Additional authenticated data: data that AES-GCM checks but does not encrypt. |
| OAEP | The RSA encryption padding used for the bootstrap. |
| Flags | A bootstrap field in early version 2 that said whether the record was encrypted. Later removed. |
| Golden-byte test | A test that compares output with a literal byte string written by hand. |
| Simplification review | A review that compared version 2 against what the assignment needs, and removed the rest. The review notes use the name "KISS" ("keep it simple"). |

## Version 1: integrity protocol

### Starting point

| | Before | After |
| --- | --- | --- |
| Code size | 5,079 lines | 1,485 lines (1,164 in the package, 321 in tests) |
| Copies of the protocol | 4 | 1 |
| Design documents | 3, in conflict | 1 |
| Extra systems | A trust store, key management, first-use key pinning, and three-region hashing | None |

Every cut was checked against the assignment brief and against what the remaining code still needed.

### Design choices

| Decision | Reason | Rejected alternative, or what happened later |
| --- | --- | --- |
| Hash the carrier with the packet's low bits cleared | One rule for sender and receiver, with no special edge cases | Three-region hashing; the region boundaries had caused early bugs |
| Find the start unit by scanning, rather than store the start unit | No location field for an attacker to change; moving the packet broke the signature | A start-location header. Version 2 replaced scanning with the encrypted bootstrap. |
| Sign the packet position as well as the payload | Moving an identical packet to another position must fail | Signing the payload bytes alone |
| Keep bit-by-bit Python loops | Readable, and fast enough: a 1 MB payload encoded in 2.9 s | Vectorised packing: faster, but harder to read. Later work vectorised the loops based on measurement. |
| Keep the 64-candidate limit and the ambiguity check while scanning | Bounded work, and never silently choose between two valid packets | Removing the limit and the check while scanning still existed. Version 2 removed the limit and the check together with scanning. |
| One `VerificationError` that carries a verdict | Three exception classes only carried three strings | Three separate exception types |
| Keep payloads as bytes and let the caller choose encryption | Keeps the library focused on integrity | Built-in encryption. Version 2 added built-in encryption, because the record structure revealed the location. |
| Keep notebook display helpers in the notebook | A demo does not justify display code in the library | Moving presentation code into `stego/` |
| Fix the RSA-PSS salt at 32 bytes | Predictable, the same size as SHA-256, and verifiable by other libraries | `PSS.MAX_LENGTH` (222 bytes for RSA-2048). Signatures made with the two settings do not verify with each other. |

Notes on the PSS salt:

- The reason for the fixed salt was written down after the rewrite, not at the time.
- RFC 8017 gives the hash length as the typical salt length. The security difference between 32 and 222 bytes is not meaningful here.
- The upstream README wrongly called RSA-PSS "PKCS#1 v1.5". Lesson: documentation can drift away from the code.

### Module layout

The code was split from one file into eight modules. Imports go in one direction only, with no import cycles:

```text
constants → bits → layout → packet → core
crypto, media → constants, bits only
core is the only module that joins the protocol, cryptography, and file formats
```

The new package passed the full test suite before the old file was deleted.

Some validation guarded a trust boundary that no longer existed. A public key was no longer untrusted JSON from a stranger, so some defensive code had no purpose. These checks were removed one at a time after review:

- checks for `True` where a number was expected;
- a length limit on keys generated by the code;
- duplicate payload size limits;
- re-parsing packet bytes that had not changed.

### Findings

**Hash rule.** The old hash split the data into before, inside, and after the packet. The new rule copies the carrier, clears the low bits where the packet sits, and hashes the rest. The new rule is simpler but has a limit: with `k=8` and a packet that fills the carrier, the hash covers no carrier bits. The `preserved_bits` count was kept so users can see the loss, rather than assume full integrity.

**WAV defect.** A test that only checked that bytes came back unchanged missed a serious bug. `WavPcmData` accepted samples of 1 to 4 bytes, but both tests used 8-bit samples. For wider samples, the embedder changed the low bit of every byte instead of one bit per sample. At `k=1`, the largest change to one sample was:

| Sample width | Measured change | Correct maximum |
| --- | ---: | ---: |
| 8-bit | 1 | 1 |
| 16-bit | 257 | 1 |
| 24-bit | 65,793 | 1 |
| 32-bit | 16,843,009 | 1 |

- The error was the sum of the byte place values, not a change of one unit.
- Noise reached −42 dBFS at `k=1` for every depth. Correct embedding gives −90 dBFS at 16-bit and −138 dBFS at 24-bit.
- A damaged 16-bit output still verified as `Authentic`, so "the bytes round-trip" did not prove that the audio was preserved.
- The fix added a check for every sample width: `max(abs(original - stego)) <= (1 << k) - 1`.

**Capacity must use the decoded size.** `samples/Banana.png` has 6,021,120 decoded pixel bytes but is a 1,673,875-byte PNG file. The compressed file fits inside the decoded image at `k=3`, so using the file size would give a false capacity demonstration.

**Embedding changes the PNG file size.** On Banana:

| File | Size (bytes) | Change |
| --- | ---: | ---: |
| Cover | 1,673,875 | |
| Stego, `k=1` | 1,675,090 | +1,215 |
| Stego, `k=3` | 1,675,035 | +1,160 |
| Stego, `k=8` | 1,674,414 | +539 |

A growth of about 1 KiB is a real clue for detection, although re-saving with different settings also changes the size.

### Oversights and regressions

| Issue | Kind | How found | Outcome |
| --- | --- | --- | --- |
| Three validations stopped working during the module split. A broad `(TypeError, ValueError)` catch hid both the rejection and a wrongly called function. | Regression | Review; every test still passed | Tests tightened to expect the exact failure |
| Multi-byte WAV samples were embedded wrongly (see [Findings](#findings)). | Oversight: the tests used only 8-bit samples | Measuring the change per sample | Per-width bound added; every accepted sample width tested |
| `secrets`, `datetime`, `timezone`, and `MEDIA_PREFIXES` were left unused in `packet.py` after dead code was removed. | Oversight | A second sweep | Removed |
| A ban on notebook outputs was added alongside the fix for missing cell IDs (`nbformat 4.5` requires cell IDs). | Unrelated change | Review | Ban reverted; the cell-ID fix kept |
| The upstream README called RSA-PSS "PKCS#1 v1.5". | Documentation drift | Review | Corrected |
| The reason for the fixed 32-byte PSS salt was not recorded at the time. | Missing record | Review | Reason written down later (see [Design choices](#design-choices)) |

### Other version 1 decisions

| Decision | Reason |
| --- | --- |
| Remove old defensive checks one at a time, keeping any check in doubt | Most guarded a trust boundary that no longer existed. |
| Leave the `encode_png` return value unchanged; the notebook rebuilds the media context | A demo convenience was not reason enough to change a public API. |
| Treat the "furthest failure wins" verdict priority as a presentation choice | The rule decided only which message the reader saw and had no security effect. Removing scanning later made the rule unnecessary. |
| Keep assertions out of the notebook | Tests prove edge cases, and the notebook shows the flow. Assertions in the notebook would become a second test suite, drifting away from the real tests. |

## Version 2: hiding the packet location

### The problem

In version 1, an attacker could find the packet without any key:

- Scanning for the public 16-byte marker at every LSB depth found the location in 0.01 to 0.43 seconds.
- Deleting the marker was not enough. The plaintext record started with a one-byte length (36) and a predictable media ID (`IMG-` plus 32 hex characters). With the packet at unit 3,412,907 of a 6,021,120-unit carrier, searching the eight 1-LSB bit offsets for that pattern found the exact location in **0.002 s**.

The decision was to encrypt the whole record, not only remove the marker.

### The design

- A fixed bootstrap at unit 0, encrypted with RSA-OAEP to the receiver, holds the location, the packet length, the AES session key, and the nonce.
- The packet, at the start unit the user chooses, holds the encrypted record and the RSA-PSS signature.
- The bootstrap's size in carrier units comes from the length of the encrypted envelope: 2,048 units for RSA-2048. The number happens to equal the key length in bits for RSA-OAEP, but the rule is the envelope length.

### The trade-off: no third-party verification

In version 1, any holder of the sender's public key could find and verify the packet. In version 2, only the receiver's private key can find the packet. A file cannot tell an honest third party from an attacker: the location is either public to both or secret to the keyholder.

Making the hash independent of the location by masking the low bits of every unit was considered. Full masking would not help the verifier find the signature, and would remove a large share of the checked bits. On a 1280 × 1568 sample carrier:

| LSB count | Bits checked (location-based mask) | Bits checked (mask all units) | Loss |
| ---: | ---: | ---: | ---: |
| 1 | 48,166,460 | 42,147,840 | 12.5% |
| 3 | 48,161,460 | 30,105,600 | 37.5% |
| 8 | 48,148,960 | 0 | 100% |

The assignment makes Party B both the receiver and the verifier, so verification that needs the receiver's key was accepted. A public-key-only mode was rejected, because two verification modes would mean two protocols.

### Accepted risks

- **The bootstrap can be wiped.** The bootstrap sits at a fixed, public position outside the hash (the bootstrap bits must be masked). An attacker can overwrite the bootstrap and stop extraction without causing a `Tampered` verdict. This denial of service was accepted as unavoidable while the bootstrap is public.
- **Embedding is still detectable.** A random-looking block at a fixed position is not hidden, and statistical analysis can show roughly where data was embedded. The claim is only that the protocol's structure does not reveal the exact packet location without the receiver's key.

### What is signed

An attacker can write any bootstrap field. Binding of each field in the version 2 plan:

| Field an attacker changes | Bound by | Why |
| --- | --- | --- |
| Version | The sender's own version constant in the signed data | Prevents a downgrade. The received version is never used for the signature. |
| Flags (while present) | Signature and GCM AAD | Otherwise an attacker could clear the encryption flag and make ciphertext be returned as plaintext under `Authentic`. |
| LSB count, start unit, ciphertext length | Signature and GCM AAD | A wrong position or length cannot become an accepted packet. |
| AES key or nonce | The GCM tag | Swapping either only makes the tag fail, giving `Cannot Decrypt`. |

- The AES key and nonce are not signed. Producing a different valid plaintext under the same signed ciphertext would require defeating the 128-bit GCM tag.
- A proposal to add a signed commitment to the key and nonce (plan decision 12) was reviewed, rejected, and later confirmed as rejected. Stage 6c, planned for the commitment, was cancelled.
- The signature covers the ciphertext, not the plaintext. GCM authenticates the ciphertext and AAD under the given key and nonce. No key-commitment property is claimed.
- Flags were removed later because zero was the only legal value and no optional mode existed.

### Verdict decisions

- **`Cannot Decrypt` stays a separate verdict.** The verdict means the signature verified but the GCM tag rejected the body. The carrier was not proven changed, so `Tampered` would be false, and `Cannot Verify` would throw away the fact that the signature was valid.
- **`InvalidTag` needed a dedicated handler.** `InvalidTag` inherits from `Exception`, not `ValueError`, so without an explicit catch this verdict would have escaped as a crash.
- **`Payload Missing` covers two cases on purpose:** a carrier with no payload, and a wrong receiver key. The detail message must not claim the payload is absent.
- **A receiver key of the wrong size** fails to open the bootstrap and gives `Payload Missing` before the hash is checked, not `Tampered`.

### Code layering

Encryption moved into `core.py`, the record builder, because caller-side encryption cannot hide the record's revealing prefix. Each module kept one role:

| Module | Role |
| --- | --- |
| `crypto.py` | Cryptographic primitives |
| `bootstrap.py` | Bootstrap fields, size, and AAD (one owner, so the sender and verifier cannot encode the fields differently) |
| `core.py` | Order of operations and verdicts |

Before the cryptographic additions, `keys.py` was renamed to `crypto.py` as a pure rename: no content lines changed, and the module had 52 exported names before and after.

### Capacity and layout findings

**The fixed 16 MiB limit refused payloads that fit.**

| Carrier at `k=8` | Real capacity | Refused despite fitting |
| --- | ---: | ---: |
| 4000 × 3000 RGB | 35,997,579 bytes | 19 MB |
| 6000 × 4000 RGB | 71,997,579 bytes | 55 MB |

Capacity was therefore calculated from the carrier.

**Record capacity and user capacity are different numbers.** The user's budget is the record capacity minus the record overhead, the 16-byte GCM tag, and the 256-byte signature. Error messages must state the user's capacity. `max_record_length` and `max_user_payload_length` stay separate, because confusing the two overstates capacity. A carrier can have exactly zero user capacity and still be usable. A carrier that cannot hold the protocol object must be refused, not reported as zero.

**The bootstrap must be counted before answering "does the payload fit?".** The bootstrap size decides which start units are legal and the smallest usable carrier. The bootstrap does not reduce the capacity measured from a start unit already chosen. Ignoring the bootstrap gave false answers:

| Carrier | `k` | Apparent capacity without the bootstrap | Real result |
| --- | ---: | ---: | --- |
| 4,000 units | 1 | 228 bytes | Does not fit |
| 4,000 units | 8 | 3,728 bytes | 1,680 bytes |
| 32,000-sample WAV | 1 | 3,728 bytes | 3,472 bytes |

A false "fits" followed by an encode failure is worse than an early refusal.

**The bootstrap size must reach three places:** both mask ranges, the hash context, and `preserved_bit_count`. At 2,048 units, leaving the bootstrap out overstated the untouched bits by 2,048 (0.004% on the sample), and rounded ratios hid the error:

- For a 10,000-unit carrier with a 500-unit packet at `k=3`, the exact preserved bits were 78,500 without the bootstrap and 76,452 with the bootstrap.
- On the 1280 × 1568 sample, the ratios were 0.999784 and 0.999741 at both `k=1` and `k=8`.
- Tests therefore check exact integers, and that the difference equals the bootstrap size.
- The bootstrap always uses 1 low bit per unit, whatever the packet's LSB count. The start unit must be at or after the bootstrap, and the two masked regions must not overlap. No capacity helper may leave out the start position or assume zero.

**Carrier-derived field widths (`W`).** Version 2 first used `W = max(1, ceil(bit_length(total_units) / 8))` for the bootstrap, signed data, hash context, and payload lengths.

- `W` had to be calculated in one place, because `bit_length(N)` and `bit_length(N-1)` disagree at powers of two.
- Golden-byte tests were needed. One test typo expected `00 ff` for 256 (the bytes for 255). A literal value caught the typo; recalculating the expected bytes with the same code would not have.
- `W` kept every format unambiguous without a carrier size ceiling. The simplification review later replaced `W` with fixed 8-byte fields.

**The 64 MiB WAV limit.** Version 1's `MAX_WAV_FRAME_BYTES` was an arbitrary limit of about six minutes of CD-quality stereo. Three options were considered:

1. keep 64 MiB and document the six-minute limit;
2. raise the limit, keeping an arbitrary ceiling;
3. remove the limit while still loading the whole file, trusting a hostile declared size and allocating heavily.

The final fix removed both the whole-file WAV helpers and the limit. `WavCarrier` now reads in chunks with random access and checks headers without loading the whole file.

**One owner for the record length.** `core.py` used the real media ID, while the layout code and tests separately assumed 36 bytes based on `token_hex(16)`.

If the generator changed to `token_hex(8)`, the ID would be 20 bytes: `core.py` would measure 85 bytes of overhead while the layout code reported 101. Capacity would be overstated and encoding would fail late. `packet.py` became the only source of record-length arithmetic, and a test pins the real generator's 36-byte ID.

### Capacity across the intermediate formats

The goal was to answer "does this payload fit this carrier?" instead of enforcing an unrelated fixed limit. These figures show how capacity changed between stages, at N = 5,000 units, start unit 137, and 17 bytes of metadata:

| Stage | Record / user maximum at `k=1` | at `k=3` | at `k=8` | Note |
| --- | ---: | ---: | ---: | --- |
| 4a | 328 / 210 bytes | 1,544 / 1,426 bytes | 4,584 / 4,466 bytes | The 118-byte gap is 101 bytes of record overhead plus 17 bytes of metadata. Tests check both the literal values and the relationship. |
| 4b | 351 / 233 bytes | 1,567 / 1,449 bytes | 4,607 / 4,489 bytes | Removing the 23-byte version 1 header added 23 bytes; the 16-byte GCM tag added later left a net gain of 7 bytes over version 1. The signature stayed 256 bytes. |

Record overhead at that time was `93 + 2W`:

| `W` | Record overhead | Packet overhead |
| ---: | ---: | ---: |
| 2 | 97 bytes | 369 bytes |
| 3 | 99 bytes | 371 bytes |
| 4 | 101 bytes | 373 bytes |

These figures are historical. The simplification review switched to fixed 8-byte fields, and version 3 kept those fields.

**Smallest usable carrier.**

- The bootstrap is not part of the capacity formula measured from a chosen start. The bootstrap decides whether that start is legal and where the largest possible capacity begins.
- `minimum_carrier_units` therefore needs the carrier's width and the smallest protocol object.
- Stage 6b fixed an inconsistency: a carrier just above the bootstrap size let empty payloads through but refused non-empty payloads. Empty and non-empty payloads now stop at the same check if the signature, tag, and record cannot fit.
- Exactly zero user capacity means the empty protocol object fits exactly.
- Tests also check that a refusal leaves the source unchanged.

### Bootstrap size and alternatives

The RSA-2048 bootstrap plaintext was 62 bytes: version, LSB count, start unit, ciphertext length, a 32-byte AES key, and a 12-byte nonce. The bootstrap GCM AAD was 18 bytes. With `W` field widths, the serialised bootstrap was 49 bytes at `W=1` and 51 bytes at `W=2`, with 5- and 7-byte AAD. RSA-2048 OAEP with SHA-256 allows 190 bytes of plaintext, so the 49-byte version had 141 bytes to spare.

The envelope size, not the key length in general, decides how many units to read:

| Envelope | Size | Carrier units | Share of sample PNG | Share of 32,000-sample WAV |
| --- | ---: | ---: | ---: | ---: |
| RSA-2048 OAEP | 256 bytes | 2,048 | 0.034% | 6.4% |
| RSA-3072 OAEP | 384 bytes | 3,072 | 0.051% | 9.6% |
| RSA-4096 OAEP | 512 bytes | 4,096 | not measured | not measured |
| X25519 + AES-GCM (not built) | 113 bytes | 904 | 0.015% | 2.8% |

At that time, the smallest carrier for an empty payload at 1 LSB was 5,000 units with RSA-2048 (2,048 bootstrap + 2,952 packet), or 3,856 with X25519 (904 + 2,952). These savings on small carriers are why X25519 stayed a fallback option, even though RSA-OAEP is simpler to explain for the assignment.

### Recognising the bootstrap

- A successful OAEP decryption shows that the bootstrap was made for this receiver. Successful decryption does not identify the sender: any holder of the receiver's public key can make a bootstrap. The sender's signature authenticates the packet.
- Random LSBs from ordinary media are expected to fail OAEP's structure checks (leading zero, label hash, separator), so no plaintext marker is needed. No claim of statistical undetectability follows.
- A bootstrap of the wrong size fails as `Payload Missing` before any hashing.

The required order of checks was:

1. Parse and bounds-check every length an attacker could write, before allocating memory.
2. Do not act on flags until the signature is verified.
3. Then decrypt, parse, and hash.

### Other version 2 rules

- Structural checks refuse, before allocating memory: LSB counts outside 1 to 8, start units inside the bootstrap, ranges outside the carrier, and ciphertext lengths larger than the carrier can hold.
- The bootstrap size comes from the receiver's key and must be known before answering questions about the smallest carrier or the largest capacity.
- The `Cannot Decrypt` detail states only what was proven: the signature verified, AES-GCM rejected the body, no payload was returned, and media integrity was not established. The result has `valid=False` and no payload, and does not claim the carrier was tampered with.
- Other verdict meanings stayed as in version 1.
- The later version 3 reader does not retry a readable version 2 bootstrap as another format. No migration was planned, because the repository stored no old files.
- The protocol accepted any byte payload but always encrypted the record. MIME type and file name were not put in a new wrapper. The simplification review later placed the MIME type and file name in the existing signed metadata. The metadata `;` and `=` separators have no escaping, so those characters are refused in values. Result: file bytes stay arbitrary, with no second format inside the payload.

### Plan decisions

| Decision | Plan | Outcome |
| --- | --- | --- |
| Require the receiver's private key to verify | Accept: matches the assignment's workflow | Kept in version 3 |
| Remove the public packet header and marker; put the session key in the bootstrap | Accept: the header was redundant, and one receiver envelope is enough | Built in version 2 |
| RSA-OAEP instead of X25519 | Accept: fewer new concepts for the assignment | Built. X25519 + AES-GCM (113-byte envelope, 904 units, against 256 bytes and 2,048 units for RSA-2048) stayed an unbuilt fallback for small carriers. |
| Carrier-derived field widths in every format | Accept: no arbitrary size ceiling | Built, then replaced by fixed 8-byte fields in the simplification review |
| Public third-party verification mode | Reject: a second protocol, undoing the secrecy | Still not available |
| Sign the flags; always encrypt; encrypt the whole record | Accept: prevents reinterpretation and plaintext scanning | Built. Flags were later removed as unused. |
| Separate verdict for the body status | Reject: one `Cannot Decrypt` verdict says enough | Kept as one verdict |
| Signed commitment to the AES key and nonce (decision 12) | Reject, reconsidered, and confirmed: swapping the key or nonce fails at the GCM tag | No commitment; stage 6c cancelled |
| Use the bootstrap fields as GCM AAD | Accept: no extra bytes, and a second binding | Built |
| Fixed-width signed fields | First rejected, to avoid bringing back a size ceiling | The simplification review later chose fixed 8-byte fields |
| `MAX_WAV_FRAME_BYTES` | Left open, then the whole-file path and limit were deleted | Closed by chunked `WavCarrier` |
| Caller-side payload encryption in the notebook | Remove: the library now always encrypts the record | Removed. File type information later went inside the encrypted record. |
| Small WAV capacity test file | Lengthen the test file, not change the protocol | The 2,000-sample test file grew to 6,000 samples to exceed the bootstrap. The notebook cover stayed at 32,000 samples, with a separate tone as the payload. |

Two judgements were first made against version 1's goals and were wrong:

- **The byte-only payload API** suited version 1's integrity-only goal, but not version 2's goal of hiding the location. `core.py` built the revealing record, so the location could not be hidden from outside `core.py`.
- **Whole-record encryption (decision 10)** was briefly withdrawn using version 1's criteria (a readable hash and clean layering). Restored once judged against the goal of hiding the location.

For the same reason, carrier-derived widths were applied to every signed format rather than keeping fixed fields for tidiness.

### Stage record

Each stage is preserved at a dedicated commit. Test counts are for that stage, not the current suite.

| Stage | Commit | Tests | Outcome and evidence |
| --- | --- | ---: | --- |
| 1: capacity from the carrier | `a313203` | 25 | Removed the 16 MiB limit. At 1, 3, and 8 LSBs, the maximum payload fits and one byte more is refused. The decoded length is checked before allocating memory. |
| 2a: derived widths and signed flags | `23fce87` | 27 | Changed both signed formats. Tested the boundaries at 255/256 units and at powers of two: 1-byte width at 255 units, 2 bytes at 65,535. A golden-byte test caught a 256-written-as-255 typo. |
| 2b: bootstrap in the mask, hash, and preserved bits | `2d7220c` | 32 | Exact preserved bits: 78,500 without the bootstrap and 76,452 with the bootstrap (N = 10,000, packet 500 units, `k=3`). The difference equals the bootstrap size at `k` = 1, 3, and 8. The notebook was fixed from an outdated three-argument call and now prints exact integers. |
| 2c: rename `keys.py` to `crypto.py` | `4df44c4` | 32 | Pure rename: no content lines changed, 52 exported names before and after. |
| 3: bootstrap and crypto primitives | `16ff1d3` | 38 | Bootstrap plaintext 49 bytes at `W=1` and 51 bytes at `W=2`; AAD 5 and 7 bytes; RSA-2048 OAEP-SHA256 limit 190 bytes; bootstrap 2,048 units. Found the `InvalidTag` handling issue and set the one-owner module roles. |
| 4a: separate capacity quantities | `cc72dd3` | 42 | No behaviour or API change. Record and user maxima as in the [capacity table](#capacity-across-the-intermediate-formats). `packet.py` became the owner of `serialized_record_length`; one record-length assumption had been copied into core, layout, and tests. |
| 4b: remove the marker, scan, and header | `e9ad8e7` | 46 | Packet with no header, still plaintext. APIs required the start unit, `k`, and the record length. 336 position tests passed. At `k=1`, 3,359 bytes fit a 32,000-unit WAV and 3,360 were refused. Notebook: 21 code cells, no errors. This stage still exposed the record prefix, so the location was not yet hidden. |
| 4c: encrypted record and bootstrap | `b4a7b61` | 50 | RSA-OAEP bootstrap; AES-GCM over the whole record; tag inside the packet; signature checked before decryption; `InvalidTag` gives `Cannot Decrypt`. Smallest carrier for an empty payload at `k` = 1, 3, 8: 5,032, 3,043, 2,421 units (with `W=4` fixed at that point). |
| 5: notebook security and verdict evidence | `d73918f` | 50 | No `stego/` changes. Removed caller-side encryption from the notebook. Showed all seven verdicts and the limits: fixed bootstrap, statistical detection, and denial of service. Notebook capacity (with `W=4`): Banana 752,011 / 6,018,699 bytes at `k` = 1 / 8; WAV 3,371 / 29,579 bytes. |
| 6a: carrier-derived record lengths | `56fbae7` | 54 | `W` replaced fixed 32-bit payload and metadata lengths. Record overhead 97 / 99 / 101 bytes at `W` = 2 / 3 / 4; empty packet 369 bytes at `W=2`; smallest carriers 5,000 / 3,032 / 2,417 units at `k` = 1 / 3 / 8. Banana capacity 752,013 / 6,018,701 bytes at `k` = 1 / 8; WAV 3,375 / 29,583 bytes. A declared length of 2³² was tested without allocating 4 GiB. |
| 6b: refuse unusable carriers | `02e90d7` | 55 | Carriers of exactly 5,000 / 3,032 / 2,417 units at `k` = 1 / 3 / 8 accept an empty payload and report zero user bytes. One unit fewer (4,999 / 3,031 / 2,416) refuses both empty and one-byte payloads before changing the carrier. Stage 6c was cancelled, so no key or nonce commitment was added. |

More detail from the stages:

| Stage | Detail |
| --- | --- |
| 3 | The AES-256 key size has two owners for different reasons: `crypto.py` enforces a 32-byte key for the primitive, and `constants.py` sets the bootstrap field width. A test pins the two values together. The bootstrap-size calculation accepts any RSA key size, but one check pins RSA-2048 when sealing, so wider support would need only one change. |
| 4a | A task brief wrongly stated which modules imported `bits` and `constants`. The implementer checked instead of trusting the brief. The brief also left out the user-facing capacity error, and first asked for a test computing the expected value with the code under test. The brief was corrected before approval. |
| 4a | A function-level import to get around the `layout`/`packet` import cycle was rejected, because the import hid the dependency instead of removing the dependency. `packet.py` measures the record, and the caller passes the overhead into `layout`. The result keeps the order of steps in `core.py` and the import graph one-way. |
| 4b | Further tests: 24 round trips (8 LSB depths × 3 starts), capacity limits, relocation and tamper verdicts, padding, malformed and empty carriers, and the file wrappers. |
| 4b | This stage was knowingly not secure. The position had left the public API, but the plaintext record prefix could still be searched for. Passing the position explicitly made a separate, reviewable step that still round-tripped, before 4c moved the position into the bootstrap. A temporary prefix reader and a format with both public and private locators were rejected, because 4c would remove the reader and the format straight away. |
| 4b | The candidate limit and the ambiguity check were removed only once there was no scan. From then on, the decoder checked only the given location and made no promise that a carrier holds only one packet. |
| 4c | The empty-packet tests also covered 24 positive cases (8 LSB depths × 3 legal positions), non-overlapping masks, flag binding, key and nonce tampering, ciphertext confidentiality, and reading the bootstrap only once. |
| 5 | The notebook's claims were limited to what the protocol's structure proves. The notebook's separate 4,000-sample tone was the payload, not the 32,000-sample WAV cover. The notebook did not choose the team's messages, the FR13 innovation, or simulate the live A-to-B transfer; those choices were left to the team. The notebook printed 48,163,592 preserved bits at `k=1` and `k=8`, with 2,048 bootstrap bits written and 14,336 bootstrap bits preserved. |
| 6a | A `W=2` demo with payload `hello` and no metadata: 104-byte record, 120-byte ciphertext, 376-byte packet, 1,003-unit footprint at `k=3`, and one padding bit. |

## Simplification review

The review compared version 2 with what the assignment needs, not with general-purpose design. The review kept receiver-only encryption, the bootstrap, AES-GCM, RSA-PSS, the masked media hash, and the PNG and WAV security behaviour, and removed extra format machinery.

### Decisions

| Decision | Reason and outcome |
| --- | --- |
| Replace `W` with fixed 8-byte (u64) fields | `W` was correct but costly to explain and test. Fixed 8-byte big-endian fields are large enough for any foreseeable carrier and simpler to parse. The timestamp became slightly wider than needed, at negligible cost. |
| Remove the caller-side content header inside the payload | MIME type and file name fit in the existing FR3 metadata. Payload bytes stay arbitrary, with no second format inside the payload. Metadata refuses `;` and `=` because there is no escaping. |
| Remove flags while changing the format anyway | Zero was the only legal value, and no mode used the flags. The protocol version can mark future incompatible formats. |
| Keep one-byte fields for small bounded values | Version, media code, LSB count, and media ID length are bounded, so widening those fields would only serve uniformity. |
| Keep the core security design | Whole-record AES-GCM, a key per object, the RSA-OAEP bootstrap, separate signing and decryption keys, RSA-PSS, the masked hash, 1 to 8 LSBs, any chosen start, the verdicts, the preserved-bit count, strict media checks, correct sample widths, and useful regression tests. Each serves a concrete security or assignment need. Fewer tests was not a goal. |
| Postpone streaming and video infrastructure | Optional video was not a reason to build speculative infrastructure. Later, separately approved work added video and chunked carriers. |
| Leave narrowing the public API optional | No assignment benefit justified reorganising exports. |

The review's scope note said not to build streaming WAV or video without separate approval. Later commits did build streaming WAV and video, outside this review.

Other decisions from the review:

- Stop opening new protocol stages without a concrete requirement.
- Order of work: fixed fields, then reuse of metadata, then removing flags while the format was already changing, then only the affected tests and docs. After that, freeze the protocol and focus on the GUI, the required image and audio demonstrations, the Party A to Party B flow, sample cases, and submission evidence.

### Phases

| Phase | Commit | Outcome |
| --- | --- | --- |
| Baseline | `51fb9e8` | Clean branch `yx`, 54 tests. `nbconvert` was missing; installed later to run the notebook. |
| Fixed 8-byte fields | `76b1e13` | Replaced carrier-dependent field widths |
| Remove flags | `5442b40` | Removed from the format and the API |
| Typed metadata | `04fb47f` | MIME type and name moved into the existing metadata |
| Refuse ambiguous separators | `ff9bd20` | Refuse `;` and `=` in metadata values |
| Refresh the notebook | `602b7b4` | Outputs regenerated with a registered kernel, not hand-edited. Added `nbconvert==7.17.1` for repeatability. |
| Security and test audit | `829c53e` | Confirmed that the security tests survived the reduced format |
| Documentation | `7445538`, `4b69a3d` | Updated the guides and index |

### Measurements after the review

The protocol version was still 2, and 57 tests passed.

| Quantity | Value |
| --- | --- |
| Media ID | 36 bytes |
| Record overhead | 109 bytes |
| Empty packet overhead (record + 16-byte tag + 256-byte signature) | 381 bytes |
| Bootstrap plaintext / AAD | 62 / 18 bytes |
| Bootstrap size (RSA-2048) | 2,048 units |
| Smallest carrier at `k` = 1 / 2 / 3 / 8 (empty metadata, start 2,048) | 5,096 / 3,572 / 3,064 / 2,429 units |
| Banana capacity (6,021,120 units) at `k` = 1 / 2 / 3 / 8 | 752,003 / 1,504,387 / 2,256,771 / 6,018,691 bytes |
| 32,000-sample WAV capacity at `k` = 1 / 2 / 3 / 8 | 3,363 / 7,107 / 10,851 / 29,571 bytes |
| Demo record / ciphertext / packet | 176 / 192 / 448 bytes |

A reported coincidence was corrected: `k × footprint` equals the packet bits plus up to `k−1` padding bits, not always the packet bits. The 448-byte demo packet divides evenly at `k=1` and `k=8`, so the preserved counts happened to match there. At `k` = 3, 5, and 6 there are 1, 1, and 4 padding bits. Outdated notebook figures were corrected to 3384, 3384, and 423.

### Fixes after review

| Commit | Fix |
| --- | --- |
| `d667444` | Corrected the alignment and field wording: bounded values and prefixes stay one byte; general lengths, positions, counters, and timestamps are 8 bytes. |
| `5b854df` | Named the packet-size constants in `serialized_record_length`. |
| `29a3f58` | Oversized metadata now reports `record overhead exceeds record capacity` with both values, instead of the misleading "carrier too small". The payload was already refused before embedding; only the message was wrong. |
| `7c1152e` | Added a named regression test for oversized metadata (55 tests). |
| `a86de7b` | The notebook checks the verdict before reading the payload, avoiding an `AttributeError` on failure. GCM wording was narrowed: GCM authenticates the ciphertext and AAD under the given key and nonce, with no key-commitment claim. |
| `f65515e` | Capacity measurement now enforces the 8-byte field limits and the timestamp range the same way as encoding. There was no live defect, because encoding uses the 36-byte ID and real byte strings never approach the limit, but one shared check is exact. The suite reached 57 tests. |

### Oversights found in the review

| Issue | Kind | Outcome |
| --- | --- | --- |
| Matching preserved-bit counts at `k=1` and `k=8` were reported as a rule. | Coincidence mistaken for a rule | Corrected (see [Measurements after the review](#measurements-after-the-review)); the alignment mechanism now has a dedicated test |
| Regenerated notebook outputs left the surrounding text with old figures. | Stale documentation | Capacities, headings, links, and status checked separately |
| Oversized metadata reported "carrier too small". | Misleading message | Fixed in `29a3f58` |
| The notebook read the payload before checking the verdict. | Defect: `AttributeError` on failure | Fixed in `a86de7b` |

## Move to version 3

The version number stayed at 2 during the simplification review. No released files needed migrating, so a new number then would have had no purpose.

Version 3 was a separate change: commit `3e6c34a`, "Move to protocol version 3 with full media hash and RGBA PNG covers" (2026-09-24). The change widened hash coverage and added RGBA support, without changing the receiver-only encryption, the RSA-OAEP bootstrap, AES-GCM, RSA-PSS, or the typed metadata. Version 1 and 2 files are not accepted by the current verifier. The current format is in the [protocol guide](../protocol.md).

## Practices adopted

Each practice below came from an oversight or near miss recorded above.

| Practice | Origin |
| --- | --- |
| New parameters are required arguments, without defaults. | A default hides the decision at every call site. Callers pass the true value, even 0. |
| Tests compare against hand-written expected values. | A test that computes the expected value with the code under test only checks the code against the same code. |
| Claims of exactness are backed by a test, not a comment. | The stage 1 inverse check and the stage 2a width boundaries were both proven this way. |
| Reported numbers are tested as exact integers. | Ratios hid a 0.004% error: too small to notice, but large enough to be false. |
| Every function arrives with a caller or with tests. | The width function was moved out of stage 1 for having no caller and no tests. |
| Each commit carries one reviewable idea. | Stage 2 carried four unrelated changes and was split into 2a, 2b, and 2c. |
| The code runs at the end of every stage. | A broken intermediate state counts as breakage, not as unfinished work. |
| Exception types are checked, not assumed. | `InvalidTag` turned out not to be a `ValueError`, so the `Cannot Decrypt` verdict would have escaped the handler. |
| A value with two legitimate owners keeps both, joined by a test. | Importing across a layer boundary to remove the duplicate would trade a caught error for a confused design. |
| Dependencies are removed, not hidden. | A function-level import would satisfy Python while breaking the documented layering. |
| A fact used in several places gets a single owner and a test. | The record length lived in three places, with no link between the assumption and the ID generator. |
| Each change is judged against the goals of the version being built. | Decision 10 and the byte-only payload API were first judged against version 1 criteria, and both judgements were wrong. |
