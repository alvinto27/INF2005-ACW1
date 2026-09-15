# Protocol Design

## What the system does

**Current state: reduced protocol version 2.** See the [KISS Reduction Record](KISS-REDUCTION-RECORD.md) and the historical [Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md). The packet has no public marker or header. An RSA-OAEP bootstrap carries the packet geometry and AES-256-GCM session material for the intended receiver. The encrypted record is authenticated by RSA-PSS and the masked media hash. Version 1 files are not readable under this scheme. Serialised protocol integers use fixed unsigned 64-bit big-endian fields, and typed payload claims use encrypted metadata.

The system embeds an encrypted signed payload in the least-significant bits of a strict RGB PNG image or an uncompressed PCM WAV file. It hashes all carrier bits that the embedding operation preserves. Verification requires the sender public key and receiver private key.

## Integrity invariant

Every carrier bit that embedding intentionally preserves is represented in the masked media hash. The payload contains that hash and the user content. The signature authenticates the payload together with the media interpretation and the embedding layout. The signature bytes are validated by RSA-PSS verification itself.

## Why the hash remains reproducible

The encoder and verifier copy the carrier and clear the selected least-significant bits inside the embedding footprint. Packet embedding can change only those cleared bits. Therefore, masking the original carrier and masking the received carrier produce the same bytes when all preserved bits are unchanged.

For example, with `k = 3`, the footprint mask is `11111000`. A carrier byte `10110110` becomes `10110000` for hashing. Embedding can change the byte to any value from `10110000` through `10110111`; applying the same mask always produces `10110000`. A change to any of the upper five bits produces a different masked byte.

The exact media-hash calculation is:

```python
masked = carrier_units.copy()
masked[0:bootstrap_span] &= np.uint8(0xFE)
mask = (~((1 << lsb_count) - 1)) & 0xFF
masked[start_unit:start_unit + footprint] &= np.uint8(mask)
preimage = (
    MEDIA_HASH_DOMAIN
    + struct.pack(">BB", media_code, lsb_count)
    + encode_protocol_field(total_units, "total_units")
    + encode_protocol_field(start_unit, "start_unit")
    + encode_protocol_field(footprint, "footprint")
    + encode_protocol_field(bootstrap_span, "bootstrap_span")
    + masked.tobytes()
)
media_hash = hashlib.sha256(preimage).digest()
```

`MEDIA_HASH_DOMAIN` is exactly:

```python
b"INF2005-ACW1\x00MEDIA-HASH\x00"
```

The shared hash and capacity functions take the reserved bootstrap span as a required argument. Core derives the span from the RSA key and masks the one-LSB bootstrap region as well as the packet region. A start unit below the span is rejected. Every serialised protocol integer uses the single fixed u64 rule: 8-byte unsigned big-endian encoding through `encode_protocol_field`.

## Module dependencies

`bits` depends on `constants` and provides `encode_protocol_field`. `layout` depends on `bits` and `constants`; `packet` and `bootstrap` also depend on `bits` and `constants` and no longer import `layout`. `crypto` and `media` depend only on `constants` and `bits`. `core` is the only module where protocol, crypto, and media meet, and it calls the bootstrap and encryption primitives for encoding and decoding.

## Packet format and signing input

The packet has no header or marker:

```text
record ciphertext plus GCM tag || 256-byte RSA-PSS signature
```

The caller supplies the sender public key and receiver private key to `decode_carrier`, `verify_png`, or `verify_wav`. The receiver recovers `start_unit`, `lsb_count`, and `ciphertext_length` from the RSA-OAEP bootstrap. The encoder returns the recovered geometry in `EmbeddingLayout`.

The payload record is exactly:

```text
media_id_length  u8
media_id         media_id_length bytes of UTF-8
timestamp        u64, Unix seconds in UTC
nonce            16 bytes
media_hash       32 bytes
user_length      u64 unsigned length
user_payload     user_length arbitrary bytes
metadata_length  u64 unsigned length
metadata         metadata_length UTF-8 bytes
```

All integers use big-endian byte order. The packet continues with a 256-byte RSA-2048 signature, followed by `(-packet_bits) mod lsb_count` zero alignment bits.

The exact layout arithmetic is:

```python
packet_bits = (ciphertext_length + 256) * 8
footprint = (packet_bits + lsb_count - 1) // lsb_count
pad_bits = footprint * lsb_count - packet_bits
```

The exact signing input is:

```python
SIGNING_DOMAIN = b"INF2005-ACW1\x00SIGN\x00"
signing_input = (
    SIGNING_DOMAIN
    + struct.pack(">BBB", PROTOCOL_VERSION, media_code, lsb_count)
    + encode_protocol_field(total_units, "total_units")
    + encode_protocol_field(start_unit, "start_unit")
    + encode_protocol_field(footprint, "footprint")
    + encode_protocol_field(ciphertext_length, "ciphertext_length")
    + media_context
    + ciphertext
)
```

The version in this input comes from the protocol constant, not from received data. The ciphertext length includes the 16-byte GCM tag. `max_record_length` accounts for the signature and tag; `max_user_payload_length` also subtracts the record overhead supplied by the caller. The generated 36-byte media id gives a flat 109-byte record overhead before user payload or metadata bytes; user payload and metadata add their own lengths. Capacity helpers refuse a carrier that cannot hold the mandatory packet or record instead of clamping that case to zero. A returned user capacity of zero therefore means the complete protocol object fits exactly and leaves no user bytes.

The PNG media context is exactly `struct.pack(">II", width, height)`. The WAV media context is exactly `struct.pack(">HBIQ", channels, sample_width, frame_rate, frame_count)`.

## Carrier units

A carrier unit is the smallest thing the embedder writes into. Its meaning is per medium:

| Medium | One carrier unit | Units available |
| --- | --- | --- |
| PNG | one 8-bit colour channel value | `width x height x 3` |
| WAV | one PCM **sample** | `frame_count x channels` |

For WAV, the unit is the sample, not the byte. Multi-byte PCM in WAV is always little-endian, so the lowest-address byte of a sample holds its low 8 bits. The carrier therefore takes every `sample_width`-th byte, starting at offset 0, and the writer puts the modified units back into those same positions. Every other byte of the file is copied through unchanged.

This keeps the change to a sample within `(1 << k) - 1`, which is what "replace the low k bits" must mean. It also makes the selectable 1 to 8 LSBs of brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) refer to bits of the cover object, as [FR6](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements) requires.

Capacity follows from the unit count, so multi-byte PCM holds `1 / sample_width` of what a byte count would suggest. That is the honest figure. The larger number came from counting bytes the encoder must not touch.

At `sample_width == 1` the stride is 1, so the sample-stride correction did not change 8-bit behaviour or compatibility at that time. The later stage 4b packet-format change is separate and does break compatibility with version 1 files.

## Payload discovery

Version 1 scanned for a fixed 16-byte marker at each LSB count from 1 to 8. The marker supplied a candidate start unit; its header supplied the record length. This public discovery path is deleted in stage 4b.

The current decoder reads one bootstrap, opens it with the receiver private key, validates its structure, checks geometry bounds, extracts the packet, verifies RSA-PSS over the geometry and ciphertext, opens AES-GCM, parses the record, and then checks the masked media hash. It does not search for another packet after a failure. Relocating a packet still causes RSA-PSS verification to fail because the recovered start unit is signed.

The removed scan had a candidate limit and refused multiple valid candidates. There is no candidate list now, so there is no automatic choice between packets and no ambiguity branch. This does not prove that the carrier holds only one packet.

**Removal of the marker is completed by encryption.** The record has no recognisable plaintext prefix at the user-selected location. The fixed bootstrap span remains observable, but its fields and the packet location are readable only with the receiver private key. See the measured attack in [Location Confidentiality Plan, section 1](LOCATION-CONFIDENTIALITY-PLAN.md#1-the-problem).

## Signature scope

The RSA-PSS signature authenticates the protocol version, media code, selected LSB count, total carrier-unit count, recovered start unit, derived footprint, ciphertext length, fixed media context, and every ciphertext byte. AES-GCM authenticates the recovered session key, nonce, and plaintext record. The record includes the stored media hash, user payload, metadata, media identifier, timestamp, and nonce.

The signature does not authenticate the original values of overwritten cover LSBs. It does not cover file-container metadata outside the decoded carrier units. It does not identify a person, prove freshness, or prevent removal of the embedded packet.

## Verification verdicts

| Verdict | Operational meaning |
| --- | --- |
| `Authentic` | The bootstrap and packet parse, padding is valid, RSA-PSS and AES-GCM verify, and the recomputed masked media hash equals the stored hash. |
| `Tampered` | The signature verifies, but the recomputed masked media hash differs from the signed stored hash. |
| `Signature Invalid` | RSA-PSS verification fails for the extracted signature and reconstructed signing input. |
| `Payload Missing` | The bootstrap cannot be opened with the supplied receiver private key, including a pristine carrier or wrong receiver key. |
| `Wrong Start Location` | Numerically valid geometry recovered from the opened bootstrap produces a footprint outside the carrier or overlaps the reserved bootstrap span. |
| `Cannot Decrypt` | The signed ciphertext fails its AES-GCM authentication tag. |
| `Cannot Verify` | The adapter rejects the file, the bootstrap is structurally malformed, or packet parsing or padding validation fails. |

Version 1 preferred the deepest failure among discovered candidates. Stage 4b checks one supplied layout and reports its failure directly. A caller can supply a wrong location that remains in range; it then receives the parsing, padding, or signature failure reached at that location, not proof that the file has no payload.

## Limitations

- Overwritten cover LSBs are destroyed and cannot be recovered or authenticated.
- The alignment padding zero-check is a format check, not a cryptographic one.
- RSA-PSS is randomised, so verification proves the signed input is intact, not that the signature bytes are byte-for-byte original.
- Preserved bits depend on packet size, not LSB depth: `preserved_bits = 8*total_units - bootstrap_span - k*footprint`, and `k*footprint` is exactly the packet bit count. For the same packet, `k = 1` and `k = 8` therefore preserve the same 48,163,528 bits in the refreshed demonstration. At `k = 8` with a full-carrier footprint, packet bits equal all carrier bits and the media hash witnesses nothing; the reported `preserved_bits` says so.
- The bootstrap field values and record are encrypted or authenticated for the receiver; the fixed bootstrap span still reveals the envelope footprint.
- Container metadata outside the decoded carrier is not covered.
- A timestamp and nonce alone do not prevent replay.

## Authenticity claim

The received media and embedded verification data pass the defined integrity checks, and the digital signature verifies using the public key supplied for verification.

This claim says nothing about a real-world identity. The caller must obtain the correct public key by a separate method.

## What this project does not implement

- Caller-side key management, trust stores, and replay protection
- Automatic packet discovery in the stage 4b format
- Key management or a trust store
- Public-key infrastructure (PKI)
- Networking
- Replay protection

---

## Typed Payload Metadata

Protocol version 2 encrypts the complete payload record inside the library, including `user_payload`. The notebook's typed-payload demonstration uses the existing `metadata` field for the MIME claim and original filename; the file bytes remain raw in `user_payload`. No caller-side seal or nested content header remains.

The working demonstration is in the Confidentiality from the protocol and Typed payloads sections of the [demonstration notebook](../notebooks/FR1-12%20Prototype.ipynb).

### 1. Record and metadata

Nothing in the payload record stays readable. AES-256-GCM protects the complete record, including the media id, timestamp, record nonce, media hash, user payload, and metadata. RSA-OAEP protects the bootstrap fields, session key, and packet geometry. The receiver decrypts the record, recomputes the masked media hash, and compares it with the recovered value. The [Location Confidentiality Plan, section 3.5](LOCATION-CONFIDENTIALITY-PLAN.md#35-the-whole-payload-record-is-encrypted) records why FR9 requires the comparison.

The notebook uses this metadata convention for typed payloads:

```text
kind=png;flow=typed-content;mime=image/png;name=generated.png
```

Entries are separated by `;` and each key is separated from its value by `=`. The sender refuses `;` and `=` in the MIME and filename values because the convention has no escaping layer. The receiver reads the fields by splitting the metadata string. There is no version byte, length prefix, JSON object, or replacement envelope.

#### Key handling in the demonstration

The receiver's private key is written to a password-protected PEM file, then loaded again in the receiver phase. The receiver verifies with a sender public key and the receiver private key. The geometry is recovered from the RSA-OAEP bootstrap; it is not transported as three plaintext values.

### 2. The declared type is a claim, not a fact

A signature proves that the sender said the bytes were a PNG. It does not prove that the bytes are a PNG. A signature can make a false claim look trustworthy, which is worse than no signature if the receiver relaxes because of it.

Therefore the receiver chooses a handler from the declared type, then confirms with the bytes before it renders anything:

```text
sniffed is None   ->  agrees only when the declared type has no known magic bytes
sniffed is set    ->  agrees only when it equals the declared type
```

The four outcomes:

| Declared | Sniffed | Agrees | Reason |
| --- | --- | --- | --- |
| `text/plain` | none | yes | text has no magic bytes. Absence is not a contradiction |
| `image/png` | none | no | claims a type with known magic bytes, and the bytes are absent |
| `image/png` | `image/png` | yes | the claim and the bytes agree |
| `text/plain` | `image/png` | no | the bytes claim a known binary type that the sender denied |

The check is inside the function that renders. It is not at the call site. A check that the caller can forget is not a check.

Types recognised by magic bytes: `image/png`, `image/jpeg`, `audio/wav`, `application/pdf`.

### 3. Handler table

| Declared type | Action |
| --- | --- |
| `text/plain` | print the text. On invalid UTF-8, save the bytes and report the path |
| `image/png`, `image/jpeg` | save, then display |
| `audio/wav`, `audio/mpeg` | save, then play |
| anything else, or empty | save and report the path |
| declared type disagrees with the bytes | save and report the path. Do not render |

The function that writes the file derives its own safe filename. It does not trust the name it was given, even after the receiver validates it. The function that writes is the function that must be safe.

### 4. Capacity

Capacity uses the library's actual encrypted record, with empty metadata and packet start at the reserved 2,048-unit RSA-2048 bootstrap span. The generated 36-byte media id gives 109 bytes of record overhead. Adding the 16-byte GCM tag and 256-byte RSA-PSS signature gives 381 bytes before user payload. These values come from the capacity helpers; a later start or nonempty metadata reduces the user capacity.

| `k` | Banana PNG, 6,021,120 units | Demonstration WAV, 32,000 samples |
| ---: | ---: | ---: |
| 1 | 752,003 | 3,363 |
| 2 | 1,504,387 | 7,107 |
| 3 | 2,256,771 | 10,851 |
| 8 | 6,018,691 | 29,571 |

Use `max_user_payload_length` with the actual start and record overhead when accepting a user payload. The table is capacity for the current library protocol, not for a caller-side seal.

The image carrier holds a small image or a short audio clip at `k=1`. The demonstration audio carrier holds text only. That limit comes from the short 8-bit mono tone the notebook generates, not from the design. Capacity grows in proportion to the sample count, so a longer cover removes the difference.

For an audio cover, one carrier unit is one PCM sample, not one byte. See [Carrier units](PROTOCOL-DESIGN.md#carrier-units). Therefore a multi-byte cover holds `1 / sample_width` of what its file size suggests: a 16-bit cover holds half, a 24-bit cover a third, and a 32-bit cover a quarter. Longer audio buys capacity; deeper samples do not.

### 5. Limitations

- The type declaration protects an honest receiver from a mistake. It does not protect anyone from a sender who signs a hostile file. Software that renders the payload must still validate the file itself.
- Compression must happen before encryption, because encrypted bytes do not compress. Compression before encryption leaks information about the plaintext through the ciphertext length. Nothing in this design lets an attacker inject chosen data into the plaintext, so the risk is theoretical here, but it is real in designs that do.
- The metadata convention describes one file. Several files need an archive as the user payload, with `mime` set to the archive type. The convention needs no new wrapper for that.
- The metadata convention separates entries with `;` and keys from values with `=`. The sender refuses those characters in MIME and filename values because it has no escaping layer.
- The demonstration sends the message content as a placeholder string. The team still chooses the message it demonstrates.

# Design history
Everything above says what the current intermediate format does. What follows records the version 1 design history: what was tried, what was thrown out, and what still bothers us. Historical line counts and measurements below describe that earlier implementation. It is here because this repository was rebuilt from something much bigger, and none of those reasons survive in the code itself.

## Where this started

The first version was 5,079 lines. It had four copies of the same protocol, three design documents that disagreed with each other, a trust store, key management, a scheme for remembering keys on first use, and a hashing design that worked in three separate regions. The assignment asked for none of it.

What is left is 1,485 lines: 1,164 in the package and 321 in the tests.

Nothing was cut for neatness. Every part that went failed the same two questions: does the brief ask for this, and does anything else here need it?

## How the hashing changed

The old design hashed the carrier in three pieces: the bytes before the packet, the bytes after it, and the packet's own area handled separately. It needed special cases at both edges, and those edges caused most of the early bugs.

The new rule is one sentence: copy the carrier, clear the low bits where the packet sits, hash what is left. The sender and the receiver run the same code. There are no edges, so there are no edge cases.

There is a price, and the Limitations section says so plainly. The bigger the packet, the fewer bits the hash is actually watching. At `k = 8` with a packet filling the whole carrier, the hash watches nothing at all. The system reports `preserved_bits` so you can see that rather than assume you are protected.

## How the code was split up

It used to be one file. Now it is eight, and the imports only ever flow one way:

```text
constants -> bits -> layout -> packet -> core
crypto and media only need constants and bits
core is the one place where the protocol, crypto, and the file formats meet
```

One rule produced that shape: a module may never import something that imports it back. Follow it strictly and `core` ends up as the only place that knows both what a PNG is and what a signature is. Everything else stays small and unaware.

The old single file was deleted only after the new package passed the whole test suite by itself.

## Decisions, and what was rejected

| Decision | Why | What was rejected |
| --- | --- | --- |
| Masked-bit hashing | One rule, no boundary cases, identical code on both sides | Three-region hashing |
| Version 1: `start_unit` is discovered, never declared | No field for an attacker to falsify; relocation breaks the signature. Stage 4b replaces discovery with explicit geometry; the signature still binds it | A start-location header field |
| Signature covers geometry as well as payload | A relocated packet fails even with identical payload bytes | Signing the payload alone |
| Per-bit Python loops in `bits.py` | Measured: a 1 MB payload encodes in 2.9 s. These are the most readable functions in the package | Vectorised bit packing, faster and unreadable |
| Version 1: keep the 64-candidate scan bound and the ambiguity branch | Cheap; the ambiguity branch prevented a silent choice between two valid packets. Both are removed with the scan in stage 4b, which checks only the supplied geometry | Removing them while retaining discovery |
| One `VerificationError` carrying a verdict | Three exception classes existed only to route three strings | Three separate exception types |
| Byte-only payload API | Confidentiality becomes a caller-side concern with no library change | Built-in encryption |
| — | **Withdrawn by the proposed protocol version 2.** Location confidentiality cannot be reached from outside the library, because the structure that leaks the start location is the record `core.py` builds. See [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md#the-byte-only-payload-api-is-withdrawn) | — |
| Notebook helpers stay in the notebook | The library does not grow to serve a demonstration | Adding display code to `stego/` |
| Fixed 32-byte PSS salt | Matches the SHA-256 digest and is predictable for other libraries; this reason was recorded after the rewrite, not when the value changed | `PSS.MAX_LENGTH` in `main`, which gives a 222-byte salt |

## Why the PSS salt length changed

PSS adds random bytes, called the salt, to the padding before it signs. The same input therefore gets a different signature each time. Both sides must use the same salt length because the verifier rebuilds the PSS padding with that setting.

`origin/main` uses `padding.PSS(..., salt_length=padding.PSS.MAX_LENGTH)` in `_get_pss_padding()`. With an RSA-2048 key and SHA-256, that maximum is 222 bytes. This branch uses a fixed 32-byte salt, the same length as the SHA-256 digest, through `RSA_PSS_SALT_LENGTH` in `constants.py`.

RFC 8017 gives the hash length as the typical PSS salt length, and 32 bytes is a common default. That makes the value predictable and lets other libraries verify these signatures without being told an unusual setting. The named constant also keeps the value in one place instead of relying on what a library computes as `MAX_LENGTH` from the key size.

The security difference between a 32-byte salt and a 222-byte salt is not meaningful here. A longer salt does not make forgery meaningfully harder. The fixed value was chosen for predictability and interoperability, not for strength.

A verifier expecting `PSS.MAX_LENGTH` rejects a signature made with a 32-byte salt. Nothing in this repository stores old signatures, so the practical cost is zero. The two branches are not signature-compatible.

The salt length changed during the rewrite. It was not chosen at the time with a recorded reason. This explanation was written afterwards, when the difference was noticed while preparing to merge.

`origin/main/README.md` incorrectly says that the module uses RSA PKCS#1 v1.5 and SHA-256, even though its code uses RSA-PSS. It is an example of documentation drifting away from code.

## Arguments worth remembering

Each of these changed a decision, and none of the reasoning shows up in a diff.

**Passing tests do not mean the code is right.** While splitting the modules, three checks quietly stopped working and every test still passed. The fault was in the tests:

```python
except (TypeError, ValueError):
    pass          # cannot tell "it rejected the value" from "we called it wrong"
```

That catch could not tell the difference between a validator doing its job and a test calling the function incorrectly. The tests were tightened to check for the specific failure before the split went any further. Of everything found during the rebuild, this mattered most.

**The tests did not exercise the parameter space the API advertised.** `WavPcmData` accepted `sample_width` 1 to 4, but both WAV tests used `setsampwidth(1)`. At one byte per sample, a byte and a sample are the same thing, so a byte-wise carrier looked correct. It was not. For wider samples the embedder wrote into the low bit of *every* byte, including the most significant one. Measured maximum sample change at `k=1`:

| Sample width | Measured | Correct |
| --- | ---: | ---: |
| 8-bit | 1 | 1 |
| 16-bit | 257 | 1 |
| 24-bit | 65,793 | 1 |
| 32-bit | 16,843,009 | 1 |

The error is the sum of every byte's place value, `1 + 256 + 65536 + 16777216`, not one bad byte. In noise terms the floor sat at -42 dBFS at `k=1` for every bit depth, so a 24-bit cover was damaged exactly as much as an 8-bit one and all the extra depth was thrown away. Sample-wise gives -90 dBFS at 16-bit and -138 dBFS at 24-bit.

Nothing failed. A 16-bit stego file still verified as `Authentic` and the payload still round-tripped. The bug was invisible to every check the project had, because the checks only ever asked "did the bytes come back", never "how far did the cover move". The fix added one assertion per width: `max(abs(original - stego)) <= (1 << k) - 1`. Four widths accepted, one tested, is the shape of defect to look for elsewhere.

**Most of the defensive code was guarding a door that no longer exists.** Validators refused a `True` where a number belonged. A length limit sat on a public key the program generates itself. Payload length was checked against two different ceilings. The packet header was parsed a second time and compared with the first parse of the same unchanged data. All of it made sense when the decoder read keys and JSON from strangers. It does not do that any more. No test can tell you whether removing a check is safe, so they were removed one at a time, in a list, and anything that raised a doubt was kept.

**Deleting dead code leaves more dead code behind.** Removing unused functions stranded the imports and constants that only those functions used. A second sweep found `secrets`, `datetime`, `timezone`, and `MEDIA_PREFIXES` still sitting in `packet.py`. One pass is never enough.

**When a tool keeps changing your file, it may be right.** The notebook kept editing itself after every commit. It was not autosave. The file said it was `nbformat 4.5`, that format requires every cell to carry an `id`, and the committed file had none. Every program that opened it fixed the file. The answer was to make the notebook valid, not to keep undoing the repair.

**One rule was written and then taken back.** Straight after that fix came a convention banning committed notebook outputs. The owner overruled it, correctly. The real bug was the invalid format; the output ban was tidiness bolted onto a bug fix, and it cost a manual undo after every run. It was removed in its own commit so the reversal is easy to find.

**A compression detail decided how one test case works.** The capacity case tries to hide the cover image inside itself. It uses the raw pixels, 6,021,120 bytes, not the PNG file, 1,673,875 bytes. PNG compresses, so the file version actually fits at `k = 3`. Using it would have let the test pass while looking like it proved the opposite.

## Afterthoughts

Known rough edges, written down so nobody has to find them the hard way.

**Hiding data makes the file bigger.** PNG compression is lossless, so the pixels come back exactly and the payload survives. But the bits we write in are basically random, and random data does not compress. Measured on `samples/Banana.png`:

| File | Size | Difference |
| --- | ---: | ---: |
| Cover | 1,673,875 | — |
| Stego at `k = 1` | 1,675,090 | +1,215 |
| Stego at `k = 3` | 1,675,035 | +1,160 |
| Stego at `k = 8` | 1,674,414 | +539 |

Someone holding both files sees about a kilobyte of growth at the same image size. That is a real hint that something is hidden. On its own it proves little, since re-saving a PNG with different settings also changes the size, but it is a genuine weakness and any honest write-up should mention it.

**`encode_png` does not give back the media context.** The notebook has to rebuild it to show the signed bytes. That is a small copy of library logic sitting somewhere it can go stale. It was left alone, because the alternative was changing what the library returns just to make a notebook cell nicer, and that is the worse trade. If the encode functions ever return something richer, this is the reason to do it.

**The version 1 order of failure verdicts was a judgement call.** When several candidates failed in different ways, that decoder reported the one that got furthest. Stage 4b removes this selection with discovery. The old choice was meant to give the most useful answer to a person reading it. It carries no security meaning. Do not build anything on top of it.

**The bit loops will not scale.** They are fast enough here and easier to read than anything else we tried: a 1 MB payload takes 2.9 seconds. A much larger payload would drag. That choice came from measuring, not guessing, and the measurement is written down so the next person can change their mind with evidence instead of instinct.

**Tests prove it works; the notebook shows it working.** The notebook has no assertions, on purpose. The moment it starts testing things, it will drift away from the real test suite and end up contradicting it, which is exactly how this project ended up with three design documents that disagreed.

**There is no encryption, and that was on purpose.** `user_payload` takes any bytes you like, so anyone who needs secrecy can encrypt before handing it over. The library has no opinion about what the plaintext says. That keeps the protocol to bytes alone, and keeps decisions about cryptography policy outside of it.
