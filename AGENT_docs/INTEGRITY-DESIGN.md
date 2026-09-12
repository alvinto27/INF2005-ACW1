# Masked Media Integrity Design

## What the system does

The system embeds a signed binary payload in the least-significant bits of a strict RGB PNG image or an uncompressed PCM WAV file. It hashes all carrier bits that the embedding operation preserves. Verification uses a caller-supplied RSA public key to authenticate the payload, media interpretation, and embedding layout.

## Integrity invariant

Every carrier bit that embedding intentionally preserves is represented in the masked media hash. The payload contains that hash and the user content. The signature authenticates the payload together with the media interpretation and the embedding layout. The signature bytes are validated by RSA-PSS verification itself.

## Why the hash remains reproducible

The encoder and verifier copy the carrier and clear the selected least-significant bits inside the embedding footprint. Packet embedding can change only those cleared bits. Therefore, masking the original carrier and masking the received carrier produce the same bytes when all preserved bits are unchanged.

For example, with `k = 3`, the footprint mask is `11111000`. A carrier byte `10110110` becomes `10110000` for hashing. Embedding can change the byte to any value from `10110000` through `10110111`; applying the same mask always produces `10110000`. A change to any of the upper five bits produces a different masked byte.

The exact media-hash calculation is:

```python
masked = carrier_units.copy()
mask = (~((1 << lsb_count) - 1)) & 0xFF
masked[start_unit:start_unit + footprint] &= np.uint8(mask)
preimage = (
    MEDIA_HASH_DOMAIN
    + struct.pack(">BBQQQ", media_code, lsb_count, total_units, start_unit, footprint)
    + masked.tobytes()
)
media_hash = hashlib.sha256(preimage).digest()
```

`MEDIA_HASH_DOMAIN` is exactly:

```python
b"INF2005-ACW1\x00MEDIA-HASH\x00"
```

## Module dependencies

Imports flow from `constants` to `bits`, then `layout`, `packet`, and `core`. The `keys` and `media` modules depend only on `constants` and `bits`; `core` is the only module where protocol, keys, and media meet.

## Packet format and signing input

The packet header is exactly 23 bytes with this format:

```python
PACKET_HEADER_FORMAT = ">16sBBBI"
```

| Header field | Size | Value |
| --- | ---: | --- |
| `magic` | 16 bytes | `d9df721b281169d4335290e30fdb48b1` |
| `version` | 1 byte | `1` |
| `lsb_count` | 1 byte | `1` through `8` |
| `media_code` | 1 byte | `1` for PNG or `2` for WAV |
| `payload_length` | 4 bytes | Length of the complete payload in bytes |

The payload is exactly:

```text
media_id_length  u8
media_id         media_id_length bytes of UTF-8
timestamp        u64, Unix seconds in UTC
nonce            16 bytes
media_hash       32 bytes
user_length      u32
user_payload     user_length arbitrary bytes
metadata_length  u32
metadata         metadata_length UTF-8 bytes
```

All integers use big-endian byte order. The packet continues with a 256-byte RSA-2048 signature, followed by `(-packet_bits) mod lsb_count` zero alignment bits.

The exact layout arithmetic is:

```python
packet_bits = (23 + payload_length + 256) * 8
footprint = (packet_bits + lsb_count - 1) // lsb_count
pad_bits = footprint * lsb_count - packet_bits
```

The exact signing input is:

```python
SIGNING_DOMAIN = b"INF2005-ACW1\x00SIGN\x00"
signing_input = (
    SIGNING_DOMAIN
    + struct.pack(
        ">BBBQQQI",
        PROTOCOL_VERSION,
        media_code,
        lsb_count,
        total_units,
        start_unit,
        footprint,
        payload_length,
    )
    + media_context
    + payload_bytes
)
```

The PNG media context is exactly `struct.pack(">II", width, height)`. The WAV media context is exactly `struct.pack(">HBIQ", channels, sample_width, frame_rate, frame_count)`.

## Payload discovery

The decoder scans the carrier for the fixed 16-byte magic under each `k` value from 1 through 8. Each match supplies a candidate start unit and `k`. The decoder then reads the fixed header, checks its declarations, derives the footprint, extracts the packet, and applies the verification stages without moving or resizing the candidate.

`start_unit` is never declared in the packet. It is discovered from the magic position and then included in the signing input. There is no start field for an attacker to falsify, and relocating a packet causes RSA-PSS verification to fail.

## Signature scope

The RSA-PSS signature authenticates the protocol version, media code, selected LSB count, total carrier-unit count, discovered start unit, derived footprint, payload length, fixed media context, and every payload byte. The payload bytes include the stored media hash, user payload, metadata, media identifier, timestamp, and nonce. RSA-PSS verification validates the received signature bytes against this signing input.

The signature does not authenticate the original values of overwritten cover LSBs. It does not cover file-container metadata outside the decoded carrier units. It does not identify a person, prove freshness, or prevent removal of the embedded packet.

## Verification verdicts

| Verdict | Operational meaning |
| --- | --- |
| `Authentic` | The packet parses, its padding is valid, its RSA-PSS signature verifies with the supplied key, and the recomputed masked media hash equals the signed stored hash. |
| `Tampered` | The signature verifies, but the recomputed masked media hash differs from the signed stored hash. |
| `Signature Invalid` | RSA-PSS verification fails for the extracted signature and reconstructed signing input. |
| `Payload Missing` | No start-magic candidate is found for any supported LSB count. |
| `Wrong Start Location` | Magic is found, but the declared packet length produces an out-of-range or inconsistent footprint at that discovered start. |
| `Cannot Verify` | The adapter rejects the file, or packet parsing, bounds, header consistency, or padding validation fails. |

When candidates fail at different stages, the decoder prefers the failure that reached the deepest integrity check: `Tampered`, then `Signature Invalid`, then `Wrong Start Location`, then `Cannot Verify`.

## Limitations

- Overwritten cover LSBs are destroyed and cannot be recovered or authenticated.
- The alignment padding zero-check is a format check, not a cryptographic one.
- RSA-PSS is randomised, so verification proves the signed input is intact, not that the signature bytes are byte-for-byte original.
- As the footprint grows, the preserved-bit count falls. At `k = 8` with a full-carrier footprint, the media hash witnesses nothing, and the reported `preserved_bits` says so.
- The magic is public, so anyone can locate and strip the packet. This is concealment, not security.
- Container metadata outside the decoded carrier is not covered.
- A timestamp and nonce alone do not prevent replay.

## Authenticity claim

The received media and embedded verification data pass the defined integrity checks, and the digital signature verifies using the public key supplied for verification.

This claim says nothing about a real-world identity. The caller must obtain the correct public key by a separate method.

## What this project does not implement

- Encryption
- Key management or a trust store
- Public-key infrastructure (PKI)
- Networking
- Replay protection

---

# Design history

Everything above says what the system does. What follows says how it ended up that way: what was tried, what was thrown out, and what still bothers us. It is here because this repository was rebuilt from something much bigger, and none of those reasons survive in the code itself.

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
keys and media only need constants and bits
core is the one place where the protocol, the keys, and the file formats meet
```

One rule produced that shape: a module may never import something that imports it back. Follow it strictly and `core` ends up as the only place that knows both what a PNG is and what a signature is. Everything else stays small and unaware.

The old single file was deleted only after the new package passed the whole test suite by itself.

## Decisions, and what was rejected

| Decision | Why | What was rejected |
| --- | --- | --- |
| Masked-bit hashing | One rule, no boundary cases, identical code on both sides | Three-region hashing |
| `start_unit` is discovered, never declared | No field for an attacker to falsify; relocation breaks the signature | A start-location header field |
| Signature covers geometry as well as payload | A relocated packet fails even with identical payload bytes | Signing the payload alone |
| Per-bit Python loops in `bits.py` | Measured: a 1 MB payload encodes in 2.9 s. These are the most readable functions in the package | Vectorised bit packing, faster and unreadable |
| Keep the 64-candidate scan bound and the ambiguity branch | Cheap; the ambiguity branch is the only thing preventing a silent choice between two valid packets | Removing them with the rest of the hardening |
| One `VerificationError` carrying a verdict | Three exception classes existed only to route three strings | Three separate exception types |
| Byte-only payload API | Confidentiality becomes a caller-side concern with no library change | Built-in encryption |
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

**The order of failure verdicts is a judgement call.** When several candidates fail in different ways, the decoder reports the one that got furthest. That is meant to be the most useful answer for a person reading it. It carries no security meaning. Do not build anything on top of it.

**The bit loops will not scale.** They are fast enough here and easier to read than anything else we tried: a 1 MB payload takes 2.9 seconds. A much larger payload would drag. That choice came from measuring, not guessing, and the measurement is written down so the next person can change their mind with evidence instead of instinct.

**Tests prove it works; the notebook shows it working.** The notebook has no assertions, on purpose. The moment it starts testing things, it will drift away from the real test suite and end up contradicting it, which is exactly how this project ended up with three design documents that disagreed.

**There is no encryption, and that was on purpose.** `user_payload` takes any bytes you like, so anyone who needs secrecy can encrypt before handing it over. The library has no opinion about what the plaintext says. That keeps the protocol to bytes alone, and keeps decisions about cryptography policy outside of it.
