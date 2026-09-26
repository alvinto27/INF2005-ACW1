# Design history

**Status:** Historical record. The version 1 design described below is not the active protocol.

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
