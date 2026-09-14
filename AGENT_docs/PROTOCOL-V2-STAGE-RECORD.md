# Protocol Version 2 Stage Record

This record holds what each completed stage of the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) actually changed, what was measured, and what the stage taught. The plan holds the design and the intent. This file holds the outcome.

One entry per stage, written when the stage is committed. A stage is not finished until it has an entry here.

Each entry names a commit, and a commit cannot contain its own hash, so an entry lands in a small follow-up commit immediately after the stage it describes. Amending the stage commit to insert the hash changes the hash.

## Status

| Stage | Scope | Commit | State |
| ---: | --- | --- | --- |
| 1 | Carrier-derived payload capacity | `a313203` | done |
| 2a | Derived widths in both signed formats, signed `flags` | `23fce87` | done |
| 2b | Reserved region in the mask, the hash, and the fidelity count | `2d7220c` | done |
| 2c | `keys.py` renamed to `crypto.py` | `4df44c4` | done |
| 3 | `bootstrap.py` and the envelope primitives | `16ff1d3` | done |
| 4a | Name the two capacity quantities, thread the span | `cc72dd3` | done |
| 4b | Delete the marker, scan and header; explicit geometry | — | next |
| 4c | Bootstrap carries the geometry; record encrypted | — | planned |
| 5 | Notebook | — | planned |

Version 1 behaviour is unchanged so far. Every stage to date is preparation, and all 38 tests pass without modification to any pre-existing test body.

## Stage 1: carrier-derived payload capacity

Commit `a313203`. 25 tests.

| Item | Outcome |
| --- | --- |
| Removed | `MAX_PAYLOAD_LENGTH`, a fixed 16 MiB cap |
| Added | `max_payload_length(total_units, start_unit, lsb_count)` |
| Changed | the rejection message now names all four capacity inputs |

**The defect this fixed.** A 4000x3000 RGB photograph at 8 LSBs holds 35,997,579 bytes. The constant refused 19 MB that fit. Brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) asks whether the payload is larger than the cover object, so the answer must come from the cover object.

**What was proved rather than asserted.** The helper claims to be the exact inverse of `build_embedding_layout`. The slack is the available bit count modulo 8, at most 7, so one further byte always overflows. Tests at 1, 3 and 8 LSBs assert that the returned value builds and that the value plus one raises.

**Security check.** Removing the cap leaves an attacker-declared length unbounded at parse time. The decode path was traced twice, by the implementer and by the reviewer: header parsing is followed by two comparisons and then by `build_embedding_layout`, and no allocation or slice uses the declared length before that carrier bound succeeds. The carrier is a tighter bound than an unrelated constant.

**What the stage taught.** No helper may take a carrier and an LSB count alone and return a capacity, because it would assume a start unit of 0. That is correct in version 1 and silently wrong once a reserved region exists. The start unit is a required argument with no default, and the same rule was applied to `bootstrap_span` in stage 2b.

## Stage 2a: derived widths and a signed flags byte

Commit `23fce87`. 27 tests.

| Format | Version 1 | Version 2 |
| --- | --- | --- |
| Media hash context | `">BBQQQ"` | `">BB"` and three W-byte fields |
| Signing context | `">BBBQQQI"` | `">BBBB"` and four W-byte fields |

Stage 1 removed a ceiling from the payload path, but both signed formats still pinned their layout fields at 64 and 32 bits. The ceiling had moved, not gone.

**Width rule.** `carrier_field_width(total_units)` returns `max(1, (bit_length + 7) // 8)`, and it is the only place a width may be derived. `bit_length(N)` and `bit_length(N - 1)` disagree at powers of two, the two expressions look interchangeable, and a disagreement between sender and verifier would break every signature.

**The boundaries are tight, and that is correct.** At 255 units the width is 1 byte holding a maximum of 255. At 65,535 units it is 2 bytes holding a maximum of 65,535. No field can overflow, because the payload byte count is at most units times the LSB count divided by 8, the count never exceeds 8, and both the footprint and the start unit are bounded by the unit count. The invariant holds by construction, so no runtime guard was added and the reasoning is recorded instead.

**Why `flags` is signed while it must always be zero.** Without it in the signing input, an attacker keeps the signed bytes in place and changes only how they are interpreted. The signature verifies, the masked hash matches, and the verdict is `Authentic`. Nothing is forged; the signature authenticated the bytes but not their meaning. Signing it now means the next field added there arrives already covered.

**What the stage taught.** Two approval tests already pinned the version 1 formats. They were updated in place and strengthened: expected bytes became literals instead of a second call to the packing code. During that work an expected value for 256 units was written as `00 ff`, which is 255 in two bytes. The literal caught it. Had the test computed its expectation with `carrier_field_width`, it would have agreed with itself and proved nothing.

A further test builds the signing input at 255 and 256 units and asserts the field bytes grow from 4 to 8. The standalone width tests prove the arithmetic; that test proves the width reaches the preimage.

## Stage 2b: the reserved region reaches three places

Commit `2d7220c`. 32 tests.

The version 2 bootstrap occupies a reserved region at the front of the carrier and overwrites its low bit. Three places must know:

| Place | Change | If it had been missed |
| --- | --- | --- |
| Mask range | clear the low bit across the span, at a fixed `0xFE` | every verification reports `Tampered` |
| Hash preimage | commit to the span as a fourth derived-width field | the hash does not pin its own geometry |
| `preserved_bit_count` | subtract one bit per unit across the span | the reported fidelity number is false |

The mask uses `0xFE` there rather than a mask derived from the user's LSB count, because the bootstrap is always written at one bit per unit.

**The fidelity count is a published claim.** `preserved_bit_count` is returned in `VerificationResult` and reported in the notebook as the FR11 and FR12 evidence. The bootstrap writes one bit per unit, so omitting the span overstates untouched bits by exactly the span at every LSB count. On the 1280x1568 sample carrier that is 2,048 bits, or 0.004%.

| LSB count | Ratio without the span | Ratio with the span |
| ---: | ---: | ---: |
| 1 | 0.999784 | 0.999741 |
| 8 | 0.999784 | 0.999741 |

Equal to four decimal places. The tests therefore assert exact integers, 78,500 at span 0 and 76,452 at span 2,048 for a 10,000-unit carrier with a 500-unit footprint at 3 LSBs, and assert that the difference is exactly the span at 1, 3 and 8 LSBs. That last test states the defect itself rather than a value that happens to be right.

**Migration pattern.** `bootstrap_span` is required everywhere and every existing caller passes 0 explicitly. Zero is truthful, because version 1 has no bootstrap, so behaviour is unchanged and the diff marks every site stage 3 must revisit. A default value would have hidden the decision at each call site.

**What the stage taught.** The notebook called `preserved_bit_count` with three arguments and would have raised `TypeError`. It was corrected in the same commit. Leaving the repository unrunnable between stages is breakage, not deferral.

Reading that cell to apply the fix revealed a second problem: it reports the figure as a ratio formatted to two decimal places, which prints `99.99%` with or without the correction. The cell cannot show the difference it exists to demonstrate, so the stage 6 gate now asks for the exact integer beside the ratio.

## Stage 2c: crypto module rename

Commit `4df44c4`. 32 tests.

`stego/keys.py` became `stego/crypto.py`. A 100% rename, zero lines changed inside the file, exported name count 52 before and 52 after.

Stage 3 adds RSA-OAEP and AES-GCM to that module, and a module called `keys` holding a symmetric cipher would describe two thirds of its contents. The rename is a separate change so that the diff adding the envelope functions carries no import churn across the package.

The module docstring still describes RSA-PSS signing and PEM handling only. It is accurate today and is widened when the envelope functions land, not before.

## Stage 3: the bootstrap envelope and the crypto primitives

Commit `16ff1d3`. 38 tests. First stage that adds a module, and the first that adds cryptography.

Nothing calls any of it yet, so it shipped with tests that exercise it. That rule came from stage 1, where the width function was moved out for having neither a caller nor a test of its use.

| Layer | Module | Added |
| --- | --- | --- |
| Primitives | `crypto.py` | `rsa_oaep_padding`, `seal_to_public_key`, `open_with_private_key`, `aead_seal`, `aead_open` |
| Constants | `constants.py` | `BOOTSTRAP_START_UNIT`, `BOOTSTRAP_LSB_COUNT`, `SESSION_KEY_SIZE`, `AEAD_NONCE_SIZE`, `BOOTSTRAP_PREFIX_FORMAT` |
| Format | `bootstrap.py` | `BootstrapFields`, `bootstrap_span`, `serialize_bootstrap`, `parse_bootstrap`, `encode_bootstrap_aad` |

**Measurements.**

| Item | Value |
| --- | ---: |
| Serialised bootstrap at 255 units, width 1 | 49 B |
| Serialised bootstrap at 256 units, width 2 | 51 B |
| Additional authenticated data, same two cases | 5 B and 7 B |
| RSA-2048 OAEP-SHA256 plaintext limit | 190 B |
| `bootstrap_span` for an RSA-2048 key | 2,048 units |

The envelope fits with 141 bytes to spare at width 1. The limit was asserted as a literal rather than computed, and the stage brief said to stop and report if any realistic carrier size made it not fit.

**No fixed span constant exists.** The span is computed from the key at runtime. That was the single mistake most worth avoiding in this stage, because a constant would have been correct for RSA-2048 and wrong for everything else.

**The span is defined by the envelope, not the key.** For RSA-OAEP the ciphertext length equals the modulus length, so the two coincide and the code looks as though it uses the key size. A comment states the coincidence, and the variable is named `envelope_bytes`. An X25519 envelope is 113 bytes against a 32-byte key, so a key-size definition would give 256 units instead of 904 and corrupt every read.

**`InvalidTag` is not a `ValueError`.** Every AES-GCM failure raises `cryptography.exceptions.InvalidTag`, whose base class is `Exception`. `decode_carrier` catches `ValueError`. Stage 4 must catch `InvalidTag` explicitly, or the single failure that `Cannot Decrypt` exists for will escape the verdict machinery and surface as a crash. Recorded in the plan at [section 7](LOCATION-CONFIDENTIALITY-PLAN.md#7-decode).

That finding matters because of decision 12. `Cannot Decrypt` was chosen over a signed commitment on the grounds that the informative verdict is worth more. The choice is worth nothing if the exception never reaches the code that names it.

**One number, two owners.** `crypto.py` enforces a 32-byte key because that is a fact about AES-256. `constants.py` declares `SESSION_KEY_SIZE` because that is the width of a bootstrap field. They are equal because the protocol chose AES-256, not because they are the same thing, so neither module imports the other. A test asserts they agree: the declared sizes must seal and open, and one byte either side must raise. Without it, a switch to AES-128 would change one constant and fail at runtime instead of at test time.

**Where the key size is pinned.** `bootstrap_span` accepts any RSA key size, because the envelope formula is general, while `seal_to_public_key` calls `validate_rsa_public_key`, which pins RSA-2048. The asymmetry is deliberate and was recorded rather than removed: one function is the single gate, so widening support is a one-line change.

## Stage 4a: two capacity quantities, and one owner for the record

Commit `cc72dd3`. 42 tests. No cryptography, no API change, no behaviour change.

| Name | Returns |
| --- | --- |
| `max_record_length` | the maximum serialised record length. Same arithmetic as before, honest name |
| `max_user_payload_length` | the maximum user payload, taking the record overhead as a required argument |

**Measured at 5,000 units, start unit 137, 17 metadata bytes.**

| LSB count | Record maximum | User maximum | Difference |
| ---: | ---: | ---: | ---: |
| 1 | 328 B | 210 B | 118 B |
| 3 | 1,544 B | 1,426 B | 118 B |
| 8 | 4,584 B | 4,466 B | 118 B |

The difference is the 101-byte fixed overhead plus 17 bytes of metadata, at every depth. The test asserts the relation as well as the literal 101, because two numbers can both be wrong while the gap between them is what must hold.

### The record length was written out three times

This was the real defect of the stage, found on review rather than planned for.

| Place | What it said |
| --- | --- |
| `core.py` | computed the length from the **actual** media identifier |
| `layout.py` | assumed a 36-byte identifier, because `core.py` happens to call `token_hex(16)` |
| `test_stego.py` | carried a verbatim copy of the `layout.py` expression |

Nothing linked the assumption to the fact. Measured drift: had `core.py` used `token_hex(8)`, the identifier would be 20 bytes, `core.py` would compute 85 and `layout.py` would still report 101. In the other direction capacity is **overstated**, so the check accepts a payload and encode fails afterwards. That is the exact failure this capacity work exists to prevent, reintroduced one layer down.

`packet.py` serialises the record, so it now owns `serialized_record_length`. `MEDIA_ID_SIZE` is pinned by a test against the real generator, which is the link that was missing.

### A function-level import is not a fix

`layout.py` cannot import `packet.py`, because `packet.py` already imports `ceil_unit_count` from `layout.py`. The first attempt used an import inside the function body.

That hides the dependency rather than removing it, and the layered graph is a recorded property of this design in [plan section 3.7](LOCATION-CONFIDENTIALITY-PLAN.md#37-where-encryption-lives). **A property that holds only at import time is not a property.**

The fix inverts the flow: the overhead is passed in, and `core.py` computes it, which is where sequencing belongs. `layout.py` now contains no statement about what a record looks like, so there is nothing there to drift. The dependency graph is unchanged:

```text
constants -> bits -> layout -> packet -> core
                       \-> crypto      /
                       \-> bootstrap
```

### Three instructions of mine were wrong this stage

Recorded because the review loop is what caught them, not care on my part.

| Error | Caught by |
| --- | --- |
| Claimed `packet.py` imports only `bits` and `constants` | the worker, who verified rather than trusting it |
| Left the user-facing capacity message unspecified | a question raised mid-stage |
| Asked for a test that rebuilt its own expectation | review of the diff |

The third is the stage 2a mirror-test pattern appearing in a brief that cited the stage 2a lesson. Knowing a rule and applying it are separate acts.

## Patterns worth keeping

These came out of the stages above and apply to the remaining ones.

| Pattern | Why |
| --- | --- |
| A new parameter is required, never defaulted | a default hides the decision at every call site. Callers pass the truthful value, even when it is 0 |
| An expected value is a literal, never a call to the code under test | otherwise the test detects only disagreement with itself |
| A claim of exactness is a test, not a comment | the stage 1 inverse and the stage 2a width boundaries were both checked this way |
| A reported number is tested as an exact integer | ratios hide errors of 0.004%, which is the dangerous size: too small to notice, large enough to be false |
| A function ships with a caller or with tests that exercise it | the width function was moved out of stage 1 for having neither |
| One reviewable idea per commit | stage 2 was split into 2a, 2b and 2c for carrying four unrelated changes |
| The repository runs at every stage boundary | a broken intermediate state is breakage, not deferral |
| An exception type is measured, not assumed | `InvalidTag` is not a `ValueError`, and the verdict that depends on it would have escaped its own handler |
| A shared number keeps two owners and one test | importing across a layer boundary to remove a duplicate trades a caught error for a confused design |
| A dependency is removed, not hidden | a function-level import satisfies the interpreter and falsifies the documented layering |
| A shared fact gets one owner and a test pinning it | the record length lived in three places and nothing linked the assumption to the generator |
| Judge a version 2 change against version 2 goals | decision 10 and the byte-only payload API were both first judged against version 1 criteria, and both judgements were wrong |
