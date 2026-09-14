# Protocol Version 2 Stage Record

This record holds what each completed stage of the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) actually changed, what was measured, and what the stage taught. The plan holds the design and the intent. This file holds the outcome.

One entry per stage, written when the stage is committed. A stage is not finished until it has an entry here.

## Status

| Stage | Scope | Commit | State |
| ---: | --- | --- | --- |
| 1 | Carrier-derived payload capacity | `a313203` | done |
| 2a | Derived widths in both signed formats, signed `flags` | `23fce87` | done |
| 2b | Reserved region in the mask, the hash, and the fidelity count | `2d7220c` | done |
| 2c | `keys.py` renamed to `crypto.py` | `4df44c4` | done |
| 3 | `bootstrap.py` and the envelope primitives | — | next |
| 4 | Encode and decode flows, `Cannot Decrypt` | — | planned |
| 5 | Delete the header, marker and scan; migrate the capacity helper | — | planned |
| 6 | Notebook | — | planned |

Version 1 behaviour is unchanged so far. Every stage to date is preparation, and all 32 tests pass without modification to any pre-existing test body.

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
| Judge a version 2 change against version 2 goals | decision 10 and the byte-only payload API were both first judged against version 1 criteria, and both judgements were wrong |
