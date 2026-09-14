# Orchestration Handoff

Written for the next orchestrator taking over the protocol version 2 build. It orients you and points at the records; it does not repeat them. Every number and every decision already lives in a record named below.

## 1. What you are inheriting

A working version 1 protocol on branch `yx`, plus five completed preparation stages toward version 2. Version 1 behaviour is unchanged so far, and all 42 tests pass.

| Item | State |
| --- | --- |
| Branch | `yx`, 20 commits ahead of `main` |
| Tests | 42, passing |
| Documentation | 11 files, 121 links, 0 errors from `scripts/check-docs.py` |
| Working trees | clean, submodule and superproject both pushed |
| Next action | stage 4b, briefed but not started |

## 2. Read in this order

1. [AGENTS.md](../AGENTS.md) — repository rules, conventions, and the commands.
2. [AGENT_docs/AGENT_MAP.md](AGENT_MAP.md) — paths and entry points.
3. [AGENT_docs/README.md](README.md) — the documentation index.
4. [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — **read this fully.** What each stage did, what was measured, what it taught. Its "Patterns worth keeping" table is the accumulated working rules.
5. [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — the version 2 design. Long. Sections 1, 2, 5.2, 5.3 and 14 matter most before you act.

Then, as needed:

| Question | Record |
| --- | --- |
| What does version 1 do, and why | [Masked Media Integrity Design](INTEGRITY-DESIGN.md) |
| What goes inside `user_payload` | [Payload Envelope Design](PAYLOAD-ENVELOPE-DESIGN.md) |
| Why the 64 MiB WAV cap survives | [Streaming Carrier Note](STREAMING-CARRIER-NOTE.md) |
| What assignment work remains | [Outstanding Work](OUTSTANDING-WORK.md) |
| What the assignment asks for | [specification transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) |

## 3. Environment

```sh
cd /home/yangxuan/Projects/School-Repos/external/INF2005-ACW1
./cyber_venv/bin/python -m unittest -q      # 42 tests
python3 scripts/check-docs.py               # link and anchor gate
```

The virtual environment is `./cyber_venv`. Use it for tests and notebook work. `check-docs.py` runs as a pre-commit hook; `git commit --no-verify` bypasses it deliberately.

## 4. The problem, in sixty seconds

Version 1 finds the hidden packet by scanning the carrier for a public 16-byte marker under each of the 8 LSB depths. The marker is public, so the scan is available to anybody. **Measured: 0.01 to 0.43 seconds to locate a packet with no key.** The assignment asks how the start location is protected, and version 1 has no answer.

Deleting the marker alone fails, because the receiver then cannot find the packet either. So version 2 puts an RSA-OAEP envelope at a fixed public offset, readable only by the receiver, carrying the secret start location, the LSB depth, the length, and an AES-GCM session key. The packet itself becomes pure ciphertext with a signature and nothing else.

The measurement that shaped the design: an earlier draft deleted the marker but left the payload record in the clear. Every record begins with the same five bytes, because the media identifier is always `IMG-` or `AUD-` followed by 32 hex characters behind a length byte of 36. **Sweeping for those five bytes recovered a secret start unit exactly, with no key, in 0.002 seconds** — faster than the marker it replaced. That is why the whole record is encrypted, and why encryption is an invariant rather than an option.

## 5. Why the stages are in this order

The reasoning matters more than the list, because you will need to split stages yourself.

```text
1    capacity        fixes a live version 1 defect. Useful alone. No dependencies
2a   widths          stage 1 removed a ceiling from one path; two signed
                     formats still had one. Same defect, different place
2b   reserved region the span must reach the mask, the hash preimage and the
                     fidelity count. Span passed as 0, so nothing changes yet
2c   rename          crypto.py, so stage 3's diff carries no import churn
3    envelope        new module, new cryptography, no callers yet
4a   capacity names  two quantities exist and differ by 101 bytes
4b   deletion        marker, scan, header gone. Geometry becomes an argument
4c   the switch      bootstrap carries the geometry, record encrypted
5    notebook        narrative, fixtures, verdict matrix
```

Two ordering ideas are worth understanding before you re-plan anything.

**Preparation before behaviour.** Stages 1 to 4a change no observable behaviour and keep every pre-existing test passing unmodified. That is deliberate: each is independently revertible, and a bug found later can be bisected against a stable baseline.

**The three-hop geometry move.** Encode and decode must change together, so stage 4 looked atomic. It is not, because the geometry can travel out of band for one commit:

| Step | Geometry lives | Round-trips |
| --- | --- | --- |
| now | in the file, public | yes |
| 4b | out of band, caller supplies it | yes |
| 4c | in the file, encrypted | yes |

The middle state needs no bootstrap, so the marker, the scan and the header can be deleted and reviewed on their own. It looks like a step back from the version 1 rule that the start unit is discovered and never declared, but out of band means the geometry is not in the file at all, which is stronger than either version. It is only inconvenient, and removing that inconvenience is what the bootstrap is for.

## 6. Working method

The division that produced these stages:

| Role | Does |
| --- | --- |
| Orchestrator | thinks, measures, decides, briefs, reviews, commits, documents |
| Worker | implements one stage, reports in five points, never commits |

Five points: what changed, what you measured, what you did not do, what surprised you, what you recommend next. **"What surprised you" earns its place** — an import cycle that invalidated one of my instructions surfaced there, not in the diff.

A brief that worked has these parts: goal, the defect in one line, numbered scope with exact function signatures, explicit out-of-scope list, the tests demanded, constraints, and one thing to check and report before editing.

**Guardrail semantics.** Tell the worker to stop when a test's assertion, expected value, or reason for existing must change. Do not make them stop for the mechanical consequence of a rename or a new required parameter. They over-applied it once and lost a round; over-caution is the better failure mode but it is worth calibrating.

**Commit shape, per stage, three commits:**

```text
1. code      in the submodule
2. record    in the submodule, naming the code commit's hash
3. gitlink   in the superproject
```

Two submodule commits because a commit cannot contain its own hash. Amending to insert it changes it.

## 7. Open decisions

| # | Decision | State |
| ---: | --- | --- |
| 14 | `MAX_WAV_FRAME_BYTES`, the 64 MiB cover-object cap | **deferred** pending the shelved chunked-carrier change. See [Streaming Carrier Note](STREAMING-CARRIER-NOTE.md) |

Decisions 1 to 13, 15 and 16 are settled with reasons in [plan section 11](LOCATION-CONFIDENTIALITY-PLAN.md#11-decisions). Two were reversed during the work and both reversals are kept on purpose, with the faulty reasoning stated.

## 8. Your next action: stage 4b

Scope, from [plan section 14](LOCATION-CONFIDENTIALITY-PLAN.md#14-staging): delete `START_MAGIC`, the 8-depth discovery scan, `MAX_MAGIC_CANDIDATES`, `PACKET_HEADER_FORMAT` and `PACKET_HEADER_SIZE`. `decode_carrier` gains explicit `start_unit` and `lsb_count` arguments.

Four hazards, all already recorded:

1. **The capacity helper must migrate in the same commit.** `max_record_length` subtracts `PACKET_HEADER_SIZE`, which is about to be zero. Leaving it understates capacity by 7 bytes; a caller reading it as a user payload budget overstates by 94 and fails during encode. [Plan section 5.2](LOCATION-CONFIDENTIALITY-PLAN.md#52-the-capacity-helper-must-migrate-with-the-header).
2. **A string is load-bearing for control flow.** `core.resolve_candidate` matches `"does not fit"` in a `ValueError` to produce the `Wrong Start Location` verdict. There is a comment at the raise site. That whole path is being rewritten, so decide deliberately what replaces the coupling.
3. **This stage deletes tests, not only edits them.** Bring the list of deleted protections to the human before the worker touches anything. Marker scanning, candidate ambiguity and header parsing all lose their tests, and the ambiguity branch is recorded in [INTEGRITY-DESIGN.md](INTEGRITY-DESIGN.md#decisions-and-what-was-rejected) as the only thing preventing a silent choice between two valid packets.
4. **Capacity boundary tests must still prove exactness** against the new layout, not the old one.

After 4b, [plan section 3.7](LOCATION-CONFIDENTIALITY-PLAN.md#37-where-encryption-lives) tells you where every piece of 4c goes, and [plan section 7](LOCATION-CONFIDENTIALITY-PLAN.md#7-decode) holds the decode order with a stated invariant: nothing may act on `flags` before the signature check.

One finding is already waiting for 4c. **`InvalidTag` is not a `ValueError`.** Every AES-GCM failure raises it, `decode_carrier` catches `ValueError`, and the `Cannot Decrypt` verdict exists solely for that failure. It must be caught explicitly or it escapes the verdict machinery and crashes.

## 9. Things I got wrong, so you need not

| Error | What caught it |
| --- | --- |
| Judged encrypting the record against version 1 criteria and withdrew a correct decision | a measurement, taken later |
| Claimed `packet.py` imports only `bits` and `constants` | the worker verified instead of trusting me |
| Wrote a brief citing the mirror-test lesson, asking for a mirror test | reading my own diff |
| Inserted prose into the middle of a table, orphaning three rows | reading my own output; the link checker cannot see this |
| Wrote a commit hash into a file, then amended the commit | the hash changed |
| Invented a documentation anchor from memory | `check-docs.py` |

The pattern in the first and third rows is the same: knowing a rule and applying it are separate acts. The remedy that worked was measuring before asserting, and asking the worker to check my arithmetic rather than trust it.

## 10. Boundaries

| Do not | Why |
| --- | --- |
| Merge `yx` into `main` | only on the repository owner's request. See [AGENTS.md](../AGENTS.md) |
| Touch other contributors' branches | `Alvin`, `joseph`, `ys`, `troy-fr9-fr10`, `Sitt-fr3-and-fr4` are other people's work |
| Commit submodule changes in the superproject | commit inside the submodule first, then the gitlink |
| Add records to `docs/` | that directory holds the supplied specification. Records go in `AGENT_docs/` and get listed in [README.md](README.md) |
| Let a map go stale | [AGENT_MAP.md](AGENT_MAP.md) changes in the same commit as the layout it describes |

## 11. Loose ends

**`yx` is 2 commits behind `main`.** Those two are pull request 5, which removed private workspace details from `AGENTS.md` and `AGENT_MAP.md`. `yx` does not contain them, so the same details are still present on this branch. Reconcile before any merge is proposed.

**Pull request 6 is closed.** It was a Flask graphical interface on branch `Alvin`, reviewed with changes requested on two blocking grounds: verification required the original cover file, and the start-location protection did not hold. If that work returns, the second objection is the problem this whole version 2 effort exists to solve, so point the author at the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) rather than re-deriving it.

**The notebook has two pending edits**, both recorded and neither urgent: the caller-side payload seal is deleted under decision 16, and the fidelity cell must print an exact integer beside its ratio, because the ratio reads `99.99%` with or without the span correction it exists to demonstrate.
