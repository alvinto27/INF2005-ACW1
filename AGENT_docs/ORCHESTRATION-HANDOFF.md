# Orchestration Handoff

Stage 4b is complete. This handoff prepares the next orchestrator for stage 4c. Read the linked records for the design and measured outcomes; do not treat this handoff as approval to implement another stage.

## 1. What you are inheriting

A headerless, signed protocol on branch `yx`. This is an intermediate format, **not the completed version 2 protocol**. The record is still plaintext, and its predictable prefix still reveals the packet location. `PROTOCOL_VERSION` remains 1 until stage 4c, but old version 1 files are no longer supported.

| Item | State at stage 4b completion |
| --- | --- |
| Code commit | `e9ad8e7` — remove public discovery and require explicit geometry |
| Outcome record commit | `7128021` |
| Parent gitlink commit | `367ca1b` — pins the outcome record commit |
| Tests | 46, passing |
| Notebook | 21 code cells executed in a fresh kernel, 0 error outputs |
| Local documentation gate | `scripts/check-docs.py` passes |
| Working trees | Both were clean and pushed after stage 4b; check again before acting |
| Next action | Brief stage 4c; no stage 4c implementation has started |

These hashes identify the completed stage, not the later commit containing this handoff. Do not amend a commit to insert its own hash.

The packet is now exactly:

```text
serialised record || 256-byte RSA-PSS signature || zero alignment bits
```

`decode_carrier`, `verify_png`, and `verify_wav` require three values supplied separately from the carrier:

| Argument | Meaning |
| --- | --- |
| `start_unit` | First carrier unit of the packet |
| `lsb_count` | Bits used per packet carrier unit, from 1 to 8 |
| `payload_length` | Complete serialised record length, **not** user message length |

There are no defaults. Encode returns all three in `EmbeddingLayout`. Verification needs no original cover file.

## 2. Read in this order

1. [AGENTS.md](../AGENTS.md) — repository rules and commands.
2. [Agent Navigation Map](AGENT_MAP.md) — paths and repository boundaries.
3. [Documentation index](README.md) — durable records.
4. [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — **read fully**, including the stage 4b outcome and “Patterns worth keeping”.
5. [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) — the final design. Sections 3.7, 4, 5.2, 5.3, 6, 7, 8 and 14 matter most for stage 4c. Section 6 has an ordering error; see this handoff's next-action section before implementing it.

Then, as needed:

| Question | Record |
| --- | --- |
| What the intermediate format does, and the version 1 history | [Masked Media Integrity Design](INTEGRITY-DESIGN.md) |
| What goes inside `user_payload` | [Payload Envelope Design](PAYLOAD-ENVELOPE-DESIGN.md) |
| Why the 64 MiB WAV cap survives | [Streaming Carrier Note](STREAMING-CARRIER-NOTE.md) |
| What assignment work remains | [Outstanding Work](OUTSTANDING-WORK.md) |
| What the assignment requires | [Specification transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) |

## 3. Environment and checks

Run from this repository:

```sh
./cyber_venv/bin/python -m unittest -q   # 46 tests at stage 4b
python3 scripts/check-docs.py           # local link and anchor gate
git diff --check
git status --short --branch
```

Use `./cyber_venv` for tests and notebook work. It has `ipykernel` and `jupyter_client`; at the last check it did not have `nbclient` or `nbformat`. The worker executed the notebook with a fresh kernel through `jupyter_client`, refreshed its outputs, and removed its temporary files. No dependency change was needed.

The installed submodule hook runs the **local** documentation checker. Both stage 4b commits passed it normally; no hook bypass was used.

The **parent** full documentation checker reports nine broken map links into uninitialised personal submodules. This was present before stage 4b. Do not initialise or edit unrelated repositories to hide that checkout issue. The parent gitlink-only commit passed its normal hook.

## 4. The problem that remains

Version 1 exposed a public marker. An attacker could find a packet without a key in 0.01 to 0.43 seconds. Stage 4b deletes that marker, its header, the eight-depth scan, the candidate limit, and candidate selection.

That does **not** protect the location yet. The plaintext record begins with a predictable media-identifier prefix. The measured PNG prefix sweep recovered the exact start unit without a key in 0.002 seconds. See [plan section 1](LOCATION-CONFIDENTIALITY-PLAN.md#1-the-problem).

Stage 4c must therefore do both:

```text
public offset 0, fixed 1 LSB
    RSA-OAEP bootstrap -> geometry, session key, nonce for the receiver

user-selected packet location and LSB count
    AES-GCM(whole record) || RSA-PSS signature
```

Nothing recognisable may remain at the selected location. Encrypting only `user_payload` leaves the record prefix exposed. The bootstrap itself is public and can be destroyed cheaply; that denial of service is an accepted limitation, not a hidden defect.

## 5. Why the stages are in this order

| Stage | Purpose | State |
| --- | --- | --- |
| 1 | Carrier-derived capacity | done |
| 2a | Derived field widths and signed flags byte | done |
| 2b | Reserved span in mask, hash input, and fidelity count | done; core still passes span 0 |
| 2c | Rename `keys.py` to `crypto.py` | done |
| 3 | Bootstrap format and encryption primitives | done; no encode/decode callers yet |
| 4a | Distinguish record capacity from user capacity | done |
| 4b | Remove discovery and header; supply geometry separately | done |
| 4c | Encrypt the record and carry geometry in the bootstrap | next |
| 5 | Full notebook narrative and demonstration update | planned |

Stages 1 through 4a prepared the switch. Stage 4b is the first deliberate behaviour and public API change. The geometry moves in three steps:

```text
version 1: public marker/header -> stage 4b: separate arguments -> stage 4c: encrypted bootstrap
```

The original stage 4b brief omitted the length argument. Start unit and LSB count alone cannot locate the signature or bound extraction after the header is removed. Supplying all three values avoided a temporary record-prefix reader that stage 4c would immediately delete.

The earlier handoff claimed that separate geometry was stronger than either file format. That was wrong: it ignored the plaintext prefix. The intermediate stage separates reviewable changes; it does not establish confidentiality.

## 6. Working method

The owner clarified the role boundary during stage 4b:

| Role | Does |
| --- | --- |
| Orchestrator | Thinks, measures, decides, briefs, reviews, and checks; approves commits |
| Worker | Makes code and documentation changes, executes the notebook, and performs approved commits and pushes |

**Do not take over the worker's edits.** The orchestrator changes files only when the owner explicitly requests that exception, as they did for this handoff update. That exception does not change the default split.

Require a five-point report: what changed, what was measured, what was not done, what surprised the worker, and what they recommend next. A completion report is a claim to review, not proof that the brief was met.

A useful implementation brief has a goal, the defect in one line, numbered scope with exact signatures, an explicit out-of-scope list, demanded tests, constraints, and one check to report before editing.

**Test-change guardrail.** Identify changes to assertions, expected verdicts, and protections before implementation. Bring deleted protections or changed meanings to the human. A rename, new required argument, or mechanical packet-offset change alone does not require a stop. Unexpected changes to a test's purpose do.

**Per-stage commit shape:**

```text
1. code and current docs/map   in the submodule
2. outcome record             in the submodule, naming commit 1
3. updated gitlink            in the superproject
```

Do not include the outcome record in commit 1 with a guessed hash. Push the child revision before publishing the parent pointer. Use normal hooks; report any failure instead of bypassing it silently.

## 7. What stage 4b established

The [stage record](PROTOCOL-V2-STAGE-RECORD.md#stage-4b-headerless-packet-and-explicit-geometry) holds the exact deletions and measurements. Important results for the next review:

- 24 round-trip cases cover eight LSB depths and three start locations. PNG and multi-byte WAV tests still pass.
- Invalid numeric geometry returns `Cannot Verify`. Valid numeric geometry whose footprint exceeds the carrier returns `Wrong Start Location`, before any bit read. The tests include a declared length of `1 << 100`.
- `Payload Missing` is not emitted in this intermediate stage. Without recognition, the decoder cannot distinguish absence from damaged data or wrong supplied geometry.
- There is no candidate list or ambiguity branch. Checking one supplied layout does not prove the carrier contains only one packet.
- The raw-packet test pins a 108-byte record, a 256-byte signature, 364 packet bytes, and a 971-unit footprint with one pad bit at three LSBs.
- Removing the header recovered **23 bytes**, not seven. Stage 4c's 16-byte tag cost is still to come. User-budget tests use real encode/decode calls at the maximum and reject maximum plus one without changing the source.

The first worker submission passed 40 migrated tests but omitted the required new regression tests. Review caught that gap. The final suite has 46 tests. Do not accept a green count without checking the demanded cases.

## 8. Your next action: brief stage 4c

Use [plan section 3.7](LOCATION-CONFIDENTIALITY-PLAN.md#37-where-encryption-lives) for ownership: primitives in `crypto.py`, bootstrap fields and additional authenticated data in `bootstrap.py`, sequencing and verdicts in `core.py`. Keep imports one-way.

Before authorising edits, settle the public signatures and the test/verdict migration. Receiver-key verification replaces the temporary geometry arguments. `PROTOCOL_VERSION` becomes 2, so tests that pin exact encoded bytes also need deliberate updates. Bootstrap flags currently have an early-rejection test whose meaning must change.

### Hazards to resolve in the brief

| Hazard | Required action |
| --- | --- |
| The plan lists record encryption before computing the hash stored inside that record | Derive the layout, compute the masked media hash, build and serialise the record, then encrypt it. Correct plan section 6 before following it |
| `parse_bootstrap` rejects nonzero flags immediately | Separate structural parsing from flags policy. Do not interpret or reject flags as policy before signature verification |
| `encode_signing_input` currently signs the constant `PROTOCOL_FLAGS` | Trace the recovered flags byte into the signing input as data. Binding a constant instead would not authenticate a substituted value. Keep the protocol **version** sourced from the constant, as designed |
| AES-GCM raises `InvalidTag`, not `ValueError` | Catch it explicitly and return `Cannot Decrypt`, with `valid=False` and no payload |
| The bootstrap span is runtime data | Derive it from the envelope size after loading the receiver key; RSA-2048 uses 2,048 units. Do not add a fixed span constant |
| Record bytes, ciphertext bytes, and user bytes are different quantities | Account for the 16-byte tag once. Keep capacity names honest, preserve exact boundary tests, and add the planned user-facing capacity refusal |
| Received geometry is untrusted until the signature passes | Bound the start, LSB count, length, and disjoint bootstrap/packet regions before bit reads or allocation |
| The current narrow layout-error catch assumes span 0 | Revisit its verdict routing when a real span is introduced. Do not restore matching error-message strings |

The receiver order must be:

```text
bootstrap read/open -> structural and carrier bounds -> packet extraction
-> RSA-PSS verification -> flags policy and AES-GCM decryption
-> record parse -> masked hash comparison
```

Use [plan sections 7 and 8](LOCATION-CONFIDENTIALITY-PLAN.md#7-decode) for the full verdict contract. `Payload Missing` returns as a receiver-key recognition result, not proof that a file is empty. A wrong receiver key and an absent bootstrap cannot be distinguished. Wrong session-key or nonce substitution with otherwise correct geometry must reach `Cannot Decrypt` only after the signature passes.

Demand the full verdict matrix, modified-bootstrap field tests, signature-before-flags tests, capacity boundaries, reserved-region refusal, and exact preserved-bit counts. Keep the repository runnable as required API arguments change; the full notebook rewrite remains stage 5.

## 9. Open decisions and loose ends

- **WAV cover cap:** decision 14 remains deferred. `MAX_WAV_FRAME_BYTES` is 64 MiB; the chunked-carrier alternative is shelved in the [Streaming Carrier Note](STREAMING-CARRIER-NOTE.md). Do not expand stage 4c into that change.
- **Notebook:** the caller-side payload seal remains. Decision 16 removes it for version 2; the content-type header stays caller-side. The fidelity cell still needs an exact integer beside its ratio in stage 5.
- **Fixture check:** the current demonstration WAV cover has 32,000 samples. The 4,000-sample tone is a typed payload embedded in PNG, not that cover. Older plan text conflates them. Check which object needs capacity before lengthening a fixture, and recompute minimum-carrier examples from the current record overhead.
- **Child branch divergence:** at the stage 4b record commit, child `main` contained `96b055f` and merge `9efdd43` that were absent from `yx`. These removed private workspace details under pull request 5. Reconcile before proposing a merge, not by merging automatically.
- **Earlier GUI review:** verification must not require the original cover. Start-location protection must satisfy the new design, not merely hide a public marker. If that work returns, point its author at the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md).

## 10. Boundaries

| Do not | Why |
| --- | --- |
| Merge child `yx` into child `main` | Only on the repository owner's request |
| Touch `Alvin`, `joseph`, `ys`, `troy-fr9-fr10`, or `Sitt-fr3-and-fr4` | These are other contributors' branches |
| Commit coursework source in the parent repository | Commit inside the submodule first; the parent stores only its pinned revision |
| Add project records to `docs/` | That directory holds the supplied specification; records belong in `AGENT_docs/` and its index |
| Leave a map or index stale | Update it in the same commit as the change it describes; run the local documentation checker |
| Leave notebook kernels or temporary files behind | Shut down the kernel and clean generated files, including on failure |
| Implement stage 4c merely because this handoff names it | First prepare and review its scope, changed protections, and tests |
