# Orchestration Handoff

Protocol version 2 is complete. This handoff tells the next orchestrator what exists, how this repository is worked, and where the boundaries are.

**There is no next stage.** Stage 6b finished the plan, and stage 6c was cancelled by the owner. Do not treat any item in this file as authorisation to build something. Every new piece of work needs a brief and the owner's approval.

## 1. What you are inheriting

A complete, signed, location-confidential protocol on branch `yx`, published to its remote.

| Item | State at this handoff |
| --- | --- |
| Child branch | `yx`, tip `e920382`, pushed |
| Parent branch | `main`, tip `64ecf47`, pushed, gitlink pins `e920382` |
| Last protocol stage | 6b, reject unusable carriers |
| Tests | 55, passing |
| Notebook | 51 cells, 20 output-bearing, fresh kernel, 0 error outputs |
| Local documentation gate | `scripts/check-docs.py` reports no errors |
| Working trees | Both clean at this handoff; check again before you act |

Hashes name the state this handoff describes, not the commit that contains it. Never amend a commit to insert its own hash.

### The shape of the protocol

```text
unit 0, fixed 1 LSB, reserved span
    RSA-OAEP envelope -> geometry, session key, nonce, for the receiver only

sender-selected start unit and LSB count
    AES-256-GCM(complete record) || 256-byte RSA-PSS signature || zero pad bits
```

Nothing recognisable sits at the selected location. The reserved span is observable and can be destroyed cheaply; that denial of service is an accepted limitation, not a hidden defect.

### The API contract you must not quietly break

| Call | Keys it requires |
| --- | --- |
| `encode_carrier`, `encode_png`, `encode_wav` | sender signing private key **and** receiver public key |
| `decode_carrier`, `verify_png`, `verify_wav` | sender public key **and** receiver private key |

Verification takes **no geometry**. The receiver recovers the start unit, LSB count and lengths from the bootstrap. There is no public, third-party verification mode, and that is a deliberate trade recorded in [plan section 2](LOCATION-CONFIDENTIALITY-PLAN.md#2-the-trade-that-cannot-be-avoided).

Encoding refuses a carrier that cannot hold the complete protocol object. A reported user capacity of `0` now means one thing only: everything mandatory fits, and zero user bytes remain.

Seven verdicts exist: `Authentic`, `Tampered`, `Signature Invalid`, `Payload Missing`, `Wrong Start Location`, `Cannot Decrypt`, `Cannot Verify`. See [Verification verdicts](PROTOCOL-DESIGN.md#verification-verdicts).

## 2. Read in this order

1. [AGENTS.md](../AGENTS.md) — repository rules and commands.
2. [Agent Navigation Map](AGENT_MAP.md) — paths and repository boundaries.
3. [Documentation index](README.md) — the records and how they are grouped.
4. [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md) — read fully, and read [Patterns worth keeping](PROTOCOL-V2-STAGE-RECORD.md#patterns-worth-keeping) twice. It is the cheapest thing in this repository.

Then, as needed:

| Question | Record |
| --- | --- |
| How does it work now, and what came before | [Protocol Design](PROTOCOL-DESIGN.md) |
| Why is it built this way, and what was rejected | [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md) |
| What is not built, owned elsewhere, undecided, or unassembled | [Work Not Built](WORK-NOT-BUILT.md) |
| Why the WAV cover cap exists, and the deferred work that removes it | [Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md) |
| What does the assignment require | [Specification transcription](../docs/INF2005-ACW1-spec_v5-f2f.md) |

## 3. Environment and checks

```sh
./cyber_venv/bin/python -m unittest -q   # 55 tests at this handoff
python3 scripts/check-docs.py            # local link and anchor gate
git diff --check
git status --short --branch
```

Use `./cyber_venv`. It has `ipykernel` and `jupyter_client`; at the last check it had neither `nbclient` nor `nbformat`. The notebook is executed through `jupyter_client` with a fresh kernel, and the kernel and temporary files are cleaned up afterwards, including on failure. No dependency change has been needed.

The installed hook runs the **local** checker. The **parent** checker reports broken map links into uninitialised personal submodules. That predates this work. Do not initialise or edit unrelated repositories to hide a checkout condition.

The local checker proves that links and anchors resolve. It cannot prove that a description is still true. That judgement is yours.

## 4. Working method

| Role | Does |
| --- | --- |
| Orchestrator | Thinks, measures, decides, briefs, reviews, checks, approves commits and pushes |
| Worker | Changes code and documentation, executes the notebook, performs approved commits |

Do not take over the worker's edits. The orchestrator changes files only when the owner asks for that exception, as they did for this handoff.

A brief that works has: a goal, the defect in one line, numbered scope with exact signatures, what is out of scope, the tests demanded, and one pre-edit check to report before any file is touched. That last item has caught a wrong assumption at almost no cost, repeatedly.

Require a five-point report: what changed, what was measured, what was not done, what surprised the worker, what they recommend next. A report is a claim to review, not proof the brief was met. A green test count is not proof the demanded cases exist.

### Guardrails that earned their place

- **Protections.** Identify changed assertions, verdicts and protections before implementation. A deleted protection or a changed test meaning goes to the owner. A rename or a new required argument does not.
- **A test must fail on the old code.** A bare `assertRaises` can pass before a fix and keep passing after the fix is removed. Assert the message.
- **Move verbatim, or edit deliberately, never both in one commit.** If a move and a reword share a commit, nobody can tell which is which.
- **Records are logs, not descriptions of today.** Stage entries are never retro-fitted. Correct a present-state summary; leave history alone.
- **Prose rots where numbers are watched.** Re-executing a notebook refreshes outputs, not claims. A sentence that stays plausible while its subject changes is the hardest defect in this repository to see, and it has occurred more than once.

### Commit shape

```text
1. code, current records, map        in the submodule
2. outcome record naming commit 1    in the submodule
3. updated gitlink                   in the superproject
```

Push the child before the parent, so the parent's gitlink never points at a revision nobody can fetch. Never amend or reset a commit that something already points at; fix forward. Use normal hooks and report a failure instead of bypassing it.

## 5. Open items

None of these is authorised work. Each needs its own brief.

- **The WAV cover cap and chunked carriers — the likely next piece of work.** `MAX_WAV_FRAME_BYTES` is 64 MiB and caps the cover, not the payload. Decision 14 is **deferred, not shelved**, and the owner intends to revisit it now that version 2 is complete. The cap and the chunked-carrier change are one topic, not two: the cap exists only because carriers are loaded whole into memory. The [Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md) owns that analysis and the order of work; [plan section 12](LOCATION-CONFIDENTIALITY-PLAN.md#12-open-decisions) holds the decision entry.
- **Child branch divergence.** Child `main` holds `96b055f` and merge `9efdd43`, absent from `yx`. Reconcile manually if the owner asks for a merge. Never merge automatically.
- **Assignment work owned elsewhere.** GUI, FR13 innovation statement, the live A-to-B transfer, individual explanations, and the submission package. All are listed in [Work Not Built](WORK-NOT-BUILT.md).
- **If the GUI work returns**, three things it must respect: verification needs the receiver private key, verification collects no geometry, and the start-unit control is bounded below by the receiver's bootstrap span.

## 6. Boundaries

| Do not | Why |
| --- | --- |
| Merge child `yx` into child `main` | Only on the owner's request, and only after manual reconciliation |
| Touch `Alvin`, `joseph`, `ys`, `troy-fr9-fr10`, or `Sitt-fr3-and-fr4` | Other contributors' branches |
| Commit coursework source in the parent | Commit inside the submodule; the parent stores only the pinned revision |
| Add records to `docs/` | That holds the supplied specification; records belong in `AGENT_docs/` and its index |
| Leave a map or index stale | Update it in the commit that changes what it describes |
| Leave a kernel or temporary file behind | Shut the kernel down and clean up, including on failure |
| Start work because this file names it | Section 5 is a list of open questions, not a backlog with permission attached |
