# Reduction Task Brief

This brief tells the implementer exactly what to change to satisfy the
[KISS Reduction Specification](REDUCTION-SPEC.md). The orchestrator wrote it after reading the
current code. It fixes every open decision, so the implementer does not have to guess a format.

Read [REDUCTION-SPEC.md](REDUCTION-SPEC.md) first, then this brief.

## Verified baseline

| Item | State |
| --- | --- |
| Branch | `yx`, clean, head `51fb9e8` |
| Tests | `cyber_venv/bin/python -m unittest -q` → 55 tests, OK, 0.45 s |
| Notebook execution | `nbconvert` is **not** installed; the notebook cannot be re-run headlessly |
| Content header in code | Does **not** exist in `stego/`. It lives only in the notebook and in documentation |

## Fixed decisions

Do not re-open these. They are settled.

| Question | Decision | Reason |
| --- | --- | --- |
| Integer width | One rule: unsigned 64-bit big-endian (`u64`) for every serialised protocol integer | Reduction spec section 1 |
| `media_id_length` prefix | Stays `u8`; `MAX_MEDIA_ID_BYTES` stays 255 | It is already fixed-width, not carrier-derived, so it is not a reduction target |
| Enumerated bytes (`version`, `media_code`, `lsb_count`) | Stay `u8` in `struct` prefixes | Same reason |
| `flags` | Removed everywhere | The wire format is already changing, so reduction spec "opportunistic cleanup" applies |
| `PROTOCOL_VERSION` | Stays `2` | No released artefact exists. The revised version-2 format simply does not read older version-2 files. Do not invent a version 3 or a new protocol stage |
| Width constant location | `PROTOCOL_FIELD_WIDTH = 8` in `stego/constants.py`; encode helper in `stego/bits.py` | Removes the `bootstrap` → `layout` import that existed only to fetch the width |
| MIME and filename | Become two more keys in the metadata string the notebook already writes. No new encoding, no replacement envelope | Reduction spec section 2 answers one question: the nested content-header format is not necessary. Deleting it is the change |
| Library view of `metadata` | Unchanged: arbitrary UTF-8 bytes | Keeps the library media-neutral and payload-agnostic |

## Target wire formats

These four formats are the whole change. Implement them exactly.

### Payload record

```text
media_id_length   u8
media_id          media_id_length bytes of UTF-8
timestamp         u64
nonce             16 bytes
media_hash        32 bytes
user_length       u64
user_payload      user_length bytes
metadata_length   u64
metadata          metadata_length bytes of UTF-8
```

Record overhead is a constant `73 + media_id_length`; with the generated 36-byte media id that is
**109 bytes**. The old rule was `93 + 2W`. Every `93 + 2W` claim in current documentation is dead.

### Bootstrap plaintext (inside RSA-OAEP)

```text
version            u8
lsb_count          u8
start_unit         u64
ciphertext_length  u64
session_key        32 bytes
aead_nonce         12 bytes
```

Total **62 bytes**, well inside the 190-byte RSA-2048 OAEP limit. `BOOTSTRAP_PREFIX_FORMAT`
becomes `">BB"`.

### GCM additional authenticated data

```text
version || lsb_count || start_unit(u64) || ciphertext_length(u64)
```

Total **18 bytes**.

### Signing input

```text
SIGNING_DOMAIN
struct.pack(">BBB", PROTOCOL_VERSION, media_code, lsb_count)
total_units(u64) || start_unit(u64) || footprint(u64) || ciphertext_length(u64)
media_context
ciphertext
```

`SIGNING_CONTEXT_PREFIX_FORMAT` becomes `">BBB"`. The version still comes from the protocol
constant, never from received data.

### Media hash preimage

```text
MEDIA_HASH_DOMAIN
struct.pack(">BB", media_code, lsb_count)
total_units(u64) || start_unit(u64) || footprint(u64) || bootstrap_span(u64)
masked carrier bytes
```

## Phase 1 — fixed-width fields

1. `stego/constants.py`: add `PROTOCOL_FIELD_WIDTH = 8`. Remove `PROTOCOL_FLAGS`. Change
   `BOOTSTRAP_PREFIX_FORMAT` to `">BB"` and `SIGNING_CONTEXT_PREFIX_FORMAT` to `">BBB"`.
2. `stego/bits.py`: add one encode helper, for example
   `encode_protocol_field(value: int, name: str) -> bytes`. It validates a non-negative integer,
   raises `ValueError` when the value does not fit in 8 bytes, and returns big-endian bytes.
   Every serialised integer goes through it, including the timestamp. Do not leave a bare
   `struct.pack(">Q", ...)` behind.
3. `stego/layout.py`: delete `carrier_field_width`. Use the helper in
   `calculate_masked_media_hash` and `encode_signing_input`. Fix the `minimum_carrier_units`
   docstring: the warning about a "width-dependent fixed point" describes a rule that no longer
   exists. Keep its signature.
4. `stego/packet.py`: drop the `total_units` parameter from `serialized_record_length`,
   `serialize_payload`, and `parse_payload`. Drop the `layout` import.
5. `stego/bootstrap.py`: drop `total_units` from `serialize_bootstrap`, `parse_bootstrap`, and
   `encode_bootstrap_aad`. Drop the `layout` import.
6. `stego/core.py`: update every call site. `minimum_record_length` no longer depends on
   `total_units`.
7. `stego/__init__.py`: keep exports in step with the code.

## Phase 2 — remove `flags`

1. Remove the `flags` field from `BootstrapFields`, `serialize_bootstrap`, `parse_bootstrap`,
   `encode_bootstrap_aad`, `_validate_bootstrap_fields`, and `encode_signing_input`.
2. Delete `require_supported_flags` and its export, and delete the flags-policy branch in
   `decode_carrier`.
3. The decode order becomes: bootstrap read, OAEP open, structural parse, bounds, signature,
   GCM open, record parse, masked-hash compare. One `Cannot Verify` cause disappears with the
   flags policy. Nothing else about verdict behaviour changes.

## Phase 3 — MIME and filename into metadata

Code in `stego/` does not change in this phase. The content header lives in the notebook.

The point of this phase is deletion. The reduction spec asked one question about the nested
content-header format: is it necessary? The answer is no, because `metadata` already carries
team-defined text in the signed and encrypted record. So the second format goes away and nothing
replaces it. Do not write a new encoder and decoder pair, a JSON object, a version byte, or any
other wrapper. A wrapper in a new syntax is the same nested envelope with a new coat.

1. `notebooks/FR1-12 Prototype.ipynb`, "Typed payloads" section: delete `pack_content` and
   `unpack_content` outright. `user_payload` carries the raw file bytes with nothing in front of
   them.
2. The declared type and the original filename become two more keys in the metadata string the
   notebook already writes, next to the existing `kind` and `flow` keys, for example
   `kind=png;flow=typed-content;mime=image/png;name=generated.png`. Reading them is a `split`,
   not a parser. Keep the existing style for the other demonstration cells; do not restyle them.
3. Keep every security behaviour the old section demonstrated, because each one exists for a
   concrete reason: MIME sniffing of the recovered bytes, the declared-versus-sniffed agreement
   table, refusal of a filename that is not a bare name, and the rule that the writing function
   derives its own safe name. A declared type stays a claim, not a fact. Negative cases N1 and N2
   must still fail for the same reasons, now reading the claim from metadata.
4. Update the other notebook call sites that the format change breaks:
   `serialize_payload(png_payload, png_layout.total_units)`, the `encode_signing_input` call that
   passes `PROTOCOL_FLAGS`, the `bootstrap_fields_from_image` helper, and the two
   `BootstrapFields(...)` constructions that pass `flags`.
5. Committed notebook outputs are wanted, but `nbconvert` is absent. Do not hand-write or edit
   outputs. Update the source cells, mark the notebook outputs as stale in your report, and raise
   it as a handoff item. If you want to prove the new notebook logic runs, copy the cells into a
   temporary script outside the repository tree, run it, then delete it.

## Phase 4 — tests

Keep the suite strong. Do not cut tests for tidiness. Remove a test only when the feature it
describes no longer exists.

| Test or helper | Action |
| --- | --- |
| `carrier_field_width` import, `test_carrier_field_width_boundaries` | Delete; the function is gone |
| `test_payload_record_widths_and_overhead` | Rewrite as one fixed 109-byte overhead assertion |
| `test_payload_record_width_transitions_add_two_length_bytes` | Delete; no transition exists |
| `test_payload_record_width_handles_length_above_uint32` | Rewrite: a declared length above `2**32` still parses as `u64` and fails on truncation |
| `test_power_of_two_carrier_record_width_round_trip` | Keep the round trip, drop the width assertion |
| `test_signing_input_width_transition` | Replace with a fixed-width assertion: the field bytes do not change with carrier size |
| `test_masked_media_hash_has_exact_approved_preimage`, `test_signing_input_has_exact_approved_bytes` | Update the approved bytes to the new formats. These are the two tests that pin the wire format; keep them exact |
| `test_bootstrap_round_trip_and_aad`, `test_bootstrap_parse_rejects_malformed_inputs` | Update for the 62-byte plaintext and 18-byte AAD |
| `test_bootstrap_authenticated_decryption_and_flags_binding`, `test_signed_flags_policy_is_reached_after_signature` | Drop the flags parts. Keep the geometry-binding and signature-order coverage that these tests also carry |
| `test_minimum_carrier_units_and_zero_capacity_boundaries` | Drop the two `carrier_field_width` assertions; recompute the boundary numbers |
| Helpers `payload_length`, `raw_bootstrap`, `bootstrap_fields_from_carrier`, `reseal_bootstrap` | Update signatures; drop `total_units` and `flags` |
| New test | A protocol field at or above `2**64` raises `ValueError` from the encode helper |

Run `cyber_venv/bin/python -m unittest -v` and report the count.

## Phase 5 — documentation

Current records must match the code. History records stay history.

| File | Action |
| --- | --- |
| `AGENT_docs/PROTOCOL-DESIGN.md` | Update the current-state sections: media-hash preimage, payload record, signing input, module dependencies, signature scope, verdicts, and decode order. Rewrite "Payload Envelope Design" so it describes the metadata convention instead of a nested content header; keep the "declared type is a claim" reasoning and the handler table. Leave the "Design history" part alone |
| `README.md` | Remove `flags` from the signature description |
| `AGENT_docs/STREAMING-CARRIER-PLAN.md` | Fix the sentence that credits the carrier-derived width function |
| `AGENT_docs/LOCATION-CONFIDENTIALITY-PLAN.md`, `AGENT_docs/PROTOCOL-V2-STAGE-RECORD.md` | Do not rewrite. Add a short superseding note near the top of each, pointing at the reduction spec and the new outcome record. Their measured numbers were true when recorded and stay as written |
| `AGENT_docs/KISS-REDUCTION-RECORD.md` | New outcome record: what changed per phase, the new formats, the recomputed numbers, the test count, and the decision list above with its reasons |
| `AGENT_docs/README.md`, `AGENT_docs/AGENT_MAP.md` | List `REDUCTION-SPEC.md`, this brief, and the new outcome record. Fix the map rows that still say "dynamic record widths", "carrier-derived capacity and field widths", and "caller-side payload-envelope design" |

Every number you write in a current document must come from running the code, not from arithmetic
in your head. Recompute at least: record overhead, minimum carrier units per `k`, the capacity
table in `PROTOCOL-DESIGN.md`, and the demonstration packet sizes.

Run `python3 scripts/check-docs.py` before every documentation commit.

## Out of scope

- Streaming or chunked carrier access, and any video carrier work.
- Any change to the bootstrap, session key, whole-record encryption, or user-selected start
  location architecture.
- Narrowing the public API beyond the symbols the phases above delete.
- New protocol stages or a protocol version bump.

## Working rules

- Repository conventions in [AGENTS.md](../AGENTS.md) apply: annotate every parameter and return
  type including private helpers, plain built-in types and `|` unions, no `typing` imports, and
  keep records in `AGENT_docs/`.
- Commit inside this repository on branch `yx`, one commit per phase, with the gitlink left to
  the superproject owner. Do not push until the orchestrator confirms.
- Report to the orchestrator after each phase, and immediately on any blocker or on any question
  that would need a decision not fixed in this brief.
