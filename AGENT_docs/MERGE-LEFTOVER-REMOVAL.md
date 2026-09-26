# Merge Leftover Removal

**Status:** complete.  
**Removal commit:** [120c02972786ffa5923b43876af48795d8bc10b4](https://github.com/alvinto27/INF2005-ACW1/commit/120c02972786ffa5923b43876af48795d8bc10b4)

This record explains the removal of the old `STG1` implementation, unused
services, the standalone FR1/FR5 helper, and a duplicate assignment PDF. Source
links point to the pushed review baseline `a0eb1f51a85ccf7d627380632dba00f23098b161` <https://github.com/alvinto27/INF2005-ACW1/tree/a0eb1f51a85ccf7d627380632dba00f23098b161>, before these removals.

## Removed legacy `STG1` implementation

The old `payload_protocol.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/payload_protocol.py>
created compact signed JSON records with media identifiers, timestamps, exact
cover-file hashes, nonces, and team metadata. Its web stack framed the payload
and RSA-PSS signature with the `STG1` marker, embedded it with LSB changes, and
derived a start location from a shared secret. Verification used the sender
public key and, for full hash checking, the original cover. It did not use the
version-3 receiver bootstrap or encrypt the whole record. The old frame and
shared-secret location code are visible in
`stego_web/services/steganography.py`
<https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego_web/services/steganography.py>
and `stego_web/services/start_location.py`
<https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego_web/services/start_location.py>;
the old verdict pipeline is in
`stego_web/services/verification_pipeline.py`
<https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego_web/services/verification_pipeline.py>.
The dedicated `test_payload_protocol.py`
<https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/test_payload_protocol.py>
contained 31 tests for that format.

The active application now uses the masked-media version-3 protocol through
`current_protocol.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego_web/services/current_protocol.py>
and `stego/core.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego/core.py>.
It encrypts the full record, uses a receiver-encrypted bootstrap, and verifies
the masked-media hash without the original cover. The old stack had no active
route consumer and was not interoperable with version 3. We removed it to avoid
maintaining or presenting a second, obsolete protocol.

Git history credits **Babydage** with the first FR3/FR4/FR8–FR11 draft
(`893ae74` <https://github.com/alvinto27/INF2005-ACW1/commit/893ae74145698fce0cd53a1a6515837da04051b7>) and the
legacy web UI (`5a0e9d5` <https://github.com/alvinto27/INF2005-ACW1/commit/5a0e9d537b1d92c1c1cbe169d6a5bc5312f97a02>);
**Sitt Min Naing** with FR3/FR4 changes
(`f266b19` <https://github.com/alvinto27/INF2005-ACW1/commit/f266b19e976ed4367c0117d661227899fbdf0b56>); and
**Yang Xuan** with extracting the live version-1 steganography code from the
notebook (`c64eab7` <https://github.com/alvinto27/INF2005-ACW1/commit/c64eab76987c6f9309983e9847f1ee20ff89acd0>).
The Git log uses `yx` and `Yang Xuan` as names for the same person. These credits
describe recorded contributions; they do not imply that the removed format is
part of the current protocol.

## Removed FR1/FR5 helper

`FR1_FR5.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/FR1_FR5.py>
contained standalone helpers to load a PNG as RGB, write raw payload bits into
an image array, and turn ASCII text into binary text. No active Python module
imported it. The current replacements are the strict RGB/RGBA PNG adapter in
`stego/media.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego/media.py>,
the authenticated encoder in
`stego/core.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego/core.py>,
and bit conversion in
`stego/bits.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego/bits.py>.
Git history credits **Yang Xuan** with the original image helper extraction
(`5398f2b` <https://github.com/alvinto27/INF2005-ACW1/commit/5398f2b3b6519ca2bde553a4139f478806bc8151>); later
file revisions include **Babydage**.

## Removed duplicate PDF

The root file `INF2005-ACW1-spec_v5-f2f - Copy (1).pdf` was 412,841 bytes and
byte-identical to `docs/INF2005-ACW1-spec_v5-f2f - Copy.pdf` (`cmp` returned 0).
The root duplicate had no links. The copy under `docs/` remains.

## How the files arrived

The `yx` branch was at base commit
`7831c44` <https://github.com/alvinto27/INF2005-ACW1/commit/7831c44484403ab497c9fd2a541f65eb00ccb2c4> before it
fast-forwarded PR #9 <https://github.com/alvinto27/INF2005-ACW1/pull/9>,
merged as commit `3eb38e0`
<https://github.com/alvinto27/INF2005-ACW1/commit/3eb38e0e4e548e783c6c4583fbd14cb5decbe916>. Reproduce its
changed-path list with:

```sh
git diff --name-only 7831c44 3eb38e0
```

The table below accounts for every path in that 33-file list. The removed
source files have no commits touching them in `3eb38e0..313a79f`. “Docs — Stage C”
marks material reserved for the approved documentation consolidation stage;
Stage B updates only the current-state claims needed to describe these removals.

| Path from the merge | Stage | Evidence |
| --- | --- | --- |
| `AGENTS.md` | Docs — Stage C | Current instructions; Stage B removes obsolete `STG1` and test claims. |
| `AGENT_docs/AGENT_MAP.md` | Docs — Stage C | Navigation map; Stage B removes links to deleted code and adds this record. |
| `AGENT_docs/WEB-APPLICATION-GUIDE.md#decode-request` | Docs — Stage C | Active decoder guide; routes use the current service, not the old stack. |
| `AGENT_docs/WEB-APPLICATION-GUIDE.md` | Docs — Stage C | Current web status; Stage B corrects protocol and API claims. |
| `AGENT_docs/CURRENT-PROTOCOL.md#limits-and-compatibility` | Docs — Stage C | Current compatibility guide; Stage B records that `STG1` code is removed. |
| `AGENT_docs/README.md` | Docs — Stage C | Documentation index; Stage B removes the legacy test entry and adds this record. |
| `AGENT_docs/WORK-NOT-BUILT.md` | Docs — Stage C | Assignment status record; no deleted module is an active dependency. |
| `FR1_FR5.py` | Removed | No active Python importer; the current media/core/bit APIs replace its prototype work. |
| `INF2005-ACW1-spec_v5-f2f - Copy (1).pdf` | Removed | `cmp` proved it is identical to the retained PDF under `docs/`; no links target it. |
| `README.md` | Docs — Stage C | Public setup and protocol guide; Stage B removes its claim that `STG1` code remains. |
| `payload_protocol.py` | Removed | Imported only by the old services and dedicated legacy test; no active route uses it. |
| `requirements.txt` | Kept | Flask, cryptography, NumPy, Pillow, and Werkzeug remain runtime/test dependencies. |
| `run.py` | Kept | Active localhost entry point; imports the Flask application factory. |
| `stego_web/__init__.py` | Kept | Active application factory and route registration. |
| `stego_web/exceptions.py` | Removed | Imported only by the removed legacy steganography and verification services. |
| `stego_web/models.py` | Removed | Imported only by removed legacy services. |
| `stego_web/routes.py` | Kept | Active `/encode`, `/decode`, download, and key routes use `CurrentProtocolService`. |
| `stego_web/services/__init__.py` | Kept, trimmed | No package-level import consumers exist; active code imports the explicit current-protocol module. It is now a docstring-only package marker. |
| `stego_web/services/cover_media.py` | Removed | Imports the legacy detector; no active route or current service imports it. |
| `stego_web/services/crypto_service.py` | Removed | Imports `payload_protocol` and legacy models; no active consumer. |
| `stego_web/services/current_protocol.py` | Kept | Active Flask adapter for protocol version 3. |
| `stego_web/services/encoding_pipeline.py` | Removed | Uses legacy models; no active consumer. |
| `stego_web/services/payload_builder.py` | Removed | Imports the legacy payload builder; no active consumer. |
| `stego_web/services/start_location.py` | Removed | Used by the removed legacy steganography engine only. |
| `stego_web/services/steganography.py` | Removed | Implements the old `STG1` framing and imports only removed legacy types/services. |
| `stego_web/services/verification_pipeline.py` | Removed | Uses legacy exceptions/models; no active consumer. |
| `stego_web/static/app.js` | Kept | Active encode wizard and web request controller. |
| `stego_web/static/motion.js` | Kept | Active UI motion helpers, imported by current browser scripts. |
| `stego_web/static/style.css` | Kept | Active application styles. |
| `stego_web/static/verify.js` | Kept | Active verification and payload-preview controller. |
| `stego_web/templates/index.html` | Kept | Active Flask page template; loads the retained browser assets. |
| `test_payload_protocol.py` | Removed | Tests only the removed `STG1` payload format; accounts for the 31-test count reduction. |
| `test_webapp.py` | Kept | Active Flask integration tests for protocol version 3. |

## Import proof and replacements

Before removal, repository-wide Python import searches found these dependency
edges only inside the legacy set: `payload_protocol.py` was imported by
`cover_media.py`, `crypto_service.py`, and `payload_builder.py`; `models.py` and
`exceptions.py` were imported by the old services; and `start_location.py` was
used by `steganography.py`. The old `services/__init__.py` re-exported those
classes, so it was trimmed as part of the removal. No active route used those
services or their models; `run.py`, the application factory, routes, and
`test_webapp.py` use the current protocol adapter. A post-removal AST scan of all
remaining Python files found zero import statements for `payload_protocol`,
`test_payload_protocol`, `stego_web.models`, `stego_web.exceptions`, or any of
the seven removed services. After removal, active imports continue through:

- `stego_web/routes.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego_web/routes.py>
  → `stego_web/services/current_protocol.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego_web/services/current_protocol.py>
  → `stego/core.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/stego/core.py>
  and the PNG/WAV adapters in `stego/media.py`.
- `test_webapp.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/test_webapp.py>
  and `test_stego.py` <https://github.com/alvinto27/INF2005-ACW1/blob/a0eb1f51a85ccf7d627380632dba00f23098b161/test_stego.py>
  cover the current application and protocol.

The version-3 route does not guess formats or import an `STG1` reader. It keeps
the documented version-3 verification outcomes and does not weaken the receiver
private-key requirement. See [Protocol Compatibility](CURRENT-PROTOCOL.md#limits-and-compatibility)
and [Implementation Status](WEB-APPLICATION-GUIDE.md).
