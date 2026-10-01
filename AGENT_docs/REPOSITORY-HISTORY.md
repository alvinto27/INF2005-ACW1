# Repository History

> Historical record. Current rules live in CURRENT-PROTOCOL.md, CARRIER-AND-PAYLOAD-FLOW.md, and WEB-APPLICATION-GUIDE.md. The full original text is in git history at commit c412ad7.

## PyAV media migration

Stages S1–S4 were accepted. The migration made PyAV the sole runtime media library and a required
dependency; Pillow remained test/notebook-only. It preserved protocol version 3, signatures,
encryption, media hash, and verdicts. Source conversion is encode-side only: `Authentic` covers the
decoded canonical carrier and signed record, not original JPEG/MP3 bytes, source metadata, or
decoder settings.

### Stages and commits

| Stage | Commit | Change |
| --- | --- | --- |
| S1: PyAV PNG I/O | [`6378bdf`](https://github.com/alvinto27/INF2005-ACW1/commit/6378bdfd99331600fd4b1fd0e7fcb4d7ddfb4106) | Replaced Pillow carrier decode/encode; preserved strict 8-bit RGB/RGBA rules, chunk handling, errors, size checks; required PyAV and restored route tests. |
| S2: 16-bit PNG | [`c66384d`](https://github.com/alvinto27/INF2005-ACW1/commit/c66384d33293e4a17481a7a061c36a3130173870) | Added strict 16-bit RGB/RGBA; specified sample order/context; added pre-decode 715,827,880-byte decoded-size cap. |
| S3: source conversion | [`0a7f553`](https://github.com/alvinto27/INF2005-ACW1/commit/0a7f553053663a14ce47db1f31c3b8417bdbbd6c) | Converts accepted still-image/audio sources to temporary canonical PNG/WAV, while strict PNG/PCM WAV bypass conversion. Added orientation, depth, channel, metadata, and size rules. |
| S4: web sources | [`38ecc23`](https://github.com/alvinto27/INF2005-ACW1/commit/38ecc23c91aa387edefc90f922171a46b05c2386) | Added common image/audio web encode sources, source metadata and UI conversion messages. At that stage web verification stayed PNG/WAV-only and web video was refused. |

### Decisions and measured evidence

- **16-bit context:** 8-bit PNG retains the 9-byte `>IIB` context; 16-bit PNG uses 10-byte `>IIBB`
  with depth 16. Carrier units are low bytes of numeric RGB values; fixed data includes matching
  high bytes and alpha in the protocol-defined order.
- **Image depth:** source integer depth ≤8 becomes 8-bit RGB/RGBA; depth 9–16 becomes 16-bit.
  Expansion preserves top source bits. Floating-point and >16-bit integer images are refused.
  Current detail is in Carrier and Payload Flow.
- **PNG size:** decoded images above 715,827,880 bytes are refused before decode. This is separate
  from file size.
- **Metadata and colour:** retain tested RGB ICC profiles and applicable PNG colour chunks. Converted
  snapshots drop metadata not describing canonical pixels, including pHYs, EXIF, and text. CMYK is
  refused: its ICC profile is invalid on RGB output, and correct colour-managed conversion needs a
  library beyond PyAV. Never silently drop or misapply the profile.
- **Audio:** lossless integer PCM, FLAC, and ALAC preserve supported decoded width; lossy or
  floating-point audio becomes 16-bit PCM at source rate. All decoded samples, including codec
  delay/padding, are retained. Library conversion ignores video streams while selecting audio; the
  web application refuses real video tracks. On 2026-09-27, lossless depths above 16 other than
  24/32 were refused because a 16-bit fallback lost precision; depths below 16 still expand
  losslessly.
- **Authenticity boundary:** canonical conversion is not authentication of the original compressed
  file. Verification checks canonical PNG, PCM WAV, or supported video only.

P0/S1 compared complete carrier-unit reads and identity rewrites for RGB/RGBA: output pixels matched
exactly, and fixed-key checks matched. Encoded-file bytes were not compared because each encode uses
a random nonce. S3a checked all eight EXIF orientations against Pillow's transform results;
supported fixtures matched, without PyAV SideData.

Historical S1 host measurements used three fresh processes per operation, including Python
startup/native buffers. Large image was 4341×26191 RGBA; these are not guarantees:

| Input | Operation | Before time / peak RSS | After time / peak RSS |
| --- | --- | ---: | ---: |
| Banana PNG | Encode | 0.350 s / 80.5 MiB | 0.098 s / 94.7 MiB |
| Banana PNG | Verify | 0.063 s / 80.8 MiB | 0.038 s / 75.1 MiB |
| 4341×26191 RGBA | Encode | 5.365 s / 948.1 MiB | 3.517 s / 1870.8 MiB |
| 4341×26191 RGBA | Verify | 2.106 s / 948.0 MiB | 1.351 s / 938.2 MiB |

Large encode got faster but used more peak memory. A 16-bit 7746×7746 RGBA test decoded to
480,004,128 bytes: encode median 5.129 s / 2011.6 MiB peak RSS; verify 1.843 s / 1519.6 MiB. Later
memory rules are in the current carrier guide.

A PyAV ICC_PROFILE SideData probe caused process-level SIGSEGV. Production code therefore avoids
SideData wrappers: bounded JPEG/WebP/PNG parsers detect profiles, and tested RGB ICC profiles
survived JPEG snapshot and final PNG byte-for-byte in `iCCP`. A bounded EXIF parser reads JPEG APP1,
PNG `eXIf`, WebP EXIF, and TIFF IFD0; verified PyAV filters apply orientations 1–8 without unbounded
metadata reads. An AAC probe decoded 240,640 samples/channel despite 240,000 declared; the extra 640
codec-delay/padding samples were kept in PCM.

## Removal of imported leftovers and the old `STG1` stack

**Removal commit:**
[`120c029`](https://github.com/alvinto27/INF2005-ACW1/commit/120c02972786ffa5923b43876af48795d8bc10b4),
2026-09-25. The `yx` branch at `7831c44` fast-forwarded PR #9, merged as `3eb38e0`; the removed
files had no commits touching them between `3eb38e0` and `313a79f`. The cleanup accounted for all 33
paths in that merge's changed-path list. The pushed review baseline for source links was
`a0eb1f51a85ccf7d627380632dba00f23098b161`.

### What was removed and why

The old `payload_protocol.py` made compact signed JSON records with media IDs, timestamps, exact
cover-file hashes, nonces, and team metadata. Its `STG1` frame embedded payload and RSA-PSS
signature with a shared-secret-derived start location. Verification required the sender public key
and original cover for full hash checking. It had neither the v3 receiver bootstrap nor whole-record
encryption, and was not interoperable with v3. No active route used it. Keeping it would maintain or
imply a second obsolete protocol.

Also removed: seven legacy services (`cover_media.py`, `crypto_service.py`, `encoding_pipeline.py`,
`payload_builder.py`, `start_location.py`, `steganography.py`, `verification_pipeline.py`), their
`models.py` and `exceptions.py`, the dedicated 31-test `test_payload_protocol.py`, standalone
`FR1_FR5.py`, and root duplicate `INF2005-ACW1-spec_v5-f2f - Copy (1).pdf`. The duplicate was
412,841 bytes and byte-identical to `docs/INF2005-ACW1-spec_v5-f2f.pdf` (`cmp` returned 0);
it had no links. `services/__init__.py` was kept but trimmed to a docstring because no package-level
imports remained.

The removal retained `run.py`, the Flask app factory, routes, current protocol service, active
JS/CSS/templates, `test_webapp.py`, and `requirements.txt`. The active chain is routes →
`current_protocol.py` → `stego/core.py` and PNG/WAV adapters. Before removal, import searches
confined legacy dependency edges to the removed set. A post-removal AST scan found no remaining
imports of the removed protocol, test, models, exceptions, or seven services. Active v3 routes
preserve the receiver-private-key requirement and do not guess formats or import an `STG1` reader.

- Later cleanup removed the disconnected carrier-map sources and Three.js bundle, the unavailable layout-estimate route, and its obsolete test; manual start-unit selection remains active.

### Authorship and provenance

These credits describe recorded contributions, not ownership of current protocol behavior:

- **Babydage:** first FR3/FR4/FR8–FR11 draft (`893ae74`) and legacy web UI (`5a0e9d5`).
- **Sitt Min Naing** (`smn-sit10` appears as the Git author on later work): FR3/FR4 changes
  (`f266b19`); Git author `smn-sit10` added video frame/audio steganography (`c56e0ea`).
- **Yang Xuan** (`yx` is the same person in this Git log): extracted live v1 steganography from the
  notebook (`c64eab7`) and originally extracted the image helper (`5398f2b`).

### Merge path accounting

The table accounts for the full 33-path PR #9 changed-path list; reproduce it with `git diff
--name-only 7831c44 3eb38e0`.

| Path | Disposition and evidence |
| --- | --- |
| `AGENTS.md` | Documentation updated; current instructions, no old stack. |
| `AGENT_docs/AGENT_MAP.md` | Documentation updated; removed links to deleted code and indexed cleanup. |
| `AGENT_docs/WEB-APPLICATION-GUIDE.md#decode-request` | Current route contract, not the legacy decoder. |
| `AGENT_docs/WEB-APPLICATION-GUIDE.md` | Current protocol/API claims corrected. |
| `AGENT_docs/CURRENT-PROTOCOL.md#limits-and-compatibility` | Records removal of `STG1`; v3 remains distinct. |
| `AGENT_docs/README.md` | Removed legacy test entry and indexed cleanup. |
| `AGENT_docs/WORK-NOT-BUILT.md` | No removed module is an active dependency. |
| `FR1_FR5.py` | Removed; no importer; replaced by current media/core/bit APIs. |
| `INF2005-ACW1-spec_v5-f2f - Copy (1).pdf` | Removed; identical retained PDF under `docs/`, no links. |
| `README.md` | Removed claim that `STG1` remains. |
| `payload_protocol.py` | Removed; imported only by legacy services/test. |
| `requirements.txt` | Kept; current dependencies remain. |
| `run.py` | Kept; imports current Flask factory. |
| `stego_web/__init__.py` | Kept; active factory and route registration. |
| `stego_web/exceptions.py`, `stego_web/models.py` | Removed; only legacy consumers. |
| `stego_web/routes.py` | Kept; active encode/decode/download/key routes use current service. |
| `stego_web/services/__init__.py` | Kept, trimmed to docstring; no package-level re-export consumers. |
| `stego_web/services/cover_media.py`, `crypto_service.py`, `encoding_pipeline.py`, `payload_builder.py`, `start_location.py`, `steganography.py`, `verification_pipeline.py` | Removed; legacy-only dependencies; `steganography.py` implemented `STG1`. |
| `stego_web/services/current_protocol.py` | Kept; active v3 adapter. |
| `stego_web/static/app.js`, `motion.js`, `style.css`, `verify.js` | Kept; active browser code and styles. |
| `stego_web/templates/index.html` | Kept; active Flask page. |
| `test_payload_protocol.py` | Removed; tests only old format, accounts for 31-test reduction. |
| `test_webapp.py` | Kept; active v3 Flask integration tests. |

The removal record classed documentation paths as “Docs — Stage C”: Stage B corrected current-state
claims, while the approved later consolidation was reserved for historical material. Removed source
files had no commits touching them in `3eb38e0..313a79f`.

