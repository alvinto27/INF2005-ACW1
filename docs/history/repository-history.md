# Repository history

Record of two larger changes to the repository: the move to PyAV for all media handling, and the removal of old code. Numbers belong to the commit of measurement. The current rules are in the [protocol guide](../protocol.md), [carrier and payload flow](../carrier-and-payload-flow.md), and [web application guide](../web-application.md). The original, longer text of this record is in Git history at commit `c412ad7`.

## Move to PyAV

PyAV became the only media library at runtime and a required dependency. Pillow is now used only by the tests and the notebook. The move did not change protocol version 3, signatures, encryption, the media hash, or the verdicts.

### Stages

All four stages were reviewed and accepted.

| Stage | Commit | Change |
| --- | --- | --- |
| S1: PNG through PyAV | [`6378bdf`](https://github.com/alvinto27/INF2005-ACW1/commit/6378bdfd99331600fd4b1fd0e7fcb4d7ddfb4106) | Replaced Pillow for reading and writing PNG carriers. Kept the strict 8-bit RGB/RGBA rules, chunk handling, error messages, and size checks. Made PyAV required and restored the route tests. |
| S2: 16-bit PNG | [`c66384d`](https://github.com/alvinto27/INF2005-ACW1/commit/c66384d33293e4a17481a7a061c36a3130173870) | Added strict 16-bit RGB/RGBA. Defined the sample order and media context. Added the 715,827,880-byte decoded-size limit, checked before decoding. |
| S3: source conversion | [`0a7f553`](https://github.com/alvinto27/INF2005-ACW1/commit/0a7f553053663a14ce47db1f31c3b8417bdbbd6c) | Converts accepted still images and audio to a temporary PNG or WAV. Strict PNG and PCM WAV skip conversion. Added the orientation, depth, channel, metadata, and size rules. |
| S4: web sources | [`38ecc23`](https://github.com/alvinto27/INF2005-ACW1/commit/38ecc23c91aa387edefc90f922171a46b05c2386) | The web encode page accepted common image and audio formats and showed conversion messages. At this stage, web verification was still PNG and WAV only, and video was refused. |

### Decisions

| Topic | Decision |
| --- | --- |
| 16-bit media context | 8-bit PNG keeps the 9-byte `>IIB` context. 16-bit PNG uses the 10-byte `>IIBB` context with depth 16. Carrier units are the low bytes of the RGB values; the matching high bytes and alpha are fixed bytes, in the order the protocol defines. |
| Image depth | Sources of up to 8 bits become 8-bit RGB/RGBA; 9 to 16 bits become 16-bit. Expansion keeps the source's top bits. Floating-point images and images over 16 bits are refused. |
| PNG size | Decoded images over 715,827,880 bytes are refused before decoding. This limit is on the decoded size, not the file size. |
| Metadata and colour | Tested RGB ICC profiles and relevant PNG colour chunks are kept. Converted files drop metadata that does not describe the converted pixels, such as `pHYs`, EXIF, and text. |
| CMYK | Refused. A CMYK ICC profile is not valid on an RGB output, and a correct colour-managed conversion needs a library other than PyAV. The profile is never silently dropped or misapplied. |
| Audio | Lossless integer PCM, FLAC, and ALAC keep the source sample width. Lossy or floating-point audio becomes 16-bit PCM at the original sample rate. All decoded samples are kept, including codec delay and padding. |
| Audio depth (2026-09-27) | Lossless depths over 16 bits other than 24 and 32 are refused, because the 16-bit fallback lost precision. Depths under 16 bits still expand to 16 without loss. |
| Audio next to video | The library's audio conversion ignores video streams when choosing the audio stream. At that stage, the web app refused files with a real video track. |
| What `Authentic` covers | The decoded, converted carrier and the signed record. Not covered: the original JPEG or MP3 bytes, source metadata, or decoder settings. Verification accepts only PNG, PCM WAV, or supported video. |

### Evidence

- **Exact output (S1).** For RGB and RGBA, full carrier-unit reads and identity rewrites (no embedded data) matched exactly, and checks with a fixed key matched. Encoded files were not compared byte for byte, because each encode uses a random nonce.
- **Orientation (S3a).** All eight EXIF orientations matched Pillow's results on the supported test files, without using PyAV's side data.
- **ICC profiles.** Reading `ICC_PROFILE` through PyAV's side data crashed the process (`SIGSEGV`). The code therefore avoids side data and uses small, bounded parsers for JPEG, WebP, and PNG to find profiles. Tested RGB ICC profiles survived from a JPEG source to the final PNG's `iCCP` chunk byte for byte.
- **EXIF.** A bounded parser reads JPEG APP1, PNG `eXIf`, WebP EXIF, and TIFF IFD0. Tested PyAV filters apply orientations 1 to 8 without unbounded metadata reads.
- **AAC samples.** An AAC test file declared 240,000 samples per channel but decoded to 240,640. The extra 640 codec-delay and padding samples were kept in the PCM output.

### Measurements (S1)

Each operation ran in three fresh processes. Times and peak memory include Python startup and native buffers. These figures come from one machine and are not guarantees.

| Input | Operation | Before: time / peak memory | After: time / peak memory |
| --- | --- | ---: | ---: |
| Banana PNG | Encode | 0.350 s / 80.5 MiB | 0.098 s / 94.7 MiB |
| Banana PNG | Verify | 0.063 s / 80.8 MiB | 0.038 s / 75.1 MiB |
| 4341 × 26191 RGBA | Encode | 5.365 s / 948.1 MiB | 3.517 s / 1,870.8 MiB |
| 4341 × 26191 RGBA | Verify | 2.106 s / 948.0 MiB | 1.351 s / 938.2 MiB |

The large encode became faster but used more peak memory. A 16-bit 7746 × 7746 RGBA image (480,004,128 bytes decoded) took a median of 5.129 s and 2,011.6 MiB to encode, and 1.843 s and 1,519.6 MiB to verify.

## Removal of old code and the `STG1` format

### Commits

| Item | Value |
| --- | --- |
| Removal commit | [`120c029`](https://github.com/alvinto27/INF2005-ACW1/commit/120c02972786ffa5923b43876af48795d8bc10b4), 2026-09-25 |
| Starting point | Branch `yx` at `7831c44` was fast-forwarded by PR #9, merged as `3eb38e0` |
| Paths checked | All 33 paths changed by that merge (see [path record](#path-record)) |
| Untouched since | No commits touched the removed files between `3eb38e0` and `313a79f` |
| Review baseline for source links | `a0eb1f51a85ccf7d627380632dba00f23098b161` |

### What was removed and why

**The `STG1` format** (`payload_protocol.py`) made compact, signed JSON records with media IDs, timestamps, exact cover-file hashes, nonces, and team metadata. The `STG1` frame embedded the payload and an RSA-PSS signature at a start location derived from a shared secret. Verification needed the sender's public key and the original cover. The format had no receiver bootstrap and no whole-record encryption, so `STG1` files could not work with version 3. No active route used the format, and keeping the code would mean maintaining, or appearing to support, a second outdated protocol.

Also removed:

| Removed | Notes |
| --- | --- |
| Seven old services: `cover_media.py`, `crypto_service.py`, `encoding_pipeline.py`, `payload_builder.py`, `start_location.py`, `steganography.py`, `verification_pipeline.py` | `steganography.py` implemented `STG1`. |
| `stego_web/models.py`, `stego_web/exceptions.py` | Used only by the old services |
| `test_payload_protocol.py` | 31 tests, covering only the old format |
| `FR1_FR5.py` | Standalone script with no importers |
| `INF2005-ACW1-spec_v5-f2f - Copy (1).pdf` | 412,841 bytes and byte-identical to the kept copy of the brief (`cmp` returned 0). No links pointed to the copy. |

`stego_web/services/__init__.py` was kept but reduced to a docstring, because no code imported from the package level any more.

### What was kept

- `run.py`, the Flask app factory, the routes, the current protocol service, the active JavaScript, CSS, and templates, `test_webapp.py`, and `requirements.txt`.
- The active chain: routes → `current_protocol.py` → `stego/core.py` and the PNG and WAV adapters.

### Checks

- Before removal, import searches showed that the old code was only used by other old code.
- After removal, a syntax-tree (AST) scan found no imports of the removed protocol, test, models, exceptions, or services.
- The version 3 routes still require the receiver's private key, do not guess formats, and do not import an `STG1` reader.

A later cleanup removed the unconnected carrier-map code and the Three.js bundle, the unused layout-estimate route, and the route test. Manual start-unit selection is still active.

### Authorship

These credits record contributions, not ownership of the current protocol behaviour.

| Contributor | Contributions |
| --- | --- |
| Babydage | First draft of FR3, FR4, and FR8 to FR11 (`893ae74`); the original web UI (`5a0e9d5`) |
| Sitt Min Naing (Git author `smn-sit10`) | FR3 and FR4 changes (`f266b19`); video frame and audio steganography (`c56e0ea`) |
| Yang Xuan (Git author `yx`) | Moved the working version 1 steganography out of the notebook (`c64eab7`); first extracted the image helper (`5398f2b`) |

### Path record

This table accounts for every path changed by PR #9. To reproduce the list, run `git diff --name-only 7831c44 3eb38e0`. Paths match the state at that time; several documentation files have since been moved or renamed.

| Path | Outcome |
| --- | --- |
| `AGENTS.md` | Updated: current instructions, no old code |
| `AGENT_docs/AGENT_MAP.md` | Updated: removed links to deleted code and recorded the cleanup |
| `AGENT_docs/WEB-APPLICATION-GUIDE.md#decode-request` | Describes the current route, not the old decoder |
| `AGENT_docs/WEB-APPLICATION-GUIDE.md` | Corrected the current protocol and API claims |
| `AGENT_docs/CURRENT-PROTOCOL.md#limits-and-compatibility` | Records the removal of `STG1`; version 3 stays separate |
| `AGENT_docs/README.md` | Removed the old test entry and recorded the cleanup |
| `AGENT_docs/WORK-NOT-BUILT.md` | Confirmed that no removed module was still needed |
| `FR1_FR5.py` | Removed: no importers; replaced by the current media, core, and bit APIs |
| `INF2005-ACW1-spec_v5-f2f - Copy (1).pdf` | Removed: identical to the kept PDF, no links |
| `README.md` | Removed the claim that `STG1` still existed |
| `payload_protocol.py` | Removed: imported only by the old services and test |
| `requirements.txt` | Kept: current dependencies |
| `run.py` | Kept: imports the current Flask factory |
| `stego_web/__init__.py` | Kept: active app factory and route registration |
| `stego_web/exceptions.py`, `stego_web/models.py` | Removed: used only by old code |
| `stego_web/routes.py` | Kept: the encode, decode, download, and key routes use the current service |
| `stego_web/services/__init__.py` | Kept, reduced to a docstring: no importers |
| `stego_web/services/cover_media.py`, `crypto_service.py`, `encoding_pipeline.py`, `payload_builder.py`, `start_location.py`, `steganography.py`, `verification_pipeline.py` | Removed: used only by old code; `steganography.py` implemented `STG1` |
| `stego_web/services/current_protocol.py` | Kept: the active version 3 adapter |
| `stego_web/static/app.js`, `motion.js`, `style.css`, `verify.js` | Kept: active browser code and styles |
| `stego_web/templates/index.html` | Kept: active Flask page |
| `test_payload_protocol.py` | Removed: tested only the old format; accounts for the 31 fewer tests |
| `test_webapp.py` | Kept: active version 3 web tests |

The documentation paths were handled in two steps. The first corrected statements about the current state. A later, approved consolidation step handled historical material.
