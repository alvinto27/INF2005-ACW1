# Reliability Audit — 2026-09-28

## Scope and architecture

The active application is Flask plus two server-rendered HTML pages with plain
JavaScript controllers, not a React/Vue SPA. Routes are `GET /`, `GET /verify`,
`POST /encode`, `POST /decode`, `POST /keys/generate`, `GET /download/<id>.<ext>`,
and `GET /payload/<id>`. `POST /layout/estimate` belongs to a disconnected map
feature and now returns a controlled 503. The active flow is: select carrier and
payload, prepare sender and receiver keys, choose geometry, encode/download,
then open the separate verify page, upload the result and keys, and inspect or
download an authenticated payload. PyAV, cryptography, and the filesystem do
the expensive work. Server files live under `instance/work`,
`instance/stego-outputs`, and `instance/recovered-payloads` by default. There
is no application database, browser local/session storage, account system, or
remote API. The optional GSAP CDN affects motion only; the workflows function
without it. This is a trusted-localhost application, not a public deployment.

## Significant issues found and addressed

| Severity | Location and reproduction | Cause | Fix |
| --- | --- | --- | --- |
| P1 | `app.js` and `verify.js`: stall or disconnect `/encode`, `/keys/generate`, or `/decode`; malformed JSON also surfaced parser/TypeError text. | Requests interpreted responses independently; encode and key generation had no timeout, and success fields were assumed. | Shared `api.js` handles status classes, network loss, timeout, and malformed bodies; successful encode/verify/key responses are validated before presentation. Controls are restored after failure and POST is never retried automatically. |
| P1 | `app.js`: change inputs while a long encode is in flight, or return HTTP 200 with an incomplete result. | Only the submit button was disabled; response rendering could partly mutate the success view before failing. | Snapshot the multipart body, temporarily lock form controls, validate response shape and same-origin download URL first, then present success. Failure keeps the user on the editable step. |
| P2 | `routes.py`: inject an `OSError` after a partial output write. | An I/O exception could be returned as a 400 with the raw exception text or leave an output file. | Log the failure, remove partial output, and return a generic 500 without the path. Sidecar failures likewise return a non-disclosing message and remove the recovered payload. |
| P2 | Multipart requests: send two files or duplicate required form fields. | Werkzeug's first-value lookup silently selected one value. | Reject ambiguous uploads and repeated required fields with 400. |
| P2 | Verify an authenticated text payload larger than 1 MiB. | The browser read the full text into memory for preview. | Keep it downloadable but disable inline preview above 1 MiB; bounded preview reads have a 30-second timeout and an explicit retry. Native media preview errors fall back to the download link. |
| P2 | Call `/layout/estimate` directly. | The inactive route referenced an unimplemented service and had an invalid helper call. | Return an explicit 503 directing users to the working manual start-unit control. The map itself remains unfinished. |
| P3 | Re-select cover files, generate keys repeatedly, or reset the wizard. | Removed `blob:` previews/download links retained object URLs, and the cover preview was not reset. | Revoke replaced/reset URLs and clear the preview on reset. |

The UI layout, protocol version 3, verdict meanings, and encode/decode request
fields were not changed. Errors use text nodes, not HTML interpolation.

## Test strategy and matrix

`A` = committed automated test, `E` = exploratory browser fault injection on
this workstation, `N/A` = the application has no such subsystem. The local
Playwright scripts used for exploratory checks are under ignored
`instance/ui-review/`; they are **not** part of the portable test suite.

| Area | Normal | Invalid | Boundary | Network failure | Server failure | Recovery |
| --- | --- | --- | --- | --- | --- | --- |
| Forms | A/E encode/verify | A empty, duplicate, numeric | A LSB, key and text-preview limits | E shared request boundary | E 500/503 | E retry without losing fields |
| APIs | A round trip | A malformed inputs and verdicts | A upload/disk limits | A/E connection loss and timeout | A/E 500–504 | E 400/429/503 then retry |
| Uploads | A PNG/WAV/MKV | A empty, corrupt, wrong type, duplicate | A 64 KiB key boundary, carrier limits | E disconnected request | A injected output I/O error | A no partial output; E retry |
| Navigation | E both pages, direct `/verify` | A unknown route gives 404 | E malformed query and reload | N/A | N/A | E reload/navigate |
| Async operations | E keys, encode, verify | E malformed/empty JSON | A/E text preview and timeouts | A/E abort/connection loss | E 4xx/5xx matrix | E button re-enabled, duplicate submit blocked |
| Stored state | N/A browser storage absent | N/A | N/A | N/A | A staged-file cleanup | A no partial publication on tested errors |

The committed tests are `test_webapp.py` and the dependency-free Node test
`node --test scripts/test-api-js.cjs`; CI runs both. The Python suite also covers the
core protocol and video backends. On this workstation, an optional Playwright
run exercised the full encode → verify round trip at 1440, 1024, 768, 390, and
320 pixels with zero axe-core WCAG 2/2.1 AA violations, plus HTTP
400/401/403/404/409/413/422/429/500/502/503/504, empty and malformed JSON,
network abort, timeout, malformed successful encode response, retry, and rapid
duplicate verify submission. The browser reported no uncaught page exceptions
in those runs. The optional CDN was blocked during the round trip. The console
showed expected failed-resource messages for deliberately injected HTTP errors,
network aborts, and the blocked CDN, but no uncaught application exceptions.

## Remaining risks and reliability assessment

- Client abort or timeout does not cancel a Flask/PyAV operation already running.
  A retry can create another output; the API has no idempotency key or job
  cancellation. Do not automatically retry encode or decode POSTs. This is the
  main remaining P1 reliability limitation for very large media.
- The default upload limit is disk-based, not a fixed size. A public deployment
  needs an explicit `MAX_CONTENT_LENGTH`, access control, request/job limits,
  quotas, and a production server. Huge but valid media can take hours.
- Power loss or `SIGKILL` can leave staging directories; successful output and
  recovered plaintext have no expiry or garbage collector. Host-level cleanup
  and access control remain necessary.
- The Three.js map is still disconnected. The 503 response prevents a broken
  endpoint from pretending to work; it does not implement the map.
- No portable Playwright dependency or CI browser job was added. Browser fault
  injection was exploratory on this workstation, not a cross-browser guarantee.
  Disk exhaustion, actual multi-hour video, and OS-level failures were simulated
  or tested at small scale rather than reproduced at full size.

Critical crash paths remaining: none reproduced in the tested active flows;
unproven under OS termination and extreme media. Unhandled exceptions or
promise rejections remaining: none observed in the browser runs; unexpected
server exceptions still become logged JSON 500 responses. Major unrecoverable
states remaining: none reproduced in the UI; a timed-out server job may still
run and leave an output that requires host cleanup. Known edge cases remaining:
the items above, especially no server-side cancellation or idempotency.
