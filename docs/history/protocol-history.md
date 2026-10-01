# Protocol History

> Historical record. Current rules are in [Protocol](../protocol.md), [Carrier and Payload Flow](../carrier-and-payload-flow.md), and [Web Application](../web-application.md). The full original text is in git history at commit c412ad7.

## Version 1: integrity protocol

Version 1 began in a 5,079-line codebase with four copies of the protocol, three conflicting design
documents, a trust store, key-management and first-use key-pinning schemes, and three-region
hashing. The rebuild left 1,485 lines (1,164 package, 321 tests); each cut was checked against the
brief and remaining dependencies.

### Design choices and rejected alternatives

| Decision | Reason | Rejected alternative or later outcome |
| --- | --- | --- |
| Hash the carrier with the packet region's low bits cleared | One rule for sender and receiver; no special edges | Three-region hashing, whose boundaries caused early bugs |
| Discover `start_unit` rather than declare it in v1 | No attacker-controlled location field; relocation broke the signature | A start-location header; discovery was replaced by the encrypted bootstrap in v2 |
| Sign geometry as well as payload | Moving an otherwise identical packet must fail | Signing payload bytes alone |
| Keep per-bit Python loops | Readable and measured adequate: 1 MB payload encoded in 2.9 s | Vectorised packing that was faster but harder to read |
| Keep the 64-candidate bound and ambiguity branch while scanning | Bounded work; never silently choose among two valid packets | Removing the checks while discovery still existed; both were removed with discovery in v2 |
| One `VerificationError` carrying a verdict | Three exception classes only routed three strings | Three separate exception types |
| Keep payloads as bytes; caller chooses confidentiality | Library stays focused on integrity and avoids imposing encryption | Built-in encryption; withdrawn in v2 because the record itself leaked location structure |
| Keep notebook helpers in the notebook | A demo does not justify display code in the library | Moving presentation code into `stego/` |
| Fix PSS salt at 32 bytes | Predictable SHA-256-sized salt and cross-library verification | `PSS.MAX_LENGTH` (222 bytes for RSA-2048); signatures from the two settings are incompatible |

The fixed PSS salt was not justified at the time of the rewrite; its interoperability rationale was
written later. RFC 8017 gives the hash length as the typical salt, and the strength difference
between 32 and 222 bytes was not meaningful here. The upstream README also incorrectly described
RSA-PSS as PKCS#1 v1.5, a warning that docs can drift from code.

The code was split from one file into eight modules with one-way imports: constants → bits → layout
→ packet → core; crypto and media depend only on constants/bits; core alone joins protocol,
cryptography, and file formats. The new package passed the full suite before the old file was
deleted. This kept a module from importing something that imported it back. Validation cleanup also
followed the changed trust boundary: checks for `True` where numbers were expected, a self-generated
key length cap, duplicate payload ceilings, and reparsing unchanged packet bytes were removed one at
a time after review. A public key was no longer untrusted JSON from a stranger; defensive code that
guarded the old boundary was not automatically useful.

### Hashing, file fidelity, and capacity findings

The old hash split data before, after, and inside the packet. The replacement copies the carrier
logically, clears the low bits where the packet sits, then hashes the remainder. This simplified the
rule but created a limit: with `k=8` and a packet filling the carrier, the hash watches no carrier
bits. `preserved_bits` was retained so users could see that loss rather than assume complete
integrity.

A test that only checked round-trip bytes missed a serious WAV defect. `WavPcmData` accepted widths
of 1–4 bytes, but both tests used 8-bit samples. For wider samples the embedder modified the low bit
of every byte. At `k=1`, measured maximum sample changes were:

| Sample width | Measured change | Correct maximum |
| --- | ---: | ---: |
| 8-bit | 1 | 1 |
| 16-bit | 257 | 1 |
| 24-bit | 65,793 | 1 |
| 32-bit | 16,843,009 | 1 |

The error was the sum of byte place values, not one sample-unit change. Noise reached -42 dBFS at
`k=1` for every depth; sample-wise embedding would be -90 dBFS at 16-bit and -138 dBFS at 24-bit. A
16-bit output still verified `Authentic`, showing that “bytes round-trip” did not prove
preservation. The repair added a per-width bound, `max(abs(original - stego)) <= (1 << k) - 1`.

Capacity tests must use the actual raw cover-object size, not its compressed PNG size.
`samples/Banana.png` has 6,021,120 raw pixel bytes but a 1,673,875-byte PNG file; the compressed
file fits inside itself at `k=3`, so using file size would make a false capacity demonstration.

Embedding also changes PNG compression. On Banana, cover size was 1,673,875 bytes; stego sizes were
1,675,090 (`k=1`, +1,215), 1,675,035 (`k=3`, +1,160), and 1,674,414 (`k=8`, +539). A roughly 1 KiB
increase is a genuine detection clue, though re-saving with different settings also changes file
size.

### Lessons and limitations

- Three validations silently stopped working during the module split while tests still passed. A broad
  `(TypeError, ValueError)` catch hid both rejection and a wrongly called function; tests were
  tightened to demand the specific failure.
- Advertised parameter space matters: 8-bit-only WAV fixtures hid the multi-byte defect. Check every
  promised width, not merely whether a result verifies.
- Most defensive checks guarded a trust boundary that no longer existed. Checks were removed one at a
  time; anything doubtful was kept.
- Deleting dead code leaves imports and constants behind. A second sweep found `secrets`, `datetime`,
  `timezone`, and `MEDIA_PREFIXES` unused in `packet.py`.
- Notebook tools kept repairing the committed notebook because `nbformat 4.5` requires cell IDs.
  Fixing the invalid file was correct; banning outputs was unrelated tidiness and was reverted.
- `encode_png` did not return media context, so the notebook rebuilt it. This was accepted over
  changing the public return value for a demo convenience.
- The v1 “furthest failure wins” verdict priority was a reader-facing judgment, not a security
  property. Discovery removal made that selection obsolete.
- Bit loops were readable and adequate at 2.9 s/MB, but will not scale indefinitely; a future speed
  change should be based on measurement.
- Tests and notebook have different roles: tests prove edge cases; the notebook shows the flow.
  Keeping notebook assertions out avoids a second, drifting test suite.
- V1 intentionally did not encrypt. The caller could encrypt bytes, keeping cryptographic policy
  outside the library. V2 later changed this because caller-side protection could not hide structure
  constructed inside `core.py`.

## Version 2: location confidentiality plan and stage outcomes

The plan addressed a concrete v1 leak: an attacker could scan the public 16-byte marker across LSB
depths and recover the packet location in 0.01–0.43 seconds. Deleting only the marker was
insufficient. A plaintext record began with a predictable 36-byte ID (`IMG-` plus 32 hex
characters), serialized behind a one-byte length. At secret unit 3,412,907 in a 6,021,120-unit
carrier, sweeping the eight 1-LSB bit offsets for `24 'IMG-'` recovered the exact location in
**0.002 s**. The conclusion was to encrypt the complete record, not just remove the marker.

### Security goal and accepted trade-offs

The receiver should recover user-chosen start, length, and LSB depth; outsiders should not receive
those fields in plaintext. The fixed RSA-OAEP bootstrap at unit 0 carries location, packet length,
AES session key, and nonce; the packet at the user-selected location contains encrypted record plus
RSA-PSS signature. The bootstrap span is derived from serialized envelope length (2,048 units for
the RSA-2048 envelope), not conceptually from key length, even though those byte counts coincide for
RSA-OAEP.

**The trade that cannot be avoided: no third-party verification.** V1 allowed anyone with the sender
public key to find the packet and verify it. V2 requires the receiver private key to discover the
packet. A file cannot distinguish an honest third party from an attacker: location is either public
to both or secret to one keyholder. Making the hash location-independent by masking the whole
carrier would not solve signature discovery and would reduce covered bits on a 1280×1568 carrier by
12.5% at `k=1`, 37.5% at `k=3`, and 100% at `k=8`. The assignment makes Party B both receiver and
verifier, so receiver-gated verification was accepted. Public-key-only verification was rejected;
two verification modes would be two protocols. On the sample 1280×1568 carrier, the observed
masked-bit coverage versus globally masking every unit was:

| LSB count | Existing coverage | Global-mask coverage | Loss |
| ---: | ---: | ---: | ---: |
| 1 | 48,166,460 bits | 42,147,840 bits | 12.5% |
| 3 | 48,161,460 bits | 30,105,600 bits | 37.5% |
| 8 | 48,148,960 bits | 0 bits | 100% |

The bootstrap is fixed, public, and unauthenticated. An attacker can overwrite it and destroy
extraction without triggering a tamper signal, because those bits must be masked from the media
hash. This denial of service was accepted as unavoidable while the bootstrap remains public.
Detection is still trivial: a random block at fixed offset is not hidden, and statistical
steganalysis can reveal approximate embedded regions. The claim is only that protocol structure and
locator metadata do not disclose the exact packet location without the receiver key.

### Binding and verdict reasoning

Every bootstrap field is writable by an attacker. Version, flags (then present), LSB count, start,
and ciphertext length were signed; geometry was also GCM additional authenticated data. The sender's
protocol-version constant, not the received bootstrap version, had to enter the signing preimage to
prevent downgrade. AES key and nonce were not signed: substituting either could only make the GCM
tag fail, not create a different accepted plaintext. The tag binds plaintext to the key and nonce; a
different valid plaintext under unchanged signed ciphertext would require defeating the 128-bit tag.
Decision 12's proposed signed key/nonce commitment was reviewed and rejected, then reaffirmed; no
session commitment was added, and stage 6c was cancelled.

`flags` had to be signed while it existed. Otherwise an attacker could write a valid receiver
bootstrap with the encryption flag cleared, keep signed bytes in place, and cause ciphertext to be
returned as plaintext under `Authentic`. Signing the interpretation prevents that class of
confusion. Flags were later removed because only zero was legal and no optional mode existed.

`Cannot Decrypt` was kept distinct: it means the signature verified but the GCM tag rejected the
body. The carrier was not proven altered, so `Tampered` would be false; collapsing into `Cannot
Verify` would discard the verified signature. `InvalidTag` is not a `ValueError` (its base is
`Exception`), so it had to be caught explicitly or this verdict would escape as a crash. `Payload
Missing` intentionally conflates a pristine carrier and wrong receiver key; its detail must not
claim the payload is absent. A wrong receiver key-size/envelope length fails bootstrap opening and
returns `Payload Missing` before the media hash, not `Tampered`.

Encryption moved inside `core.py`, which builds the record; caller-side encryption cannot conceal
the record's location-revealing prefix. Responsibilities stayed layered: `crypto.py` owns
primitives, `bootstrap.py` field format/span/AAD, and `core.py` operation order and verdicts.
Bootstrap AAD has one owner so sender and verifier cannot encode those fields differently. `keys.py`
was mechanically renamed `crypto.py` before cryptographic additions; 100% rename, zero file-content
lines changed, 52 exports before and after.

### Capacity and geometry lessons

The fixed v1 16 MiB cap refused payloads that fit a carrier: a 4000×3000 RGB image at `k=8` holds
35,997,579 bytes, and the cap refused 19 MB that fit; a 6000×4000 image holds 71,997,579 bytes,
refusing 55 MB. Capacity therefore became carrier-derived. The exact user-payload budget subtracts
serialized-record overhead, 16-byte GCM tag, and 256-byte signature; error messages must describe
the user's payload capacity, not the serialized-record maximum. `max_record_length` and
`max_user_payload_length` were kept distinct because confusing them overstates capacity. A usable
carrier can have exactly zero user capacity; an unusable carrier must raise rather than be clamped
to zero.

The bootstrap span is runtime data. It is the serialized envelope size times eight at 1 LSB, and
constrains legal starts and minimum usable carriers. It does not reduce capacity measured from an
already-chosen start. The illustration showed why it must be considered before maximum-capacity
answers: on a 4,000-unit carrier, at `k=1`, ignoring the RSA-2048 span appeared to leave 228 bytes
but the protocol did not fit; at `k=8`, the figures were 3,728 versus 1,680 bytes. The 32,000-sample
WAV figures were 3,728 versus 3,472 bytes at `k=1`. A false “fits” answer followed by encode failure
is worse than an early refusal.

Version 2 first explored carrier-derived integer width `W=max(1, ceil(bit_length(total_units)/8))`
across bootstrap, signature context, media-hash context, and payload lengths. Width had to be
derived in one place; `bit_length(N)` and `bit_length(N-1)` disagree at powers of two. Literal
golden-byte tests were required: one test typo expected `00 ff` for 256 (255), and a literal caught
it where recomputing expected bytes from the implementation would not. The width kept each format
injective and avoided a carrier-size ceiling. The KISS reduction later replaced this mechanism with
fixed u64 fields.

The bootstrap span must reach three places: both mask ranges, hash context, and
`preserved_bit_count`. At 2,048 units, omitting the bootstrap correction overstated untouched bits
by 2,048 (0.004% on the sample); rounded ratios hid the error. For a 10,000-unit carrier with
500-unit footprint at k=3, exact preserved bits were 78,500 at span zero and 76,452 at span 2,048.
On the 1280×1568 sample, the span-free and corrected ratios were 0.999784 and 0.999741 at both k=1
and k=8. Tests therefore asserted exact integers and that the difference equalled span, not rounded
ratios. Bootstrap masking is fixed at one low bit/unit, independent of packet LSB depth. Start must
be at or above the span, and the two masked regions must be disjoint. No capacity helper may omit
required start geometry or silently assume zero.

Version 1's 64 MiB `MAX_WAV_FRAME_BYTES` was an arbitrary cap on the carrier, about six minutes of
CD-quality stereo audio. Keeping it documented, raising it, or removing it while retaining
whole-file allocation were considered. The final resolution deleted the whole-file WAV helpers and
cap; `WavCarrier` provides seekable chunk access and validates headers without loading the whole
file.

#### Capacity changes across the intermediate formats

The user-facing limit was intended to answer “does this payload fit this carrier?” rather than
enforce an unrelated fixed ceiling. For v1, the 16 MiB cap was removed and exact carrier capacity
became the allocation guard. In v2 the serialized-record length and raw user-payload length were
explicitly separated: layout only knows record length; encode knows metadata and can report the
user's actual maximum. At N=5,000, start=137, metadata=17 bytes, stage 4a measured record/user
maxima of 328/210 bytes at k=1, 1,544/1,426 at k=3, and 4,584/4,466 at k=8. The fixed difference of
118 bytes was the 101-byte record overhead plus metadata; tests asserted both literal values and the
relationship. The owner defect was that core used the actual media ID while layout and tests
independently assumed 36 bytes based on `token_hex(16)`. If the generator changed to `token_hex(8)`,
the ID would be 20 rather than 36 bytes; core would measure 85 bytes while layout reported 101.
Capacity would be overstated and encoding would fail late. `packet.py` became the sole source of
record-length arithmetic, and a test pinned the actual generator's 36-byte ID.

Deleting the 23-byte v1 header raised record capacity by 23 bytes at stage 4b; adding the 16-byte
GCM tag then left a net +7 bytes over v1, while the signature remained 256 bytes. At the stage 4b
fixture, maxima became 351/233, 1,567/1,449, and 4,607/4,489 bytes (record/user, k=1/3/8). The v2
record overhead at that time was `93 + 2W`; at W=2 it was 97 bytes, at W=3 99, at W=4 101.
Consequently packet overhead was 369/371/373 bytes at those widths. These figures are historical:
KISS first made all general integer fields u64 and the subsequent v3 transition retained that
fixed-width approach. Current arithmetic belongs in Current Protocol.

The reserved span does not belong in the capacity formula measured from a user-selected start; it
determines whether that start is legal, and where maximum possible capacity begins.
`minimum_carrier_units` therefore needs the actual carrier's width and minimum protocol object.
Stage 6b corrected an asymmetry where an above-span carrier let empty payloads proceed while
refusing nonempty payloads. Both now refuse at the same structural guard if signature/tag/record
cannot fit; exact zero means the empty protocol object fits exactly. Tests must check that a refusal
leaves the source unchanged.

#### Envelope size, recognition, and field validation

The historical RSA-2048 bootstrap plaintext was 62 bytes: version, LSB count, start and ciphertext
length, 32-byte AES key, and 12-byte nonce. Its GCM AAD was 18 bytes. At the measured derived
widths, serialized bootstrap sizes were 49 bytes at W=1 and 51 bytes at W=2, with 5- and 7-byte AAD;
RSA-2048 OAEP/SHA-256 permits 190 plaintext bytes. Thus the 49-byte envelope fit with 141 bytes to
spare. The whole-envelope size, rather than RSA key length as a general rule, determines the number
of carrier units to read. For RSA-3072/RSA-4096 the design table gave 384/512-byte OAEP ciphertexts
and 3,072/4,096 units; the unimplemented X25519+AES-GCM alternative was 113 bytes/904 units with a
32-byte key. Their measured/design budget on the sample PNG and 32,000-sample WAV was RSA-2048:
0.034% / 6.4%; RSA-3072: 0.051% / 9.6%; X25519: 0.015% / 2.8%. The then-projected smallest empty
1-LSB carriers were 5,000 units with RSA-2048 (2,048 bootstrap + 2,952 packet) and 3,856 with X25519
(904 + 2,952). These small-carrier savings were why X25519 remained a fallback, despite RSA-OAEP's
simpler assignment explanation.

OAEP success is private bootstrap recognition, not sender authentication: anyone with the receiver's
public key can create an OAEP envelope. The sender signature authenticates the packet. Random
ordinary-media LSBs were expected to fail OAEP structure (leading zero, label hash, separator),
avoiding a plaintext marker, but no statistical undetectability claim followed. Bootstrap size
mismatch fails open as `Payload Missing` before hash processing. The ordering invariant was
explicit: parse and bounds-check all attacker-writable lengths before allocation; do not interpret
flags until signature verification; then decrypt, parse, and hash.

| Attacker changes | Binding in the v2 plan | Failure reason |
| --- | --- | --- |
| Version | Sender's constant in signing input | Prevents downgrade; never trust the received version for the preimage. |
| Flags | Signature and GCM AAD | Otherwise signed bytes could be reinterpreted as unencrypted content. |
| LSB count, start, ciphertext length | Signature and GCM AAD | Wrong extraction/length cannot become an accepted packet. |
| AES key or nonce | GCM tag | Substitution prevents authenticated plaintext; it can produce only `Cannot Decrypt`. |

The signing input covered ciphertext, not plaintext. This was accepted because GCM authenticates
ciphertext and AAD under the supplied key/nonce; a changed plaintext with a valid tag requires
defeating the tag. No key-commitment property was claimed. A signed version constant additionally
prevents using an attacker-supplied bootstrap version as the signing version.

#### Other v2 scope details retained

Version-2 structural checks were meant to refuse LSB counts outside 1–8, starts below the reserved
bootstrap span, ranges outside the carrier, and ciphertext lengths beyond carrier capacity before
allocation. The span must be loaded from the receiver key before questions about minimum usability
or maximum capacity are answered. For an illustrative 4,000-unit carrier at k=1, ignoring RSA-2048's
span appeared to leave 228 bytes but the protocol did not fit; at k=8 the figures were 3,728 and
1,680 bytes. For the 32,000-sample WAV at k=1, the values were 3,728 and 3,472 bytes. These examples
were meant to prevent false success followed by late encode failure.

V2's `Cannot Decrypt` detail stated only what was proved: the signature verified but AES-GCM
rejected the body; no payload was returned and media integrity was not established. For this result
`valid=False`, payload was `None`, and the protocol did not claim the carrier was tampered. Version
1 verdict semantics otherwise remained. A readable v2 bootstrap in the later v3 reader was not
retried as a different format. No migration for old files was planned because the repository stored
no old artifacts.

The v2 public protocol deliberately accepted any byte payload but encrypted the record
unconditionally. MIME and filename were not part of a new wrapper. The later KISS decision put those
claims in existing authenticated metadata, whose semicolon/equal-sign delimiters have no escaping;
therefore those characters are rejected in values. This kept raw file bytes arbitrary while avoiding
a second content mini-protocol.

### Plan decisions and their disposition

| Decision | Plan call | Disposition |
| --- | --- | --- |
| Receiver private key required for verification | Accept; matches assignment workflow | Retained in v3 |
| Delete public packet header/marker; put session key in bootstrap | Accept; redundant header and one receiver envelope | Implemented in v2 |
| RSA-OAEP instead of X25519 | Accept; fewer new concepts for assignment | Implemented. X25519/AES-GCM (113-byte envelope, 904 units versus RSA-2048's 256 bytes/2,048 units) remained a fallback for small carriers, not implemented |
| Carrier-derived widths in every format | Accept; no arbitrary size ceiling | Implemented, then replaced by fixed u64 in KISS |
| Public third-party verification mode | Reject; would create a second protocol and undo secrecy | Still unavailable |
| Sign flags; always encrypt; encrypt whole record | Accept; prevent reinterpretation and plaintext scanning | Implemented, then flags removed as dead policy |
| Separate verdict and body status | Reject; one `Cannot Decrypt` verdict says enough | Kept as one verdict |
| Signed commitment to AES key/nonce | Reject, reconsidered and reaffirmed; GCM substitution fails at tag | No commitment; stage 6c cancelled |
| Bootstrap layout as GCM AAD | Accept; no wire cost, second binding | Implemented |
| Fixed-width signing fields | Initially reject to avoid reintroducing ceiling | KISS later selected uniform u64 fields |
| `MAX_WAV_FRAME_BYTES` | Leave open, then delete whole-file path/cap | Closed by chunked `WavCarrier` |
| Caller-side payload seal in notebook | Remove; library now encrypts record unconditionally | Removed; later typed metadata stays inside encrypted record |
| Small WAV capacity fixture | Lengthen fixture, not protocol | 2,000-sample test fixture raised to 6,000 to exceed bootstrap span; notebook cover remains 32,000 samples, typed tone is a separate payload |

The byte-only API was correct for v1's integrity-only goal, not for v2's location-confidentiality
goal: `core.py` constructed the leaky record, so confidentiality could not be achieved outside it.
MIME/type description remained caller metadata, not part of the encrypted record's structure in the
v2 plan; KISS later placed typed claims in the existing metadata field. An early withdrawal of
whole-record encryption used obsolete v1 criteria (“readable hash” and layering); it was reversed
once the location-confidentiality objective was evaluated directly. Likewise, the derived-width
design was extended to every signed format rather than retaining fixed fields merely for elegance.

### V2 stage record: outcomes and measurements

Historical stage outcomes are preserved at their own commits. Stage counts below are counts at that
stage, not current suite size.

| Stage | Commit | Outcome and evidence |
| --- | --- | --- |
| 1: carrier-derived capacity | `a313203` | 25 tests. Removed 16 MiB cap. At 1, 3, and 8 LSB, maximum fits and maximum+1 refuses; decoded length was bounded before allocation. |
| 2a: derived widths and signed flags | `23fce87` | 27 tests. Changed both signed formats; boundaries at 255/256 and power-of-two widths tested. Widths were 1 byte at 255 units and 2 bytes at 65,535. A literal golden-byte test caught a 256-as-255 typo. |
| 2b: bootstrap span in mask/hash/fidelity | `2d7220c` | 32 tests. Exact fidelity assertions: 78,500 bits at span 0 and 76,452 at span 2,048 for N=10,000, footprint=500, k=3; difference equals span at k=1/3/8. Notebook was corrected from a stale three-argument call and gained exact integer evidence. |
| 2c: `keys.py` → `crypto.py` | `4df44c4` | 32 tests; 100% rename, zero content lines changed, 52 exported names before and after. |
| 3: bootstrap and crypto primitives | `16ff1d3` | 38 tests. Bootstrap plaintext serialized to 49 B at W=1 and 51 B at W=2; AAD 5/7 B; RSA-2048 OAEP-SHA256 plaintext limit 190 B; RSA-2048 span 2,048 units. `InvalidTag` handling and the one-owner layering were identified. |
| 4a: distinct capacity quantities | `cc72dd3` | 42 tests, no behavior/API change. At N=5,000, start=137, metadata=17 B, record/user maxima at k=1/3/8 were 328/210, 1,544/1,426, 4,584/4,466 B. `packet.py` became owner of `serialized_record_length`; one record-length assumption had been duplicated in core, layout, and tests. |
| 4b: remove marker, scan, header; explicit geometry | `e9ad8e7` | 46 tests. Headerless plaintext intermediate packet; APIs required start, k, and serialized length. Capacity at the 4a fixture became 351/233, 1,567/1,449, 4,607/4,489 B. 336 geometry probes passed; 3,359 B fit a 32,000-unit WAV at k=1, 3,360 refused. Notebook: 21 code cells, zero errors. This intermediate still leaked the record prefix, so did not provide location secrecy. |
| 4c: encrypted record and bootstrap | `b4a7b61` | 50 tests. RSA-OAEP bootstrap; AES-GCM whole record; tag included in packet; signature before decrypt; `InvalidTag` → `Cannot Decrypt`. Empty-object minimums at k=1/3/8 were 5,032/3,043/2,421 units for the then-fixed W=4 record. |
| 5: notebook security/verdict evidence | `d73918f` | 50 tests; no `stego/` files changed. Removed caller-side seal; demonstrated all seven verdicts and explicit fixed-bootstrap/statistical-steganalysis/DoS limits. The notebook capacity table reflected W=4 then: Banana 752,011 / 6,018,699 B at k=1/8; WAV 3,371 / 29,579 B. |
| 6a: carrier-derived record lengths | `56fbae7` | 54 tests. `W` replaced fixed u32 payload/metadata lengths. Record overhead 97/99/101 B at W=2/3/4; empty packet 369 B at W=2; minimums 5,000/3,032/2,417 units at k=1/3/8. Banana capacity 752,013/6,018,701 B at k=1/8; WAV 3,375/29,583 B. A 2^32 declared length was tested without allocating 4 GiB. |
| 6b: reject unusable carriers | `02e90d7` | 55 tests. Exact-fit totals 5,000/3,032/2,417 at k=1/3/8 accept empty payload and return zero user bytes. One-below totals 4,999/3,031/2,416 refuse both empty and one-byte inputs before modifying carrier. Stage 6c was cancelled; no key/nonce commitment was added. |

Further 4b evidence: 24 round trips (8 LSB depths × 3 starts), capacity-boundary encoding/refusal,
relocation/tamper verdicts, padding, malformed/pristine cases, and file wrappers. In stage 4a,
passing record overhead rather than importing across the `layout`/`packet` cycle preserved the
acyclic graph. The test-brief errors and the 2a mirror-test lesson are retained as broader testing
lessons below.

Stage 3's AES-256 key size had two owners for different reasons: `crypto.py` enforced a 32-byte
primitive key; `constants.py` declared the bootstrap field width. A test pinned their agreement. RSA
span calculation accepted general key sizes, while sealing pinned RSA-2048 in one validator, making
broader support one gate. Stage 4c also established bootstrap recognition is not authentication:
anyone with the receiver public key can produce OAEP ciphertext; the sender signature authenticates
packet content.

The stage-4a review exposed a process lesson worth retaining: a brief incorrectly stated which
modules imported `bits`/`constants`; the worker checked instead of trusting the brief. The brief
also omitted the user-facing capacity error and initially requested a test that computed its
expected value using the same code under test. These were corrected before approval. A
function-level import to work around the `layout`/`packet` cycle was rejected: it hid, rather than
removed, a dependency. `packet.py` owns record measurement; the caller passes overhead into layout,
keeping sequencing in core and the import graph acyclic. The stage 2a literal test and stage 4a
review both showed that test intent and implementation details must be verified independently.

The 4b intermediate state was knowingly not secure for location confidentiality: explicit geometry
had left the public API, but the plaintext record prefix remained searchable. Geometry was passed
explicitly only to create a separately reviewable, round-tripping transition before 4c moved it into
the receiver bootstrap. A temporary record-prefix reader and a transitional file with both public
and private locators were rejected because 4c would immediately remove them. Candidate limits and
ambiguity logic were removed only when there was no longer a scan; the decoder then checked only the
supplied location and made no “only one packet” guarantee.

Stage 5's notebook claim was limited to what protocol structure proves. Its separate 4,000-sample
tone was typed payload data, not the 32,000-sample WAV cover. The notebook did not choose the team
messages, FR13 innovation, or simulate the required live A-to-B transfer; those remained human
demonstration/submission decisions at that commit. Stage 6a's 2^32 declared-length test allocated no
4 GiB buffer. Stage 6b's one-below cases refused before changing the carrier. These are historical
gates and do not claim current suite counts.

### KISS reduction and move to protocol version 3

The KISS review compared v2 against the assignment, not against theoretical generality. Its scope
was deliberately surgical: preserve receiver-gated encryption, bootstrap, AES-GCM, RSA-PSS,
masked-media hash, and PNG/WAV security behavior while removing extra format machinery.

| Reduction decision | Reason and outcome |
| --- | --- |
| Replace carrier-derived `W` with uniform u64 | `W` was correct but costly to explain/test; uniform 8-byte big-endian fields are ample for foreseeable carriers and simplify parsing. Timestamp was slightly wider than needed; negligible cost. |
| Remove the caller-side nested content header | MIME and filename claims fit the existing FR3 metadata. Keep raw arbitrary user bytes, avoiding a second mini-protocol. Metadata rejects `;` and `=` because there is no escaping. |
| Remove flags while touching wire format | Only legal value was zero; no implemented mode justified policy branches. Protocol versioning can mark future incompatible formats. |
| Keep one-byte bounded/enumerated fields | Version, media code, LSB count, and media-ID length are bounded; do not widen for uniformity's sake. |
| Retain whole-record AES-GCM, per-object key, RSA-OAEP receiver bootstrap, distinct signing/decryption roles, RSA-PSS, masked hash, 1–8 LSB, arbitrary chosen start, verdicts, fidelity metric, strict media validation, sample-width correctness, and useful regression tests | Each serves a concrete security/assignment behavior; reducing test count is not a goal. |
| Defer more streaming/video infrastructure | Optional video is not a reason to build speculative infrastructure; retain room, revisit only for a concrete carrier. | Later project work implemented video and chunked carriers separately. |
| Leave public API narrowing optional | No assignment benefit justified reorganization. |

The agreed scope note said not to implement streaming WAV or video unless separately authorized.
Subsequent commits did implement those features; this history does not imply they were part of the
KISS reduction.

Reduction phases and outcomes:

| Phase | Commit | Outcome |
| --- | --- | --- |
| Baseline | `51fb9e8` | Clean branch `yx`, 54 tests. `nbconvert` absent; installed later for notebook execution. |
| Fixed u64 fields | `76b1e13` | Replaced carrier-dependent integer widths. |
| Remove flags | `5442b40` | Removed from format and API. |
| Typed metadata | `04fb47f` | MIME/name moved into existing metadata. |
| Reject ambiguous metadata delimiters | `ff9bd20` | Reject `;` and `=` where no escaping exists. |
| Refresh notebook | `602b7b4` | Outputs refreshed with registered kernel, not hand-edited; added `nbconvert==7.17.1` for reproducibility. |
| Security/test audit | `829c53e` | Audited reduced format and retained security coverage. |
| Docs updates | `7445538`, `4b69a3d` | Current guides, records, index, and maps updated. |

At the reduction snapshot, protocol version remained 2 and the suite had 57 passing tests. Generated
36-byte media ID gave 109-byte record overhead, 381-byte empty packet overhead (record + 16-byte GCM
tag + 256-byte signature), 62-byte bootstrap plaintext, 18-byte AAD, and 2,048-unit RSA-2048 span.
Empty metadata, start 2,048, span 2,048: minimum units at k=1/2/3/8 were 5,096/3,572/3,064/2,429.
Banana (6,021,120 units) user capacity was 752,003/1,504,387/2,256,771/6,018,691 B; 32,000-sample
WAV was 3,363/7,107/10,851/29,571 B. Demo record/ciphertext/packet were 176/192/448 B.

A reported coincidence was corrected: `k*footprint` equals packet bits plus up to `k-1` pad bits,
not always packet bits. The 448-byte example divides at k=1 and k=8, so preserved counts happen to
match; k=3/5/6 have 1/1/4 pad bits. Stale notebook figures were corrected to 3384, 3384, and 423.
Other post-review fixes retained:

- `d667444`: corrected alignment and field wording; enumerations/prefixes remain u8 while general
  lengths, positions, counters, and timestamps use u64.
- `5b854df`: named packet-size constants in `serialized_record_length`.
- `29a3f58`: oversized metadata now reports `record overhead exceeds record capacity` and both
  compared values, not the structural “carrier too small” diagnostic. Refusal still occurred before
  embedding; the defect was misleading wording.
- `7c1152e`: named regression test for oversized metadata; test count 55.
- `a86de7b`: notebook checks verdict before dereferencing payload, preventing an `AttributeError` on
  failure. GCM language was narrowed: authenticates ciphertext/AAD under supplied key/nonce, no
  key-commitment claim.
- `f65515e`: capacity measurement now enforces u64 bounds and timestamp range consistently. No live
  defect existed because encode supplies the 36-byte ID and real byte strings do not approach the
  limit; exact inverse behavior justified the shared validator. Suite reached 57 tests.

The version number stayed 2 during the KISS reduction because there were no released artifacts
needing migration; inventing v3 then would have been needless. The later transition to v3 was a
separate protocol change: commit `3e6c34a` (“Move to protocol version 3 with full media hash and
RGBA PNG covers”, 2026-09-24). It expanded hash coverage and added RGBA support without undoing
receiver-gated encryption, RSA-OAEP bootstrap, AES-GCM, RSA-PSS, or typed metadata. The v3 wire
format and current rules are documented in [Protocol](../protocol.md); v1/v2 artifacts
are not accepted by the active verifier.

The stage 4c empty-packet test set also exercised 24 positive cases (8 LSB depths × 3 legal
positions), disjoint masking, flags binding, key/nonce tampering, ciphertext confidentiality, and
the single-bootstrap-read ordering. Stage 5 printed 48,163,592 preserved bits at k=1 and k=8,
alongside 2,048 bits written in the bootstrap and 14,336 bootstrap-preserved bits. At stage 6a, a
W=2 demo with payload `hello` and empty metadata measured a 104-byte record, 120-byte ciphertext,
376-byte packet, 1,003-unit footprint at k=3, and one pad bit. These values belong to their commits
and widths, not today's wire contract.

The closed WAV-cap decision explicitly considered three choices: keep 64 MiB and state the
six-minute implication; raise it but leave an arbitrary ceiling; or remove it while whole-file
parsing could trust a hostile declared count and allocate heavily. The actual closure removed both
whole-file helpers and cap, then used seekable chunked access. KISS also made two non-format
decisions: stop opening new protocol stages without a concrete requirement, and treat public-API
narrowing as optional cleanup rather than spending assignment time reorganizing exports. Its
priority order was fixed fields, metadata reuse, opportunistic flags removal while already changing
the format, affected tests/docs only, then freeze protocol and focus on GUI, required image/audio
demonstrations, Party A→B flow, sample cases, and submission evidence. Video and streaming were
deferred in that plan; they arrived in separately authorized work later.

### Reduction lessons

- Generality can be correct and still exceed the assignment; fixed fields improved readability without
  weakening the retained security design.
- Removing a nested format is safer than replacing it with another wrapper when authenticated metadata
  already exists.
- Keep stage-time measurements attached to their commits; later wire changes supersede present-day
  claims but do not make historical measurements false.
- Notebook output refresh does not refresh nearby prose. Re-audit capacities, headings, links, and
  status separately.
- A measured coincidence is not a rule; test the alignment mechanism, not only matching outputs at two
  convenient k values.

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
