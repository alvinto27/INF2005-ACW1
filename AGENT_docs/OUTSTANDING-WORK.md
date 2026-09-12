# Outstanding Work

This record lists assignment work that remains outside the finished library and notebook.

## 1. IMPLEMENTED INTERFACE AND REMAINING INTEGRATION

### GUI

The mandatory GUI from brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) is now implemented in `stego_web/`. It provides guided encoding, decoding and verification for PNG and PCM/WAV, cover/stego previews, audio controls, 1–8 LSB selection, status and verdict displays, downloads, and responsive animated interactions. Criteria 2 and 3 still require a complete team demonstration and evidence under brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks).

The incoming masked-media `stego/` protocol is retained alongside the Flask application's existing `STG1` protocol. They are not yet exposed as selectable formats in the GUI and are intentionally not treated as interoperable. See [Protocol Compatibility](PROTOCOL-COMPATIBILITY.md). A future integration must version or select the format explicitly and preserve rejection tests for cross-format files.

### Individual technical explanation (criterion 6)

This individual criterion is worth 5 marks. It remains outstanding for every member (brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks)). Each person must explain their own technical contribution and answer relevant demonstration questions with credible understanding. Each person owns this work individually; it is not a team-level item.

### Innovation explanation (FR13)

This requirement is worth 4 marks (brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criterion 5). The team still needs to explain what innovation it incorporated, why it is useful, meaningful and practical, and how it improves the baseline (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope), [§6 FR13](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements), and [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criterion 5). A candidate is the repository's existing negative test cases, which already function as an attack simulation. It is undecided whether the team will use this candidate or choose another innovation explanation.

## 2. NOT BUILT, BELONGS HERE OR TO THE DEMO

### Confidentiality payload

The required various-payload-sizes case includes a relevant custom payload that the team decides can protect the hidden message's confidentiality and integrity (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)). Integrity and authenticity already exist. Confidentiality means encrypting the message before embedding it. This needs no library change: `user_payload` contains plain bytes, so the caller can pass ciphertext. The encrypted payload choice is **undecided**. The team must choose the custom message and encryption format to embed.

### Party A to party B transfer

The demonstration must show a stego object sent from party A to party B, such as by email. Party B must download it to their folder and extract the hidden message with proof of integrity and signature verification (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§7](../docs/INF2005-ACW1-spec_v5-f2f.md#7-required-security-workflow)). The notebook deliberately does not simulate this transfer. It must happen live in the demonstration.

### Limitations, ethics and AI-use reflection (criterion 7)

This team criterion is worth 2 marks (brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks)). The team still needs an honest reflection on technical limits, responsible use, originality, and how AI was used and checked. The following material is available for that reflection:

- Technical limitations are already written in [INTEGRITY-DESIGN.md](INTEGRITY-DESIGN.md#limitations): overwritten cover bits cannot be recovered or authenticated; the start magic is public; padding validation is only a format check; and authenticity is relative to the public key supplied for verification.
- One further limitation is not yet written down. PNG compression is lossless, so LSB embedding preserves the pixels exactly. However, embedded bits are random and compress poorly, so the stego file is slightly larger than the cover. For `samples/Banana.png`, the cover is 1,673,875 bytes; the stego files are 1,675,090 bytes at `k=1`, 1,675,035 bytes at `k=3`, and 1,674,414 bytes at `k=8`. An observer holding both files sees a size increase of 1,215, 1,160, or 539 bytes at identical dimensions. This is a real detectability signal and an honest limitation to report.
- The cleanup and demonstration work in this repository was carried out by AI agents under human direction and human review. The team must write and sign its own reflection; this record does not write that reflection for it.

## 3. DECIDED BUT NOT YET USED

The brief names the exact test payload categories, but the notebook currently uses placeholder strings (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope), required cases: various payload sizes).

- **Short message:** Use one Learning Outcome from brief [§3](../docs/INF2005-ACW1-spec_v5-f2f.md#3-learning-outcomes). The recorded choice is outcome 6, about designing and securing the start location. It is 138 bytes and is the outcome this implementation answers most directly.
- **Large message:** Use the Project Overview paragraphs from brief [§2](../docs/INF2005-ACW1-spec_v5-f2f.md#2-project-overview). They are 673 bytes.
- **Capacity reference:** At `k=1`, the Banana cover holds 752,640 bytes and the 32,000-sample WAV holds 4,000 bytes. Therefore, the 673-byte large message fits both. The large message is large only relative to the short message; it is not a capacity test. The separate capacity case embeds the cover image inside itself (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)).

## 4. SUBMISSION PACKAGE, NOT ASSEMBLED

The submission package still needs the items required by brief [§9](../docs/INF2005-ACW1-spec_v5-f2f.md#9-required-submission-package): source code, sample files, test evidence, README, a declaration of originality, and an agreed team contribution and distribution statement. The form of the test evidence is **undecided**: the team must choose between screenshots, logs, output files, or a combination.

The demonstration must run for no more than 25 minutes, with speaking or demonstration time allocated to every member (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§9](../docs/INF2005-ACW1-spec_v5-f2f.md#9-required-submission-package)).
