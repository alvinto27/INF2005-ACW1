# Outstanding Work

This record lists assignment work that remains outside the library and notebook. The library implements committed protocol version 2 stage 6b: verification recovers geometry through the encrypted bootstrap and is gated by the receiver private key; see the [Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md).

## 1. NOT BUILT, OWNED ELSEWHERE

### GUI

The GUI is mandatory under brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope). Another team member owns it; this repository does not build it. Criteria 2 and 3 total 19 marks (9 for image and 10 for audio) under brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks). Those criteria assess the working implementations and their demonstrations. This repository already provides the working encoders and decoders, payload insertion, extraction through the encrypted bootstrap, receiver-gated verification, and negative or tampered detection for both media. The GUI remains the demonstration surface owed by the team. It must:

- play or execute the payload (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)). The content header that makes this possible is designed and demonstrated; see [Payload Envelope Design](PROTOCOL-DESIGN.md#payload-envelope-design). The GUI must read the declared type to select a handler, and must confirm the declared type against the bytes before it renders anything;
- display the cover and stego objects side by side before and after encoding and decoding (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope));
- allow selection of 1 to 8 LSBs for encoding (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope));
- collect the start unit and LSB count for encoding, with the start-unit control bounded below by the receiver's reserved bootstrap span;
- require the receiver private key as well as the sender public key for verification. Verification no longer collects or transports start unit, LSB count, or record length: the receiver recovers those values from the encrypted bootstrap;
- not offer public-key-only third-party verification. This is deliberate because location confidentiality makes the receiver private key the verification gate; see the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md#2-the-trade-that-cannot-be-avoided).

### Individual technical explanation (criterion 6)

This individual criterion is worth 5 marks. It remains outstanding for every member (brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks)). Each person must explain their own technical contribution and answer relevant demonstration questions with credible understanding. Each person owns this work individually; it is not a team-level item.

### Innovation explanation (FR13)

This requirement is worth 4 marks (brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criterion 5). The team still needs to explain what innovation it incorporated, why it is useful, meaningful and practical, and how it improves the baseline (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope), [§6 FR13](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements), and [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criterion 5). A candidate is receiver-gated location confidentiality: the encrypted bootstrap prevents recovery of the packet location without the receiver private key and directly answers the section 5 start-location question. It remains a candidate, not a decision; the team must choose whether to use it or another innovation explanation.

## 2. NOT BUILT, BELONGS HERE OR TO THE DEMO

### Party A to party B transfer

The demonstration must show a stego object sent from party A to party B, such as by email. Party B must download it to their folder and extract the hidden message with proof of integrity and signature verification (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§7](../docs/INF2005-ACW1-spec_v5-f2f.md#7-required-security-workflow)). The notebook deliberately does not simulate this transfer. It must happen live in the demonstration.

### Limitations, ethics and AI-use reflection (criterion 7)

This team criterion is worth 2 marks (brief [§11](../docs/INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks)). The team still needs an honest reflection on technical limits, responsible use, originality, and how AI was used and checked. The following material is available for that reflection:

- Technical limitations are already written in [PROTOCOL-DESIGN.md](PROTOCOL-DESIGN.md#limitations): overwritten cover bits cannot be recovered or authenticated; the fixed bootstrap span remains observable even though its fields and the record are encrypted; padding validation is only a format check; and authenticity is relative to the sender public key supplied for verification.
- One further limitation is not yet written down. PNG compression is lossless, so LSB embedding preserves the pixels exactly. However, embedded bits are random and compress poorly, so the stego file is slightly larger than the cover. For `samples/Banana.png`, the cover is 1,673,875 bytes; the stego files are 1,675,090 bytes at `k=1`, 1,675,035 bytes at `k=3`, and 1,674,414 bytes at `k=8`. An observer holding both files sees a size increase of 1,215, 1,160, or 539 bytes at identical dimensions. This is a real detectability signal and an honest limitation to report.
- The cleanup and demonstration work in this repository was carried out by AI agents under human direction and human review. The team must write and sign its own reflection; this record does not write that reflection for it.

## 3. DECIDED BUT NOT YET USED

The brief names the exact test payload categories, but the notebook currently uses placeholder strings (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope), required cases: various payload sizes).

- **Short message:** Use one Learning Outcome from brief [§3](../docs/INF2005-ACW1-spec_v5-f2f.md#3-learning-outcomes). The recorded choice is outcome 6, about designing and securing the start location. It is 138 bytes and is the outcome this implementation answers most directly.
- **Large message:** Use the Project Overview paragraphs from brief [§2](../docs/INF2005-ACW1-spec_v5-f2f.md#2-project-overview). They are 673 bytes.
- **Custom confidential payload:** Library-level encryption and integrity, plus the content-type mechanism, are **built and demonstrated** in the [demonstration notebook](../notebooks/FR1-12%20Prototype.ipynb). Only the **message content is undecided**. The notebook uses a placeholder string, and the team must choose the message it demonstrates.
- **Typed payload files:** The typed-payload demonstration generates its own payload files, a 64x64 image and a short tone. A supplied audio file replaces the generated tone later. The swap point is one variable in the typed-payload cell. A supplied file must stay below about 700,000 bytes to fit the image carrier at `k=1`, and should be plain PCM WAV or MP3 so that the notebook can play it.
- **Capacity reference:** Measured from start unit 2,048 with empty metadata, the current library gives 752,013 bytes at `k=1` and 6,018,701 bytes at `k=8` in the 6,021,120-unit Banana cover; it gives 3,375 bytes at `k=1` and 29,583 bytes at `k=8` in the 32,000-sample WAV. Therefore, the 673-byte large message fits both. The large message is large only relative to the short message; it is not a capacity test. The separate capacity case embeds the cover image inside itself (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)).

## 4. SUBMISSION PACKAGE, NOT ASSEMBLED

The submission package still needs the items required by brief [§9](../docs/INF2005-ACW1-spec_v5-f2f.md#9-required-submission-package): source code, sample files, test evidence, README, a declaration of originality, and an agreed team contribution and distribution statement. The form of the test evidence is **undecided**: the team must choose between screenshots, logs, output files, or a combination.

The demonstration must run for no more than 25 minutes, with speaking or demonstration time allocated to every member (brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§9](../docs/INF2005-ACW1-spec_v5-f2f.md#9-required-submission-package)).
