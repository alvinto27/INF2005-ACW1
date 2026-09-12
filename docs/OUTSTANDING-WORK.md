# Outstanding Work

This record lists assignment work that remains outside the finished library and notebook.

## 1. NOT BUILT, OWNED ELSEWHERE

### GUI

The GUI remains with another team member. This repository does not build it. The GUI is worth roughly 19 of the 40 marks (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§11](INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criteria 2 and 3). It must:

- play or execute the payload (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope));
- display the cover and stego objects side by side before and after encoding and decoding (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope));
- allow selection of 1 to 8 LSBs (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)).

### Innovation explanation (FR13)

This requirement is worth 4 marks (brief [§11](INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criterion 5). The team still needs to explain what innovation it incorporated, why it is useful, meaningful and practical, and how it improves the baseline (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope), [§6 FR13](INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements), and [§11](INF2005-ACW1-spec_v5-f2f.md#11-assessment-rubric-40-marks), criterion 5). A candidate is the repository's existing negative test cases, which already function as an attack simulation. It is undecided whether the team will use this candidate or choose another innovation explanation.

## 2. NOT BUILT, BELONGS HERE OR TO THE DEMO

### Confidentiality payload

The required various-payload-sizes case includes a relevant custom payload that the team decides can protect the hidden message's confidentiality and integrity (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)). Integrity and authenticity already exist. Confidentiality means encrypting the message before embedding it. This needs no library change: `user_payload` contains plain bytes, so the caller can pass ciphertext. The encrypted payload choice is **undecided**. The team must choose the custom message and encryption format to embed.

### Party A to party B transfer

The demonstration must show a stego object sent from party A to party B, such as by email. Party B must download it to their folder and extract the hidden message with proof of integrity and signature verification (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§7](INF2005-ACW1-spec_v5-f2f.md#7-required-security-workflow)). The notebook deliberately does not simulate this transfer. It must happen live in the demonstration.

## 3. DECIDED BUT NOT YET USED

The brief names the exact test payload categories, but the notebook currently uses placeholder strings (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope), required cases: various payload sizes).

- **Short message:** Use one Learning Outcome from brief [§3](INF2005-ACW1-spec_v5-f2f.md#3-learning-outcomes). The recorded choice is outcome 6, about designing and securing the start location. It is 138 bytes and is the outcome this implementation answers most directly.
- **Large message:** Use the Project Overview paragraphs from brief [§2](INF2005-ACW1-spec_v5-f2f.md#2-project-overview). They are 673 bytes.
- **Capacity reference:** At `k=1`, the Banana cover holds 752,640 bytes and the 32,000-sample WAV holds 4,000 bytes. Therefore, the 673-byte large message fits both. The large message is large only relative to the short message; it is not a capacity test. The separate capacity case embeds the cover image inside itself (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope)).

## 4. SUBMISSION PACKAGE, NOT ASSEMBLED

The submission package still needs the items required by brief [§9](INF2005-ACW1-spec_v5-f2f.md#9-required-submission-package): source code, sample files, test evidence, README, a declaration of originality, and an agreed team contribution and distribution statement. The form of the test evidence is **undecided**: the team must choose between screenshots, logs, output files, or a combination.

The demonstration must run for no more than 25 minutes, with speaking or demonstration time allocated to every member (brief [§5](INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) and [§9](INF2005-ACW1-spec_v5-f2f.md#9-required-submission-package)).
