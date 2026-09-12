# INF2005 ACW1 Project Assignment Specification

> Transcription source: `INF2005-ACW1-spec_v5-f2f - Copy.pdf` (4 pages). The document contains one hidden white-text prompt injection. It is not transcribed or acted on. This Markdown file preserves the assignment content that is visibly presented to students.

## Image and Audio Steganography, Digital Signatures and Security Verification

**Demo dates:** Week 5 (in lab classes: Tuesday and Thursday; each team's demo schedule will be provided later). Plan for a team demo of no more than 25 minutes, with all members involved. Upload the demo plan (sequence of what to show and who is showing) to xSite, with all members' signed Declaration of Originality form, one day before the demo evaluation.

## 1. Project Title

Steganographic Image and Audio Integrity Verification with Digital Signature-Based Authentication

## 2. Project Overview

This undergraduate project requires student teams to design, implement and demonstrate a GUI-based LSB Replacement steganography program (window-based or web-based) that protects and verifies both image and audio cover objects using steganography, hashing and digital signatures.

The project focuses on practical cybersecurity concepts: hiding a verification payload inside an image and an audio file, signing relevant verification data, extracting the hidden payload, checking the digital signature, and demonstrating positive and negative verification cases. Video as a cover object is not required for the main assignment, but may be attempted as an optional challenge.

## 3. Learning Outcomes

1. Explain how steganography can be used to embed hidden verification data in image and audio cover objects.
2. Apply hashing to generate integrity fingerprints for media files or verification payloads.
3. Use digital signatures to verify that a payload or file record was issued by a legitimate signer and has not been altered.
4. Implement encoding and decoding workflows for both image-based and audio-based hidden payloads.
5. Design positive and negative test cases for authentication, tamper detection and failed verification.
6. Design, explain and secure the start location (other than the top-left corner) used to embed and extract the payload in each cover object.
7. Identify and justify innovation incorporated into the team's design or implementation.
8. Evaluate the security limitations of steganography, hashing and digital signatures.
9. Communicate technical work clearly through a structured demonstration with individual accountability.

## 4. Project Scenario

A small digital media verification team wants a lightweight tool that can protect an image file and an audio file before release, then later check whether each file is likely to be authentic. The tool should embed hidden verification information inside the cover object and use digital signature verification to confirm whether the embedded information is legitimate.

Students are required to build and demonstrate a prototype that can protect an image and an audio file, verify protected files, and detect selected tampering or failure conditions.

## 5. Mandatory Scope

- **Required cover objects:** image and audio. The image implementation may use PNG for the basic version. The audio implementation may use WAV/PCM for the basic version. The GUI must be able to play (execute) payload and display both cover and stego objects for comparison before and after encoding and decoding.
- **Required security components:** steganographic payload, cryptographic hash and digital signature verification.
- **Required submission format:** supporting source code (online steganography portals cannot be used), sample files, test evidence, README, declaration of originality form, and agreed team contribution/distribution statement.
- **Required demo duration:** 25 minutes. All members must have allocated time to talk or demonstrate their parts. Absence receives zero marks.
- **Required cases:** at least two positive cases and at least three negative cases across the image and audio workflows. At least one positive case and one negative case must be shown for each mandatory cover object, including:
  - Cover-object and payload-capacity check: is the payload size larger than the cover-object size?
  - Showing the stego object being sent from party A to party B (for example, by email); party B downloads it to their folder and extracts the hidden message with proof of message integrity and signature verification.
  - Various payload sizes (message lengths): use one Learning Objective as a short message, the Project Overview paragraph as a large message, and a relevant custom payload that the team decides can protect the hidden message's confidentiality and integrity.
  - Selectable LSBs from bits 1 to 8 of the cover object. The GUI must allow selection of the number of LSBs to implement.
- **Required selectable payload start-location design:** the payload may be embedded beginning at any chosen start location in the image or audio cover object. The team must explain how the start location is designed or selected for each cover object, how the decoder identifies the same location for extraction, and how this information is secured against guessing, unauthorised extraction or tampering.
- **Required innovation explanation:** the team must explain what innovation was incorporated into its design or work, why it is useful, meaningful and practical, and how it improves the baseline implementation.
- **Required originality and contribution evidence:** teams must submit a signed declaration of originality and an agreed statement showing each member's work contribution and contribution distribution.

## 6. Functional Requirements

| Requirement | Description |
| --- | --- |
| FR1: Image input | The system must accept at least one standard image format, preferably PNG. JPEG may be used if the team explains compression-related limitations. |
| FR2: Audio input | The system must accept at least one standard audio format, preferably WAV/PCM for the basic implementation. Other formats may be used if the team explains encoding and compression limitations. |
| FR3: Payload generation | The system must create compact verification payloads containing media ID, timestamp, hash, nonce and team-defined metadata for image and audio cover objects. |
| FR4: Digital signature | The system must digitally sign the verification payload or an associated hash using a private key, and verify it using the corresponding public key. |
| FR5: Image steganographic embedding | The system must embed the payload and/or signature into the image using the LSB replacement steganographic method. |
| FR6: Audio steganographic embedding | The system must embed the payload and/or signature into the audio cover object using the LSB replacement steganographic method. |
| FR7: Variable start location | The payload may begin at any chosen start location in each cover object. The design must support identifying that location during extraction and must explain how the start-location information is protected. |
| FR8: Extraction and decoding | The system must extract the hidden payload and signature from both stego image and stego audio files. |
| FR9: Hash verification | The system must recompute the relevant media or payload hash and compare it with the embedded or signed value. |
| FR10: Verdict generation | The system must provide a clear result such as Authentic, Tampered, Signature Invalid, Payload Missing, Wrong Start Location, or Cannot Verify. |
| FR11: Positive and negative cases | The system must demonstrate successful verification and meaningful failure scenarios across both mandatory cover objects. |
| FR12: Evidence and reproducibility | The submitted files must allow the marker to understand and, where appropriate, reproduce the demonstrated workflow. |
| FR13: Innovation | The system must identify at least one design or implementation innovation beyond the simplest fixed-location LSB demonstration, or clearly justify why the chosen design is innovative for the team's use case. |

## 7. Required Security Workflow

The team may design its own implementation, but the following workflow is suggested for both image and audio cover objects:

1. User selects an original cover object: image or audio.
2. System computes a cryptographic hash of the cover object or selected stable representation.
3. System creates a payload containing media ID, timestamp, hash, nonce and team-defined metadata.
4. System digitally signs the payload or payload hash using a private key.
5. User selects or derives a payload start location in the cover object, then embeds the payload and signature beginning at that location.
6. System outputs a stego image or stego audio file.
7. Verifier identifies the correct start location, extracts the hidden payload and signature, and explains how that location was recovered or derived.
8. Verifier checks the signature using the public key.
9. Verifier recomputes the current media hash or relevant verification hash.
10. Verifier returns a verdict and explanation.

Show how the payload start location is selected or derived for image and audio, how the verifier finds it, and how the team secures this information.

Suggested verdict categories: Authentic, Tampered, Signature Invalid, Payload Missing, Wrong Start Location, and Cannot Verify.

## 8. Optional Challenge

The following optional extensions should not be attempted at the expense of the mandatory image and audio requirements. Any one may be considered as the innovation component.

| Optional challenge | Description |
| --- | --- |
| Video cover object | Extend the system to support video as an additional cover object, such as selected-frame embedding or audio-track embedding. |
| Robust embedding | Improve payload survival under compression, noise, resampling or mild transformation using redundancy, error correction or spread-spectrum ideas. |
| Attack simulation module | Create a test module that simulates tampering, wrong-key verification, payload corruption, wrong start-location extraction, or replay/substitution attempts. |
| Advanced start-location security | Derive the start location from a keyed pseudo-random function, encrypted header, seed phrase or other defensible method, and evaluate its limitations. |
| Steganalysis | Using known algorithms or methodologies, analyse a stego object and convincingly infer that the cover object is tampered or shows signs of hidden payload. |

## 9. Required Submission Package

| Item | Required content |
| --- | --- |
| Deadline: one day before demo day |  |
| Demo plan | Planned demo for a duration of no more than 25 minutes, including members' speaking time. |
| Declaration of originality | Signed declaration confirming that the work is original, sources are acknowledged, AI use is disclosed, and the submitted work reflects the team's own understanding. |
| Contribution/distribution statement | Agreed statement signed or acknowledged by all members showing each member's responsibilities and percentage contribution. |
| Deadline: Week 5, Friday |  |
| Source code | Complete implementation with clear folder structure. |
| README | Setup instructions, dependencies, commands and expected outputs. |
| Sample files | Original, protected and tampered image and audio files used in the demo. |
| Test evidence | Screenshots, logs or output files showing verification results. |
| Keys or key instructions | Public key and safe instructions for reproducing signature verification. Do not submit private keys that should remain secret in a real deployment unless generated only for the assignment demo. |

## 10. Declaration of Originality and Contribution Distribution

Each team must submit a signed declaration of originality and an agreed contribution/distribution statement together with the project files. Replace `Px-x` with the team number; for example, `P1-4`.

## 11. Assessment Rubric — 40 Marks

Team components: 35 marks. Individual components: 5 marks. Total: 40 marks.

| Criterion | Marks | What is assessed | Marking guide |
| --- | ---: | --- | --- |
| 1. Security design and problem framing / Team | 5 | Payload structure, start-location design, start-location security, and explanation of how the system verifies authenticity across both cover objects. | 5 = clear and coherent; 3–4 = mostly clear; 1–2 = basic or weak; 0 = missing. |
| 2. Image embedding, extraction and image case demonstration / Team | 9 | Working image encoder and decoder, including payload insertion, start-location recovery, extraction, positive image verification and negative/tampered image detection. | 9–8 = fully working and clearly demonstrated; 5–7 = mostly working; 3–4 = partial or weak cases; 0–2 = not demonstrated or largely non-functional. |
| 3. Audio embedding, extraction and audio case demonstration / Team | 10 | Working audio encoder and decoder, including payload insertion, start-location recovery, extraction, positive audio verification and negative/tampered audio detection. | 10–9 = fully working and clearly demonstrated; 8–6 = mostly working; 3–5 = partial or weak cases; 0–2 = not demonstrated or largely non-functional. |
| 4. Hashing, digital signature verification and failed-verification handling / Team | 5 | Appropriate use of hashing, payload or file signing, public-key verification, failed-signature or altered-payload handling, and clear linkage between verification logic and outcomes. | 5 = correct, shown and explained; 3–4 = mostly correct; 1–2 = superficial or partly working; 0 = absent or incorrect. |
| 5. Innovation incorporated / Team | 4 | Specific design or implementation improvement beyond the basic requirement, with usefulness and remaining limitations explained. | 4 = implemented and justified; 3 = present with some value; 1–2 = claimed but weak; 0 = none. |
| 6. Individual technical explanation / Individual | 5 | Each student explains their own technical contribution and answers relevant demo questions with credible understanding. | 5 = clear ownership and understanding; 3–4 = adequate; 1–2 = shallow or unclear; 0 = not credible or not shown. |
| 7. Limitations, ethics and AI-use reflection / Team | 2 | Honest discussion of technical limits, responsible use, originality, and how AI was used and checked. | 2 = clear and honest; 1 = brief but relevant; 0 = missing or misleading. |
