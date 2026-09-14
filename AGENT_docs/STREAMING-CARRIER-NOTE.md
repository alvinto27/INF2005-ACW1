# Streaming Carrier Note

**Status: shelved. Not designed, not planned, not scheduled.** This note exists so that [decision 14](LOCATION-CONFIDENTIALITY-PLAN.md#12-open-decisions) has a named target, and so that the idea is not rediscovered from scratch.

The brief does not ask for this. It is an internal architecture question.

## What it is

The package holds the whole carrier in memory as one NumPy array of 8-bit units. `MAX_WAV_FRAME_BYTES = 64 MiB` exists because of that: the WAV loader reads a declared frame count before it can validate anything, so the constant guards the allocation.

The shelved change replaces whole-carrier arrays with chunked access, so the working set stays bounded and the constant is no longer needed.

## The name is slightly wrong

"Streaming" suggests one forward pass. That is not enough here:

| Need | Why one pass fails |
| --- | --- |
| Masked media hash | covers the whole carrier, so a full pass is required |
| Packet read and write | happens at a user-selected start unit, so random access is required |
| Bootstrap read | happens at unit 0, before the start unit is known |

So the requirement is **seekable chunked access**, not a stream. Encoding needs two passes over the input: one to compute the masked hash, one to write. Those cannot merge, because the signature depends on the hash and the signature is written into the carrier.

Decoding needs a seek to unit 0, then a seek to the start unit, then a full pass for the hash.

## What it would fix

| Item | Effect |
| --- | --- |
| `MAX_WAV_FRAME_BYTES` | removable. The bound becomes the chunk size, which is a real memory figure rather than an arbitrary file-size ceiling |
| Large carriers | a seven-minute stereo song becomes usable as a cover object |
| Peak memory | bounded by the chunk size instead of the carrier size |

## What it would cost

The carrier array is the central type of the package. Every module takes or returns one:

| Module | Dependency |
| --- | --- |
| `stego/media.py` | `rgb_array_to_carrier`, `wav_frame_bytes_to_carrier`, and both save paths |
| `stego/bits.py` | all LSB read and write primitives |
| `stego/layout.py` | `calculate_masked_media_hash` takes the full array |
| `stego/core.py` | `encode_carrier` and `decode_carrier` take and return full arrays |

PNG gains less than WAV. Pillow decodes a whole image regardless, so the honest benefit is on the audio side.

## Why it is shelved

- The brief sets no memory or carrier-size requirement.
- It touches every module, so it cannot be reviewed in small pieces the way the version 2 stages can.
- Protocol version 2 is assignment-relevant and this is not. Doing this first would delay work that is graded.

## Order, if it is ever revisited

Do protocol version 2 first. Its stage 1 introduces the carrier-derived width and capacity functions, which take the unit count as a plain integer and do not care how the carrier is stored. That part survives a move to chunked access unchanged.

The parts that would need rework are the masked hash and the read and write primitives, and those are rewritten by version 2 anyway. Doing streaming first would mean writing them twice.

## Before revisiting, these must be true

1. Protocol version 2 is implemented and its tests pass.
2. There is a real carrier that the 64 MiB cap rejects and that somebody needs.
3. A chunk size is chosen with a stated reason, not a round number.
