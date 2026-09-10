# Personal TODO — FR1 and FR5 Algorithms

Owner scope: image loading, validation, capacity calculation, and LSB embedding. GUI work is excluded.

## FR1: Image input algorithm

- [ ] Select a lossless image representation; support PNG first.
- [ ] Implement image loading from a file path or byte stream.
- [ ] Validate that the input is a supported image type.
- [ ] Reject unreadable, unsupported, and corrupted input with clear errors.
- [ ] Preserve image dimensions, colour mode, and pixel values when loading.
- [ ] Return image metadata required by the embedding algorithm.
- [ ] Document any unsupported image modes and conversion rules.
- [ ] If JPEG is supported, document that lossy compression can destroy embedded data.

## FR5: Image LSB embedding algorithm

- [ ] Define deterministic byte-to-bit and bit-to-byte ordering.
- [ ] Define the embedded header or payload-length representation.
- [ ] Implement LSB replacement across image pixel channels.
- [ ] Support an LSB count from 1 through 8 as a function parameter.
- [ ] Accept a payload start location as a function parameter.
- [ ] Calculate usable capacity from the image, LSB count, start location, and header size.
- [ ] Reject invalid LSB counts and start locations.
- [ ] Reject over-capacity payloads before changing image data.
- [ ] Return a new stego image without modifying the original image in place.
- [ ] Preserve image dimensions and required metadata.
- [ ] Save or serialize the stego image in a lossless format, preferably PNG.

## Tests

- [ ] Load a valid PNG and verify its dimensions, mode, and pixel data.
- [ ] Reject unsupported, unreadable, and corrupted input.
- [ ] Test deterministic embedding of a known payload.
- [ ] Test every LSB count from 1 through 8.
- [ ] Test valid start locations near the beginning, middle, and capacity boundary.
- [ ] Test invalid and out-of-range start locations.
- [ ] Test empty, short, large, exact-capacity, and over-capacity payloads.
- [ ] Verify that an over-capacity failure leaves the source image unchanged.
- [ ] Verify that embedding leaves the original image object unchanged.
- [ ] Save and reopen a stego PNG, then confirm that its embedded bits remain unchanged.
- [ ] Confirm that the FR8 extraction algorithm can recover the exact payload.

## Algorithm handoff

- [ ] Agree on the payload byte format with the FR3 and FR4 owners.
- [ ] Agree on the start-location value and unit with the FR7 owner.
- [ ] Agree on channel order, bit order, header format, and LSB count with the FR8 owner.
- [ ] Document function inputs, outputs, exceptions, capacity units, and image-mode assumptions.

## Completion criteria

- [ ] The algorithm loads and validates supported PNG input.
- [ ] It embeds arbitrary payload bytes using LSB replacement.
- [ ] It respects the supplied LSB count and start location.
- [ ] It rejects invalid or over-capacity input without partial output.
- [ ] The stego PNG survives saving and reopening.
- [ ] Automated tests pass and FR8 can extract the payload exactly.
