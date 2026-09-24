# Three.js steganography map

## Purpose

Step 4 of the encoding wizard includes a technical PNG carrier map. It is a
progressive enhancement over the existing numeric `start_unit` field: the map
selects and explains protocol geometry, while the Flask encoder remains the
only component that validates and writes steganographic data.

The packet format, traversal order, cryptography, verification flow, and WAV
behavior are unchanged.

## Coordinate and footprint model

An RGB PNG contributes three carrier units per pixel. For a pixel at `(x, y)`:

```text
pixel_index = y * width + x
start_unit = pixel_index * 3
total_units = width * height * 3
```

Map clicks always select the first channel of a pixel. Manual entry still allows
an exact channel-level unit. The first 2,048 units are drawn as the receiver
bootstrap region and map clicks inside that region are rejected. Because unit
2,048 is the third channel of pixel 682, the first whole pixel that the map can
select begins at unit 2,049.

The packet remains one contiguous carrier-unit range. The client maps that range
to at most three overlay meshes: a partial first row, a block of complete rows,
and a partial final row. It does not create one mesh or DOM element per pixel.

## Authoritative layout flow

The browser posts the current cover, receiver public key, payload, metadata,
`start_unit`, and LSB count to `POST /layout/estimate`. The service uses the same
strict PNG/WAV loaders, metadata builder, RSA bootstrap sizing,
`serialized_record_length`, `build_embedding_layout`,
`max_user_payload_length`, and `preserved_bit_count` calculations as `/encode`.

The response contains non-secret layout information only: carrier dimensions,
unit counts, packet footprint, payload capacity, remaining units, usage, and
preserved-bit ratio. The normal `/encode` submission repeats all validation and
is authoritative. No session key, private key material, or bootstrap plaintext
is exposed to the viewer.

## Browser components

- `stego-map-geometry.js` contains framework-free coordinate and row-span helpers.
- `stego-map.js` owns the Three.js scene, texture plane, constrained
  `OrbitControls`, raycasting, marker, overlays, statistics, and lifecycle.
- `index.html` contains the Step 4 map, mode controls, inspector, statistics, and
  the retained manual input.
- `style.css` supplies the responsive technical-viewer layout.
- `app.js` emits the successful image result to the optional difference view.

Normal mode keeps the exact footprint subtle. Embedding Map exaggerates the
same footprint and states that it is not a prediction of visible distortion.
After a successful PNG encode, Difference mode compares original and stego RGB
values in browser memory and highlights pixels that changed; this overlay never
modifies the exported image.

Hovering reports pixel coordinates, row-major pixel index, first carrier unit,
RGB values, and the three channel bit strings. Changing the existing 1-8 LSB
control requests fresh authoritative geometry and updates the explanatory bit
count.

## Progressive enhancement and lifecycle

If Three.js, WebGL, image decoding, or canvas access fails, the manual
`start_unit` input remains usable and the server still performs normal
validation. WAV covers never enter the Three.js path and show the manual linear
sample-unit control.

New covers dispose the prior plane geometry, materials, texture, marker,
footprint meshes, and difference texture. Resizing uses one `ResizeObserver`;
hovering reuses one raycaster and the existing image buffer.

## Local dependency

Three.js is bundled under `stego_web/static/vendor/three/`; the application does
not fetch it from a CDN. `VERSION.txt` records version `0.180.0` (`r180`), the
retained module and `OrbitControls` files, and their npm source. The upstream MIT
license is retained beside them.

## Verification

`test_webapp.py` checks the endpoint against real encode geometry, LSB and
payload-size changes, invalid reserved and end-of-carrier starts, PNG dimensions,
WAV linear units, and the rendered local-module entry points. When Node.js is
available, it also imports the real geometry module to test both documented
coordinate examples, inverse mapping, image corners/Y-axis conversion, the
bootstrap boundary, and partial-row footprint rectangles.
