# Three.js steganography map

**Status:** Not connected. The map assets exist, but the active GUI does not load them, and the estimate route that they call fails. Manual `start_unit` entry is the only working layout control.

## Current state

The repository contains `stego_web/static/stego-map.js`,
`stego_web/static/stego-map-geometry.js`, and locally bundled Three.js files
under `stego_web/static/vendor/three/`. `VERSION.txt` records version 0.180.0
(`r180`) and the upstream source. The vendor directory includes its upstream
MIT `LICENSE`.

`index.html` does not load these map assets, and the template does not contain
the controls that the map module expects. The active seven-step wizard uses the
manual `start_unit` field in Step 4. Therefore, the Three.js map,
click-to-select behavior, footprint overlays, hover inspector, and difference
view are not active GUI features. The source files describe an intended map;
they do not prove a working interface.

## Known gaps

- The map module posts the cover, receiver key, payload, metadata,
  `start_unit`, and LSB count to `POST /layout/estimate`. The route is declared
  in `stego_web/routes.py`, but it calls `protocol_service.estimate_layout()`,
  which does not exist in `CurrentProtocolService`. The call raises an
  `AttributeError`. The route does not catch it, so Flask returns HTTP 500.
- `index.html` does not load `stego-map.js` and does not contain the map
  controls.
- The map and geometry assets have no active integration test in
  `test_webapp.py`.

`POST /encode` remains the active validation path.

## Intended geometry (design notes)

These notes describe the intended map. They are not active behavior until the
gaps above are fixed.

An RGB PNG contributes three carrier units per pixel. For a pixel at `(x, y)`:

```text
pixel_index = y * width + x
start_unit = pixel_index * 3
total_units = width * height * 3
```

Map clicks select the first channel of a pixel. Manual entry can select any
exact carrier unit. Units 0–2,047 are reserved for the receiver bootstrap.
Unit 2,048 is the third channel of pixel 682, so the first whole-pixel map
selection would be unit 2,049.

The packet is one contiguous carrier-unit range. The client maps that range to
at most three row rectangles: a partial first row, a block of complete rows,
and a partial final row. WAV covers use linear sample units, not the image map.

The estimate response is intended to contain non-secret layout information
only: carrier dimensions, unit counts, packet footprint, payload capacity,
remaining units, usage, and preserved-bit ratio. `POST /encode` repeats all
validation and is authoritative.
