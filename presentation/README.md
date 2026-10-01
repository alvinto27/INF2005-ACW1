# StegoVerify technical-design slides

This guide helps teammates and markers run the technical-design slides and export a PDF. The offline Reveal.js deck uses the Flask app's visual theme; Reveal.js 5.2.1 and its presenter-notes plugin are included under `vendor/reveal/`, so it needs no network access.

## Run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --directory presentation
```

On Linux or macOS, run:

```sh
python3 -m http.server 8000 --directory presentation
```

Open `http://127.0.0.1:8000`.

## Controls

- `Right`, `Space`, or click the right control: next slide or fragment.
- `Left`: previous slide or fragment.
- `S`: open presenter view with speaker notes.
- `O`: slide overview.
- `F`: fullscreen.
- On the capacity slide, select any LSB depth from 1 through 8 to update the example packet footprint and preserved-bit ratio.

## Export to PDF

Open `http://127.0.0.1:8000/?print-pdf`, use the browser print dialog, select landscape, enable background graphics, and save as PDF.

`stego-slides.pdf` is a committed export. Export it again after you change the slides.

The slides describe protocol version 3. If the protocol changes, update the deck and [`docs/protocol.md`](../docs/protocol.md) together.
