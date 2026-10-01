# StegoVerify technical-design slides

The deck is a self-contained Reveal.js presentation matching the active Flask GUI theme. Reveal.js 5.2.1 and its presenter-notes plugin are vendored under `vendor/reveal/`, so the presentation does not require network access.

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

The slide content describes protocol version 3. Update it together with `AGENT_docs/CURRENT-PROTOCOL.md` if the protocol changes.
