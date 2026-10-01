# StegoVerify technical-design slides

These are the slides for our technical-design presentation. If you only want to read them, open [`stego-slides.pdf`](stego-slides.pdf). To present them live, follow the steps below.

The deck is built with Reveal.js and uses the same visual style as the web app. Reveal.js 5.2.1 and its speaker-notes plugin are included under `vendor/reveal/`, so the slides work without a network connection.

## Run

From the repository root, on Windows (using the project's virtual environment):

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

`stego-slides.pdf` was exported from this `?print-pdf` view. Export it again after changing the slides.

The slides describe protocol version 3. If the protocol changes, update the deck and [`docs/protocol.md`](../docs/protocol.md) together.
