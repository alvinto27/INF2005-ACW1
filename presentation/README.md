# StegoVerify technical-design slides

These are the slides for our technical-design presentation. A PDF copy is in [`stego-slides.pdf`](stego-slides.pdf).

The slides use Reveal.js 5.2.1, which is included in `vendor/reveal/`, so they work offline.

## Run

From the repository root:

```sh
python -m http.server 8000 --directory presentation
```

Use `python3` on Linux or macOS. Then open `http://127.0.0.1:8000`. The server needs no extra packages.

## Controls

| Key | Action |
| --- | --- |
| `Right` or `Space` | Next slide or step |
| `Left` | Previous slide or step |
| `S` | Presenter view with speaker notes |
| `O` | Slide overview |
| `F` | Full screen |

On the capacity slide, choose an LSB count from 1 to 8 to update the example.

## Export to PDF

1. Open `http://127.0.0.1:8000/?print-pdf`.
2. Print, with landscape layout and background graphics turned on.
3. Save as PDF.

Export the PDF again after changing the slides.

The slides describe protocol version 3. If the protocol changes, update the slides and [`docs/protocol.md`](../docs/protocol.md) together.
