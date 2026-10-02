"""Display helpers for the demonstration notebook.

The notebook uses these functions to show check results as tables and to draw
diagrams and charts. They only display data. They do not change protocol
behaviour, and the tests do not depend on them.
"""

from html import escape

import matplotlib.pyplot as plt
import numpy as np
from IPython.display import HTML, display
from matplotlib.axes import Axes
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle

PASS_COLOUR = "#1a7f37"
FAIL_COLOUR = "#cf222e"
WARN_COLOUR = "#9a6700"
INFO_COLOUR = "#0969da"
MUTED_COLOUR = "#8c959f"
BOOTSTRAP_COLOUR = "#54aeff"
PACKET_COLOUR = "#fb8f44"
UNTOUCHED_COLOUR = "#eaeef2"

VERDICT_COLOURS = {
    "Authentic": PASS_COLOUR,
    "Tampered": FAIL_COLOUR,
    "Signature Invalid": FAIL_COLOUR,
    "Wrong Start Location": FAIL_COLOUR,
    "Cannot Decrypt": FAIL_COLOUR,
    "Payload Missing": WARN_COLOUR,
    "Cannot Verify": WARN_COLOUR,
    "Refused": INFO_COLOUR,
}

CHECK_STEPS = (
    "Open the\nbootstrap",
    "Check the\nlocation",
    "Read the packet,\ncheck the signature",
    "Decrypt the\nrecord",
    "Compare the\nmedia hash",
)
CHECK_HEADERS = ("Open\nbootstrap", "Check\nlocation", "Check\nsignature", "Decrypt\nrecord", "Compare\nmedia hash")
STEP_FAILURE_VERDICTS = (
    "Payload Missing\nor Cannot Verify",
    "Wrong Start\nLocation",
    "Signature Invalid\nor Cannot Verify",
    "Cannot Decrypt",
    "Tampered",
)

_TABLE_STYLE = (
    "border-collapse:collapse;margin:6px 0 12px 0;font-size:13px;"
    "background:#ffffff;color:#1f2328;"
)
_HEAD_STYLE = (
    "text-align:left;padding:6px 10px;background:#f6f8fa;color:#1f2328;"
    "border-bottom:2px solid #d0d7de;"
)
_CELL_STYLE = (
    "text-align:left;padding:5px 10px;border-bottom:1px solid #eaeef2;"
    "vertical-align:top;max-width:560px;overflow-wrap:anywhere;"
)
_TITLE_STYLE = "font-weight:600;font-size:14px;margin:10px 0 2px 0;"

_pending_checks: list[tuple[str, object, object, bool]] = []


def _badge(text: str, colour: str) -> str:
    """Return an HTML pill with white text on the given colour."""
    return (
        f'<span style="background:{colour};color:#ffffff;border-radius:10px;'
        f'padding:1px 9px;font-weight:600;white-space:nowrap;">{escape(text)}</span>'
    )


def _cell_html(value: object) -> str:
    """Format one table cell, turning verdict names into coloured badges."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    if text in VERDICT_COLOURS:
        return _badge(text, VERDICT_COLOURS[text])
    if isinstance(value, int):
        text = f"{value:,}"
    return escape(text)


def _table_html(title: str, columns: list[str], rows: list[list[str]]) -> str:
    """Build a styled HTML table whose cells are already HTML."""
    head = "".join(f'<th style="{_HEAD_STYLE}">{escape(column)}</th>' for column in columns)
    body = "".join(
        "<tr>" + "".join(f'<td style="{_CELL_STYLE}">{cell}</td>' for cell in row) + "</tr>"
        for row in rows
    )
    caption = f'<div style="{_TITLE_STYLE}">{escape(title)}</div>' if title else ""
    return f'{caption}<table style="{_TABLE_STYLE}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def show_check(label: str, expected: object, actual: object, passed: bool | None = None) -> None:
    """Record one expected-versus-actual check for the table at the end of the cell.

    When ``passed`` is None, the check passes if both values have the same text.
    Pass ``passed`` when the expected value is a description, such as "not Authentic".
    """
    result = str(expected) == str(actual) if passed is None else passed
    _pending_checks.append((label, expected, actual, result))


def flush_checks(result: object = None) -> None:
    """Show the checks recorded in the current cell as one table, then clear them.

    The notebook registers this function to run after every cell.
    """
    if not _pending_checks:
        return
    rows = [
        [
            escape(label),
            _cell_html(expected),
            _cell_html(actual),
            _badge("✓ Pass", PASS_COLOUR) if passed else _badge("✗ Fail", FAIL_COLOUR),
        ]
        for label, expected, actual, passed in _pending_checks
    ]
    passed_count = sum(1 for *_, passed in _pending_checks if passed)
    title = f"Checks: {passed_count} of {len(_pending_checks)} passed"
    _pending_checks.clear()
    display(HTML(_table_html(title, ["Check", "Expected", "Actual", "Result"], rows)))


def show_facts(title: str, facts: dict[str, object]) -> None:
    """Show named values as a two-column table."""
    rows = [[escape(name), _cell_html(value)] for name, value in facts.items()]
    display(HTML(_table_html(title, ["Item", "Value"], rows)))


def show_table(title: str, columns: list[str], rows: list[list[object]]) -> None:
    """Show rows of values as a table. Verdict names become coloured badges."""
    display(HTML(_table_html(title, columns, [[_cell_html(value) for value in row] for row in rows])))


def _box(axis: Axes, x: float, y: float, width: float, height: float, text: str, colour: str, text_colour: str = "#1f2328", size: float = 10) -> None:
    """Draw a rounded box with centred text, with (x, y) as the box centre."""
    axis.add_patch(FancyBboxPatch(
        (x - width / 2, y - height / 2), width, height,
        boxstyle="round,pad=0.02,rounding_size=0.08", facecolor=colour, edgecolor="#57606a", linewidth=1,
    ))
    axis.text(x, y, text, ha="center", va="center", fontsize=size, color=text_colour, wrap=True)


def _arrow(axis: Axes, start: tuple[float, float], end: tuple[float, float], label: str = "") -> None:
    """Draw an arrow, with an optional label above its middle."""
    axis.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=16, color="#57606a", linewidth=1.4))
    if label:
        axis.text((start[0] + end[0]) / 2, (start[1] + end[1]) / 2 + 0.17, label, ha="center", va="bottom", fontsize=8.5, color="#57606a")


def draw_flow_diagram() -> None:
    """Draw how a message travels from Party A to Party B."""
    figure, axis = plt.subplots(figsize=(12, 3.6))
    axis.set_xlim(0, 12)
    axis.set_ylim(0, 3.6)
    axis.axis("off")
    _box(axis, 1.1, 2.6, 2.0, 0.8, "Cover\nPNG, WAV,\nor video", "#f6f8fa", size=9)
    _box(axis, 1.1, 1.2, 2.0, 0.8, "Message\ntext or file", "#f6f8fa", size=9)
    _box(axis, 3.9, 1.9, 2.4, 1.9, "Party A (sender)\n\nSigns with\nA's private key\n\nLocks the location with\nB's public key", "#ddf4ff", size=9.5)
    _box(axis, 6.9, 1.9, 1.9, 1.2, "Stego file\n\nLooks like\nthe cover", "#fff8c5")
    _box(axis, 9.7, 1.9, 2.4, 1.9, "Party B (receiver)\n\nUnlocks the location with\nB's private key\n\nChecks the signature with\nA's public key", "#dafbe1", size=9.5)
    _box(axis, 11.45, 1.9, 1.0, 0.9, "Verdict\n+\nmessage", "#f6f8fa", size=9)
    _arrow(axis, (2.1, 2.5), (2.7, 2.1))
    _arrow(axis, (2.1, 1.3), (2.7, 1.7))
    _arrow(axis, (5.1, 1.9), (5.95, 1.9), "embed")
    _arrow(axis, (7.85, 1.9), (8.5, 1.9), "send")
    _arrow(axis, (10.9, 1.9), (10.95, 1.9))
    axis.text(6.9, 0.45, "The original cover never travels. B needs only the stego file and the two keys.", ha="center", fontsize=9, color="#57606a")
    axis.set_title("How a message travels", fontsize=12, loc="left")
    plt.show()
    plt.close(figure)


def draw_verification_pipeline() -> None:
    """Draw the five verification checks and the verdict when each one fails."""
    figure, axis = plt.subplots(figsize=(12, 3.4))
    axis.set_xlim(0, 12.6)
    axis.set_ylim(0, 3.4)
    axis.axis("off")
    for index, (step, verdict) in enumerate(zip(CHECK_STEPS, STEP_FAILURE_VERDICTS)):
        x = 1.15 + index * 2.25
        _box(axis, x, 2.45, 1.9, 0.9, f"{index + 1}. {step}", "#ddf4ff", size=9)
        axis.add_patch(FancyArrowPatch((x, 1.95), (x, 1.35), arrowstyle="-|>", mutation_scale=12, color=FAIL_COLOUR, linewidth=1.2))
        axis.text(x + 0.08, 1.65, "fails", fontsize=8, color=FAIL_COLOUR, va="center")
        _box(axis, x, 0.85, 1.9, 0.8, verdict, "#ffebe9", text_colour=FAIL_COLOUR, size=9)
        if index < len(CHECK_STEPS) - 1:
            _arrow(axis, (x + 0.97, 2.45), (x + 1.28, 2.45))
    _arrow(axis, (11.07, 2.45), (11.45, 2.45))
    _box(axis, 12.0, 2.45, 1.0, 0.9, "All pass:\nAuthentic", "#dafbe1", text_colour=PASS_COLOUR, size=9)
    axis.set_title("Verification runs these checks in order and stops at the first failure", fontsize=12, loc="left")
    plt.show()
    plt.close(figure)


def draw_check_grid(rows: list[tuple[str, int | None, str]]) -> None:
    """Draw which checks passed, failed, or did not run for each case.

    Each row is (case label, index of the failed check or None, actual verdict).
    """
    step_labels = CHECK_HEADERS
    figure, axis = plt.subplots(figsize=(12.5, 0.55 * len(rows) + 1.6))
    axis.set_xlim(0, len(step_labels) + 3.6)
    axis.set_ylim(len(rows), -1.3)
    axis.axis("off")
    for column, label in enumerate(step_labels):
        axis.text(2.1 + column + 0.5, -0.45, label, ha="center", va="center", fontsize=9)
    axis.text(2.1 + len(step_labels) + 0.75, -0.45, "Verdict", ha="center", va="center", fontsize=9, fontweight="bold")
    for row, (label, failed_step, verdict) in enumerate(rows):
        axis.text(2.0, row + 0.5, label, ha="right", va="center", fontsize=9.5)
        for column in range(len(step_labels)):
            if failed_step is None or column < failed_step:
                colour, mark = PASS_COLOUR, "✓"
            elif column == failed_step:
                colour, mark = FAIL_COLOUR, "✗"
            else:
                colour, mark = "#d0d7de", "–"
            axis.add_patch(Rectangle((2.1 + column + 0.06, row + 0.08), 0.88, 0.84, facecolor=colour, edgecolor="white"))
            axis.text(2.1 + column + 0.5, row + 0.5, mark, ha="center", va="center", color="white", fontsize=12, fontweight="bold")
        axis.text(2.1 + len(step_labels) + 0.15, row + 0.5, verdict, ha="left", va="center", fontsize=9.5, fontweight="bold", color=VERDICT_COLOURS.get(verdict, "#1f2328"))
    axis.set_title("Green = passed, red = first failed check, grey = not run", fontsize=10, loc="left", color="#57606a")
    plt.show()
    plt.close(figure)


def draw_carrier_layout(title: str, total_units: int, bootstrap_units: int, start_unit: int, footprint: int, lsb_count: int) -> None:
    """Draw where the bootstrap and the packet sit in the carrier, to scale and zoomed in."""
    figure, (whole, zoom) = plt.subplots(2, 1, figsize=(12, 3.4), gridspec_kw={"hspace": 1.1})
    for axis in (whole, zoom):
        axis.set_yticks([])
        for side in ("left", "right", "top"):
            axis.spines[side].set_visible(False)
    whole.add_patch(Rectangle((0, 0), total_units, 1, facecolor=UNTOUCHED_COLOUR, edgecolor="#57606a"))
    marker_width = max(footprint, total_units * 0.004)
    whole.add_patch(Rectangle((0, 0), max(bootstrap_units, marker_width), 1, facecolor=BOOTSTRAP_COLOUR))
    whole.add_patch(Rectangle((start_unit, 0), marker_width, 1, facecolor=PACKET_COLOUR))
    whole.set_xlim(0, total_units)
    whole.set_ylim(0, 1)
    whole.set_title(f"{title}: the whole carrier ({total_units:,} units, to scale; narrow regions are widened so that they are visible)", fontsize=10, loc="left")
    whole.ticklabel_format(axis="x", style="plain")
    whole.xaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{int(value):,}"))
    margin = max(footprint, 40)
    low, high = max(0, start_unit - margin), min(total_units, start_unit + footprint + margin)
    zoom.add_patch(Rectangle((low, 0), high - low, 1, facecolor=UNTOUCHED_COLOUR, edgecolor="#57606a"))
    zoom.add_patch(Rectangle((start_unit, 0), footprint, 1, facecolor=PACKET_COLOUR))
    if low < bootstrap_units:
        zoom.add_patch(Rectangle((low, 0), bootstrap_units - low, 1, facecolor=BOOTSTRAP_COLOUR))
    zoom.set_xlim(low, high)
    zoom.set_ylim(0, 1)
    zoom.xaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{int(value):,}"))
    zoom.set_title(f"Zoomed in: packet at units {start_unit:,} to {start_unit + footprint - 1:,} ({footprint:,} units, {lsb_count} bit(s) each)", fontsize=10, loc="left")
    zoom.set_xlabel("Carrier unit index")
    figure.legend(
        handles=[
            Rectangle((0, 0), 1, 1, facecolor=BOOTSTRAP_COLOUR),
            Rectangle((0, 0), 1, 1, facecolor=PACKET_COLOUR),
            Rectangle((0, 0), 1, 1, facecolor=UNTOUCHED_COLOUR, edgecolor="#57606a"),
        ],
        labels=[f"Bootstrap: units 0 to {bootstrap_units - 1:,}, lowest bit only", f"Packet: {lsb_count} low bit(s) per unit", "Not written; covered by the media hash"],
        loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.12), fontsize=9,
    )
    plt.show()
    plt.close(figure)


def draw_bit_grid(cover_values: np.ndarray, stego_values: np.ndarray, lsb_count: int) -> None:
    """Draw the bits of a few carrier units before and after embedding.

    The shaded columns are the low bits that embedding may replace. Red cells are bits that changed.
    """
    count = len(cover_values)
    figure, axis = plt.subplots(figsize=(12, 0.42 * count + 1.5))
    axis.set_xlim(-2.4, 20.6)
    axis.set_ylim(count, -1.2)
    axis.axis("off")
    for row, (cover_value, stego_value) in enumerate(zip(cover_values, stego_values)):
        cover_bits, stego_bits = f"{int(cover_value):08b}", f"{int(stego_value):08b}"
        axis.text(-0.3, row + 0.5, f"unit {row}:  {int(cover_value):3d}", ha="right", va="center", fontsize=9, family="monospace")
        axis.text(20.4, row + 0.5, f"{int(stego_value):3d}", ha="right", va="center", fontsize=9, family="monospace")
        for column in range(8):
            low_bit = column >= 8 - lsb_count
            changed = cover_bits[column] != stego_bits[column]
            for offset, bits in ((0, cover_bits), (10, stego_bits)):
                if offset and changed:
                    colour = FAIL_COLOUR
                elif low_bit:
                    colour = "#ddf4ff"
                else:
                    colour = "#f6f8fa"
                axis.add_patch(Rectangle((offset + column + 0.05, row + 0.08), 0.9, 0.84, facecolor=colour, edgecolor="#d0d7de"))
                axis.text(offset + column + 0.5, row + 0.5, bits[column], ha="center", va="center", fontsize=10, family="monospace", color="white" if offset and changed else "#1f2328")
    axis.text(4, -0.6, "Cover bits", ha="center", fontsize=10, fontweight="bold")
    axis.text(14, -0.6, "Stego bits", ha="center", fontsize=10, fontweight="bold")
    axis.text(9, -0.6, "→", ha="center", fontsize=14)
    axis.set_title(f"First {count} packet units. Blue columns: the {lsb_count} low bit(s) that may change. Red: bits that changed. High bits never change.", fontsize=10, loc="left")
    plt.show()
    plt.close(figure)


def plot_lsb_sweep(rows: list[tuple[str, int, int, int, str]]) -> None:
    """Chart footprint, changed units, and the largest per-unit change for k = 1 to 8.

    Each row is (cover name, k, footprint units, changed units, verdict).
    """
    figure, axes = plt.subplots(1, 3, figsize=(13, 3.6))
    for cover_name, marker in (("PNG", "o"), ("WAV", "s")):
        cover_rows = [row for row in rows if row[0] == cover_name]
        k_values = [row[1] for row in cover_rows]
        axes[0].plot(k_values, [row[2] for row in cover_rows], marker=marker, label=cover_name)
        axes[1].plot(k_values, [row[3] for row in cover_rows], marker=marker, label=cover_name)
    k_range = np.arange(1, 9)
    axes[2].bar(k_range, 2 ** k_range - 1, color=PACKET_COLOUR)
    titles = (
        "Units used by the packet\n(more bits per unit = fewer units)",
        "Units actually changed\n(some new bits equal the old bits)",
        "Largest change to one unit\n(2^k − 1)",
    )
    for axis, title in zip(axes, titles):
        axis.set_title(title, fontsize=10)
        axis.set_xlabel("k (LSB count)")
        axis.set_xticks(k_range)
        axis.grid(alpha=0.3)
    axes[0].legend()
    axes[1].legend()
    figure.tight_layout()
    plt.show()
    plt.close(figure)


def plot_wav_change(cover: np.ndarray, stego: np.ndarray, bootstrap_units: int, start_unit: int, footprint: int) -> None:
    """Chart a WAV cover against its stego copy: a waveform close-up and the per-sample change."""
    figure, (wave_axis, change_axis) = plt.subplots(2, 1, figsize=(12, 5.6), gridspec_kw={"hspace": 0.55})
    window = np.arange(start_unit, min(start_unit + 60, len(cover)))
    wave_axis.plot(window, cover[window], color="#57606a", linewidth=2.5, label="Cover")
    wave_axis.plot(window, stego[window], color=PACKET_COLOUR, linewidth=1.2, linestyle="--", label="Stego")
    wave_axis.set_title(f"Samples {window[0]:,} to {window[-1]:,}, inside the packet: the two waves overlap", fontsize=10, loc="left")
    wave_axis.set_ylabel("Sample value")
    wave_axis.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0))
    wave_axis.grid(alpha=0.3)
    span = min(len(cover), start_unit + footprint + max(footprint // 2, 200))
    difference = stego[:span].astype(np.int32) - cover[:span].astype(np.int32)
    change_axis.axvspan(0, bootstrap_units, color=BOOTSTRAP_COLOUR, alpha=0.25, label="Bootstrap (1 bit per sample)")
    change_axis.axvspan(start_unit, start_unit + footprint, color=PACKET_COLOUR, alpha=0.25, label="Packet")
    changed = np.nonzero(difference)[0]
    change_axis.scatter(changed, difference[changed], s=6, color=FAIL_COLOUR, label="Changed sample")
    change_axis.axhline(0, color="#57606a", linewidth=0.8)
    change_axis.set_xlim(0, span)
    change_axis.set_title(f"Stego minus cover for samples 0 to {span - 1:,}; samples outside the shaded areas are unchanged", fontsize=10, loc="left")
    change_axis.set_xlabel("Sample index")
    change_axis.set_ylabel("Change")
    change_axis.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), fontsize=8)
    change_axis.grid(alpha=0.3)
    plt.show()
    plt.close(figure)


def plot_byte_bars(title: str, items: list[tuple[str, int]], highlight: str = "") -> None:
    """Draw a horizontal bar chart of byte counts, with optional highlighted bar labels."""
    figure, axis = plt.subplots(figsize=(11, 0.6 * len(items) + 1.2))
    labels = [label for label, _ in items]
    values = [value for _, value in items]
    colours = [PACKET_COLOUR if label == highlight else BOOTSTRAP_COLOUR for label in labels]
    axis.barh(labels, values, color=colours)
    for index, value in enumerate(values):
        axis.text(value, index, f"  {value:,} bytes", va="center", fontsize=9)
    axis.invert_yaxis()
    axis.set_xlim(0, max(values) * 1.3)
    axis.xaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{value / 1_000_000:.1f} MB"))
    axis.set_title(title, fontsize=11, loc="left")
    for side in ("right", "top"):
        axis.spines[side].set_visible(False)
    figure.tight_layout()
    plt.show()
    plt.close(figure)
