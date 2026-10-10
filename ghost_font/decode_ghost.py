#!/usr/bin/env python3
"""Ghost Font — recover the hidden text from a single stego screenshot."""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

import numpy as np
from PIL import Image

CANVAS_WIDTH = 1280
CANVAS_HEIGHT = 720
CELL_SIZE = 6
ATLAS_WIDTH = 1296
SIGNAL_X_OFFSET = 294


def inspect_png(path: Path) -> None:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")

    offset = 8
    print("PNG chunks:")
    while offset + 12 <= len(data):
        start = offset
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack(">I", data[offset + 8 + length : offset + 12 + length])[0]
        actual_crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        print(
            f"  0x{start:06x} {kind.decode('latin1'):4s} "
            f"length={length:6d} crc={'ok' if stored_crc == actual_crc else 'BAD'}"
        )
        offset += length + 12
        if kind == b"IEND":
            break

    print(f"Parsed end: {offset}; file size: {len(data)}; trailing bytes: {len(data) - offset}")


def longest_run(indices: np.ndarray) -> tuple[int, int]:
    if indices.size == 0:
        raise ValueError("could not locate the Ghost Font canvas")

    splits = np.flatnonzero(np.diff(indices) > 1) + 1
    runs = np.split(indices, splits)
    run = max(runs, key=len)
    return int(run[0]), int(run[-1]) + 1


def normalize_canvas(image: Image.Image) -> np.ndarray:
    gray = np.asarray(image.convert("L"))

    # Browser chrome has only a few dark pixels per row; the canvas has hundreds.
    # A toolbar row can occasionally cross 100 dark pixels; the canvas crosses
    # 10% of the screenshot width immediately and then stays dense.
    rows = np.flatnonzero((gray < 100).sum(axis=1) > max(200, gray.shape[1] // 10))
    if rows.size == 0:
        raise ValueError("could not locate the top edge of the canvas")
    top = max(0, int(rows[0]) - 1)

    # Select the longest column run containing the black/white dot field.
    below_top = gray[top + 1 :]
    canvas_counts = (below_top < 245).sum(axis=0)
    left, right = longest_run(np.flatnonzero(canvas_counts > 0.8 * below_top.shape[0]))

    scale = (right - left) / CANVAS_WIDTH
    available_height = min(CANVAS_HEIGHT, int((gray.shape[0] - top) / scale))

    # Sample original canvas-pixel centres from the browser-scaled screenshot.
    xs = np.rint(left + (np.arange(CANVAS_WIDTH) + 0.5) * scale - 0.5).astype(int)
    ys = np.rint(top + (np.arange(available_height) + 0.5) * scale - 0.5).astype(int)
    xs = np.clip(xs, 0, gray.shape[1] - 1)
    ys = np.clip(ys, 0, gray.shape[0] - 1)

    print(
        f"Canvas bounds: x=[{left}, {right}), y={top}; "
        f"scale={scale:.6f}; recovered size={CANVAS_WIDTH}x{available_height}"
    )
    return gray[np.ix_(ys, xs)]


def box_mean(array: np.ndarray, radius: int) -> np.ndarray:
    padded = np.pad(array, ((radius, radius), (radius, radius)), mode="reflect")
    integral = np.pad(padded, ((1, 0), (1, 0)), mode="constant").cumsum(0).cumsum(1)
    size = 2 * radius + 1
    return (
        integral[size:, size:]
        - integral[:-size, size:]
        - integral[size:, :-size]
        + integral[:-size, :-size]
    ) / (size * size)


def carrier_score(dots: np.ndarray) -> np.ndarray:
    """Make a coarse text mask from the two different six-pixel phases."""
    height, width = dots.shape

    phase = np.exp(-2j * np.pi * np.arange(height)[:, None] / CELL_SIZE)
    carrier = dots * phase

    border = np.zeros((height, width), dtype=bool)
    border[:40, :] = True
    border[-40:, :] = True
    border[:, :40] = True
    border[:, -40:] = True
    background_phase = carrier[border].mean()

    local_phase = box_mean(carrier, radius=24)
    return box_mean(np.abs(local_phase - background_phase), radius=9)


def find_vertical_shift(field: np.ndarray) -> tuple[int, np.ndarray, np.ndarray]:
    """Find the second atlas copy by circular correlation along the y axis."""
    height, width = field.shape
    padded = np.zeros((CANVAS_HEIGHT, width), dtype=np.float64)
    padded[:height, :] = field

    output_x = np.arange(width)
    atlas_x = (output_x - SIGNAL_X_OFFSET) % ATLAS_WIDTH
    mapped = atlas_x < width
    output_x = output_x[mapped]
    atlas_x = atlas_x[mapped]

    left_fft = np.fft.fft(padded[:, output_x], axis=0)
    right_fft = np.fft.fft(padded[:, atlas_x], axis=0)
    correlation = np.fft.ifft(np.conj(left_fft) * right_fft, axis=0).real.sum(axis=1)
    shift = int(np.argmax(correlation))
    print(f"Matched atlas vertical shift: {shift}/{CANVAS_HEIGHT} pixels")
    return shift, padded, mapped


def recover_visual(canvas: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    dots = (canvas < 100).astype(np.float64)
    height, _width = dots.shape
    coarse = carrier_score(dots)

    # The frontend draws the message using a second view of the same random atlas:
    # x is offset by 294 pixels and y moves in the opposite direction. Once that
    # circular y shift is found, local equality reveals sharper glyph shapes.
    field = np.where(dots > 0, 1.0, -1.0)
    shift, padded, mapped_x = find_vertical_shift(field)

    valid_pixels = np.zeros_like(padded)
    valid_pixels[:height, :] = 1.0
    output_x = np.flatnonzero(mapped_x)
    atlas_x = ((output_x - SIGNAL_X_OFFSET) % ATLAS_WIDTH).astype(int)
    mapped_y = (np.arange(CANVAS_HEIGHT) + shift) % CANVAS_HEIGHT

    equality = np.zeros_like(padded)
    weights = np.zeros_like(padded)
    equality[:, output_x] = padded[:, output_x] * padded[mapped_y[:, None], atlas_x[None, :]]
    weights[:, output_x] = (
        valid_pixels[:, output_x] * valid_pixels[mapped_y[:, None], atlas_x[None, :]]
    )
    exact = box_mean(equality, radius=5) / np.maximum(box_mean(weights, radius=5), 0.01)
    exact = exact[:height, :]

    # Phase is robust but blurry; atlas matching is sharp but noisy. Their product
    # keeps the sharp evidence only where the coarse phase map says text exists.
    rendered = np.clip((exact - 0.40) / 0.60, 0.0, 1.0)
    rendered *= np.clip((coarse - 0.025) / 0.035, 0.0, 1.0)
    rendered[:, ~mapped_x] = np.clip((coarse[:, ~mapped_x] - 0.03) / 0.07, 0.0, 1.0)

    region = coarse > 0.06
    region[:25, :] = False
    region[-25:, :] = False
    region[:, :25] = False
    region[:, -25:] = False
    return rendered, region


def save_cropped_visual(rendered: np.ndarray, region: np.ndarray, output: Path) -> None:
    ys, xs = np.nonzero(region)
    if xs.size == 0:
        raise ValueError("the recovered mask is empty")

    padding = 30
    x0 = max(0, int(xs.min()) - padding)
    x1 = min(region.shape[1], int(xs.max()) + padding + 1)
    y0 = max(0, int(ys.min()) - padding)
    y1 = min(region.shape[0], int(ys.max()) + padding + 1)
    cropped = np.rint(rendered[y0:y1, x0:x1] * 255).astype(np.uint8)
    Image.fromarray(cropped, mode="L").save(output)
    print(f"Decoded mask: {output} ({cropped.shape[1]}x{cropped.shape[0]})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", type=Path, default=Path("ghost_screenshot.png"))
    parser.add_argument("-o", "--output", type=Path, default=Path("ghost_decoded.png"))
    args = parser.parse_args()

    inspect_png(args.input)
    canvas = normalize_canvas(Image.open(args.input))
    rendered, region = recover_visual(canvas)
    save_cropped_visual(rendered, region, args.output)


if __name__ == "__main__":
    main()
