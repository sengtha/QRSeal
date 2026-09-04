#!/usr/bin/env python3
"""
Redact a screen capture before it is committed as evidence.

Covers the given rectangles with solid boxes and optionally crops, then writes
the result. The original is never modified and is not meant to be committed.

Why a script and not an image editor: the rectangles are recorded in
docs/evidence/README.md next to each file, so anyone holding the original can
reproduce the committed file exactly and confirm that nothing else was touched.

Usage:
  python3 tools/redact-capture.py --in original.png --out docs/evidence/name.png \
      --cover 812,1195,300,300 --cover 815,1150,240,40 \
      --crop 0,120,1080,1620 --label "payment QR" --label "payee name"

Coordinates are pixels in the ORIGINAL image, x,y,w,h, measured before any
crop. --label entries pair with --cover entries in order and are drawn on the
box so a reader can see what was covered and why, not just that something was.

Requires Pillow:  pip install Pillow
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    sys.exit("Pillow is required: pip install Pillow")


def rect(spec: str) -> tuple[int, int, int, int]:
    parts = [int(p) for p in spec.split(",")]
    if len(parts) != 4 or parts[2] <= 0 or parts[3] <= 0:
        raise argparse.ArgumentTypeError(f"expected x,y,w,h with positive w,h: {spec!r}")
    return parts[0], parts[1], parts[2], parts[3]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="src", required=True, type=Path)
    ap.add_argument("--out", dest="dst", required=True, type=Path)
    ap.add_argument("--cover", action="append", default=[], type=rect, metavar="x,y,w,h",
                    help="rectangle to cover, in original-image pixels; repeatable")
    ap.add_argument("--label", action="append", default=[], metavar="TEXT",
                    help="label for the matching --cover, in order; repeatable")
    ap.add_argument("--crop", type=rect, metavar="x,y,w,h", help="crop applied after covering")
    args = ap.parse_args()

    if args.label and len(args.label) != len(args.cover):
        sys.exit(f"{len(args.label)} labels for {len(args.cover)} covers; give one per cover or none")

    img = Image.open(args.src).convert("RGB")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 18)
    except OSError:
        font = ImageFont.load_default()

    for i, (x, y, w, h) in enumerate(args.cover):
        draw.rectangle([x, y, x + w, y + h], fill=(0, 0, 0))
        label = f"redacted: {args.label[i]}" if args.label else "redacted"
        # Draw the label only if the box can hold it; a tiny box stays a plain box.
        tw = draw.textlength(label, font=font)
        if w > tw + 12 and h > 26:
            draw.text((x + 6, y + 4), label, fill=(255, 255, 255), font=font)

    if args.crop:
        x, y, w, h = args.crop
        img = img.crop((x, y, x + w, y + h))

    args.dst.parent.mkdir(parents=True, exist_ok=True)
    img.save(args.dst, optimize=True)
    covered = ", ".join(f"({x},{y},{w},{h})" for x, y, w, h in args.cover) or "nothing"
    print(f"wrote {args.dst}  covered {covered}" + (f"  cropped {args.crop}" if args.crop else ""))


if __name__ == "__main__":
    main()
