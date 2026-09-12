"""PNG loading and saving, and the flat carrier array the codec works on."""

from pathlib import Path

import numpy as np
from PIL import Image

MEDIA_TYPE = "image/png"

# Anything lossy discards the low bits we hide in, so protected output is
# restricted to formats that store pixel values exactly.
LOSSLESS_SUFFIXES = {".png", ".bmp"}


class ImageCarrier:
    media_type = MEDIA_TYPE

    def __init__(self, pixels, source_format="PNG"):
        self.pixels = pixels
        self.carrier = pixels.reshape(-1)
        height, width, channels = pixels.shape
        self.height = height
        self.width = width
        self.source_format = source_format
        # Read from the container itself, never from the filename: one of our
        # test cases emails the file to another party, and downloads are
        # frequently renamed.
        self.seed = f"{width}x{height}x{channels}"

    def describe(self):
        return (
            f"{self.width} x {self.height} {self.source_format}, "
            f"{len(self.carrier):,} carrier values"
        )

    def save(self, path):
        if Path(path).suffix.lower() not in LOSSLESS_SUFFIXES:
            raise ValueError(
                f"refusing to write {Path(path).suffix}: lossy formats destroy the payload"
            )
        Image.fromarray(self.pixels, "RGB").save(path)


def load(path):
    with Image.open(path) as img:
        source_format = img.format or "image"
        # Palette ('P') images would have us modify palette indices rather than
        # colours, and some viewers premultiply alpha, silently altering RGBA
        # values. Converting to RGB makes every carrier value a real channel.
        if img.mode != "RGB":
            img = img.convert("RGB")
        pixels = np.array(img, dtype=np.uint8)
    return ImageCarrier(pixels, source_format)
