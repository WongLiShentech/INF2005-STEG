"""WAV/PCM loading and saving, and the flat carrier array the codec works on.

This mirrors image_helpers.py exactly: load the media, expose a flat NumPy
array of integer carrier units, and save it back. Every bit-level operation
lives in stego_utils.py and is shared with the image path unchanged.
"""

import wave
from pathlib import Path

import numpy as np

MEDIA_TYPE = "audio/wav"

# Anything lossy discards the low bits we hide in, so protected output is
# restricted to formats that store sample values exactly.
LOSSLESS_SUFFIXES = {".wav"}

# One unsigned NumPy dtype per PCM sample width. The carrier is always read
# as *unsigned* little-endian: LSB replacement only ever touches the low bits,
# and reinterpreting the same bytes as unsigned keeps the masking arithmetic
# in stego_utils.py identical for image and audio. 16-bit PCM is signed on
# disk, but .view() reinterprets the bytes rather than converting them, so the
# values written back are bit-for-bit what we read.
SAMPLE_DTYPES = {
    1: np.dtype("u1"),  # 8-bit PCM is unsigned on disk already
    2: np.dtype("<u2"),  # 16-bit PCM, the common case
    4: np.dtype("<u4"),  # 32-bit PCM
}


class AudioCarrier:
    media_type = MEDIA_TYPE

    def __init__(self, samples, n_channels, sample_width, frame_rate, n_frames):
        self.samples = samples
        self.carrier = samples.reshape(-1)
        self.n_channels = n_channels
        self.sample_width = sample_width
        self.frame_rate = frame_rate
        self.n_frames = n_frames
        # Read from the container itself, never from the filename: one of our
        # test cases emails the file to another party, and downloads are
        # frequently renamed. Mirrors the image seed in shape and purpose.
        self.seed = f"{n_frames}x{n_channels}x{sample_width}"

    def describe(self):
        seconds = self.n_frames / self.frame_rate if self.frame_rate else 0
        channels = "mono" if self.n_channels == 1 else f"{self.n_channels} channels"
        return (
            f"{seconds:.1f}s WAV, {self.frame_rate:,} Hz, {channels}, "
            f"{self.sample_width * 8}-bit, {len(self.carrier):,} carrier values"
        )

    def save(self, path):
        if Path(path).suffix.lower() not in LOSSLESS_SUFFIXES:
            raise ValueError(
                f"refusing to write {Path(path).suffix}: lossy formats destroy the payload"
            )
        with wave.open(str(path), "wb") as out:
            out.setnchannels(self.n_channels)
            out.setsampwidth(self.sample_width)
            out.setframerate(self.frame_rate)
            out.writeframes(self.samples.tobytes())


def load(path):
    with wave.open(str(path), "rb") as source:
        n_channels = source.getnchannels()
        sample_width = source.getsampwidth()
        frame_rate = source.getframerate()
        n_frames = source.getnframes()

        if sample_width not in SAMPLE_DTYPES:
            raise ValueError(
                f"{sample_width * 8}-bit PCM is not supported. "
                "Use 8, 16 or 32-bit WAV/PCM: 24-bit has no native integer width, "
                "so its samples cannot be addressed as whole carrier units."
            )

        frames = source.readframes(n_frames)

    # np.frombuffer gives a read-only view of immutable bytes; the codec writes
    # into the carrier in place, so take an owned, writable copy.
    samples = np.frombuffer(frames, dtype=SAMPLE_DTYPES[sample_width]).copy()
    return AudioCarrier(samples, n_channels, sample_width, frame_rate, n_frames)
