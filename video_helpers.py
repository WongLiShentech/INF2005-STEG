"""Video loading and saving, and the flat carrier array the codec works on.

This mirrors image_helpers.py and audio_helpers.py exactly: load the media,
expose a flat NumPy array of integer carrier units, and save it back. Every
bit-level operation lives in stego_utils.py and is shared with the image and
audio paths unchanged — a stack of video frames flattens into the same 1-D
array an image's pixel grid already does, with frame count standing in as
one more dimension before the flatten.
"""

import subprocess
from pathlib import Path

import cv2
import imageio_ffmpeg
import numpy as np

MEDIA_TYPE = "video/x-msvideo"

# The only format we ever write. FFV1 is a lossless codec — confirmed by a
# round-trip spike to be bit-exact through OpenCV's bundled FFmpeg backend —
# so protected output is restricted to it, exactly as image_helpers.py
# restricts output to PNG/BMP and audio_helpers.py restricts it to WAV.
# Anything lossy here would discard the low bits we hide in.
LOSSLESS_SUFFIXES = {".avi"}
FOURCC = cv2.VideoWriter_fourcc(*"FFV1")

# Input can be a wider set of containers than we ever write: OpenCV's bundled
# FFmpeg backend can decode ordinary MP4/MOV footage. Reading is never
# destructive to a payload — only re-encoding on write would be — so we are
# generous here the same way image_helpers.py accepts JPEG input even though
# it always writes PNG.
READABLE_SUFFIXES = {".avi", ".mp4", ".mov", ".mkv"}

DEFAULT_FPS = 30.0

# A lossy, browser-playable copy for display only — never read back by this
# tool and never what protect()/verify() operate on. No browser decodes
# FFV1-in-AVI (an H.264 spike found the encoder unavailable in OpenCV's
# build entirely; VP8-in-WebM is what every major browser's <video> element
# natively decodes). Muxed by a real ffmpeg binary rather than OpenCV's own
# VideoWriter: a duration-header check found no difference between the two
# for a small test clip, but ffmpeg is the far more battle-tested muxer, and
# this path only has to satisfy a browser, not this tool's own round-trip
# tests, so there is no reason to lean on the less-proven writer here.
PREVIEW_SUFFIX = ".webm"
FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()


class VideoCarrier:
    media_type = MEDIA_TYPE

    def __init__(self, frames, fps, source_format="AVI"):
        self.frames = frames
        self.carrier = frames.reshape(-1)
        self.n_frames, self.height, self.width, self.channels = frames.shape
        self.fps = fps or DEFAULT_FPS
        self.source_format = source_format
        # Read from the container itself, never from the filename: one of our
        # test cases emails the file to another party, and downloads are
        # frequently renamed. Mirrors the image and audio seeds in shape and
        # purpose, with frame count standing in for the extra dimension.
        self.seed = f"{self.n_frames}x{self.width}x{self.height}x{self.channels}"

    def describe(self):
        seconds = self.n_frames / self.fps if self.fps else 0
        return (
            f"{self.width} x {self.height} {self.source_format}, "
            f"{self.n_frames} frames @ {self.fps:.2f} fps, {seconds:.1f}s, "
            f"{len(self.carrier):,} carrier values"
        )

    def save(self, path):
        if Path(path).suffix.lower() not in LOSSLESS_SUFFIXES:
            raise ValueError(
                f"refusing to write {Path(path).suffix}: lossy formats destroy the payload"
            )
        writer = cv2.VideoWriter(str(path), FOURCC, self.fps, (self.width, self.height))
        if not writer.isOpened():
            raise ValueError("could not open a lossless AVI writer for this video")
        try:
            for frame in self.frames:
                writer.write(cv2.cvtColor(frame, cv2.COLOR_RGB2BGR))
        finally:
            writer.release()

    def save_preview(self, path):
        """A lossy WebM/VP8 copy of this exact frame stack, for the browser
        to play. Not the protected artifact — nothing downloads this, and
        nothing verifies against it."""
        command = [
            FFMPEG_EXE, "-y",
            "-f", "rawvideo", "-pix_fmt", "rgb24",
            "-s", f"{self.width}x{self.height}", "-r", f"{self.fps}",
            "-i", "-",
            "-c:v", "libvpx", "-pix_fmt", "yuv420p",
            str(path),
        ]
        result = subprocess.run(command, input=self.frames.tobytes(), capture_output=True)
        if result.returncode != 0 or not Path(path).is_file():
            detail = result.stderr.decode(errors="replace")[-300:]
            raise ValueError(f"could not encode a preview for this video: {detail}")


def load(path):
    suffix = Path(path).suffix.lower()
    if suffix not in READABLE_SUFFIXES:
        raise ValueError(f"{suffix or 'that file'} is not a supported video format")

    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        raise ValueError(f"{suffix} could not be opened as a video")

    frames = []
    try:
        fps = capture.get(cv2.CAP_PROP_FPS) or 0.0
        # CAP_PROP_FRAME_COUNT is unreliable for some containers, so frames
        # are counted by reading until exhaustion rather than trusted from
        # metadata — the same defensive posture audio_helpers.py can skip
        # only because wave.getnframes() is reliable for WAV.
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            # OpenCV decodes as BGR; normalise to RGB to match
            # image_helpers.py's convention, since an extracted payload may
            # itself be a picture served straight from these bytes.
            frames.append(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
    finally:
        capture.release()

    if not frames:
        raise ValueError("no frames could be read from this file")

    stacked = np.ascontiguousarray(np.stack(frames), dtype=np.uint8)
    return VideoCarrier(stacked, fps, source_format=suffix.lstrip(".").upper())
