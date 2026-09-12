"""Regenerate every sample file in testFiles/ and write a run log to evidence/.

Run this whenever the payload format, the key derivation or the demo message
text changes, so the committed samples always match the current code:

    python make_demo_files.py

Each case below is one of the positive or negative cases in the demo plan. The
log it prints is the reproducible record of what the marker will see live.
"""

import tempfile
import wave
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from PIL import Image

import attacks
import security
import workflow

ROOT = Path(__file__).parent
ORIGINAL = ROOT / "testFiles" / "original"
PROTECTED = ROOT / "testFiles" / "protected"
TAMPERED = ROOT / "testFiles" / "tampered"
EVIDENCE = ROOT / "evidence"

KEY = b"team demo key"
PRIVATE = ROOT / "keys" / "demo_private.pem"
PUBLIC = ROOT / "keys" / "demo_public.pem"
STRANGER = ROOT / "keys" / "other_public.pem"

# Section 5 asks for three message sizes: a short one, a long one, and a
# custom one whose confidentiality and integrity the team protects.
SHORT = b"Apply hashing to generate integrity fingerprints for media files or verification payloads."

LARGE = (
    b"This undergraduate project requires student teams to design, implement and demonstrate "
    b"a GUI-based LSB Replacement steganography program (window-based or web-based) that "
    b"protects and verifies both image and audio cover objects using steganography, hashing "
    b"and digital signatures. The project focuses on practical cybersecurity concepts: hiding "
    b"a verification payload inside an image and an audio file, signing relevant verification "
    b"data, extracting the hidden payload, checking the digital signature, and demonstrating "
    b"positive and negative verification cases."
)

CUSTOM = (
    b"RELEASE AUTHORISATION\n"
    b"Asset: quarterly-results-briefing\n"
    b"Cleared by: media desk\n"
    b"Embargo: not for distribution before the published date\n"
    b"This block is encrypted at rest inside the cover object."
)

log_lines = []


def log(line=""):
    print(line)
    log_lines.append(line)


def make_cover_image(path, width=420, height=320):
    """A smooth gradient with texture. Flat colour would make LSB changes
    easier to see than a real photograph would."""
    rng = np.random.default_rng(seed=20260911)
    ys, xs = np.mgrid[0:height, 0:width]
    red = (40 + 180 * xs / width).astype(np.float64)
    green = (60 + 150 * ys / height).astype(np.float64)
    blue = (200 - 120 * (xs + ys) / (width + height)).astype(np.float64)
    pixels = np.stack([red, green, blue], axis=-1)
    pixels += rng.normal(0, 6, size=pixels.shape)
    Image.fromarray(np.clip(pixels, 0, 255).astype(np.uint8), "RGB").save(path)
    return path


def make_cover_audio(path, seconds=6, rate=44100, channels=2):
    """A short two-channel tone with harmonics and a fade, so the hiss that
    appears at high LSB depth is audible against something musical."""
    frames = rate * seconds
    t = np.arange(frames) / rate
    left = 0.35 * np.sin(2 * np.pi * 220 * t) + 0.18 * np.sin(2 * np.pi * 440 * t)
    right = 0.32 * np.sin(2 * np.pi * 277 * t) + 0.16 * np.sin(2 * np.pi * 554 * t)
    envelope = np.minimum(1.0, np.minimum(t * 4, (seconds - t) * 4))

    interleaved = np.empty(frames * channels)
    interleaved[0::2] = left * envelope
    interleaved[1::2] = right * envelope
    samples = np.clip(interleaved * 28000, -32768, 32767).astype("<i2")

    with wave.open(str(path), "wb") as out:
        out.setnchannels(channels)
        out.setsampwidth(2)
        out.setframerate(rate)
        out.writeframes(samples.tobytes())
    return path


def make_small_cover(path):
    """Deliberately too small to hold a large payload, for the capacity case."""
    rng = np.random.default_rng(seed=3)
    pixels = rng.integers(0, 256, size=(48, 48, 3), dtype=np.uint8)
    Image.fromarray(pixels, "RGB").save(path)
    return path


def verdict_of(path, key=KEY, public_key_path=PUBLIC):
    return workflow.verify(path, key, security.load_public_key(public_key_path))


def report(case, path, result, expected):
    status = "OK " if result.verdict == expected else "!! "
    log(f"{status}{case}")
    log(f"     file      {Path(path).relative_to(ROOT)}")
    log(f"     verdict   {result.verdict}   (expected {expected})")
    log(f"     reason    {result.explanation}")
    for check in result.checks:
        log(f"       {'PASS' if check['ok'] else 'FAIL'}  {check['label']}: {check['detail']}")
    log()
    return result.verdict == expected


def main():
    for folder in (ORIGINAL, PROTECTED, TAMPERED, EVIDENCE):
        folder.mkdir(parents=True, exist_ok=True)

    private_key = security.load_private_key(PRIVATE)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    log("INF2005 ACW1 demo sample generation")
    log(f"Generated {stamp}")
    log(f"Derivation passphrase: {KEY.decode()!r}")
    log("=" * 72)
    log()

    cover_png = make_cover_image(ORIGINAL / "cover.png")
    cover_wav = make_cover_audio(ORIGINAL / "cover.wav")
    small_png = make_small_cover(ORIGINAL / "small_cover.png")
    log(f"Cover image  {workflow.load_media(cover_png).describe()}")
    log(f"Cover audio  {workflow.load_media(cover_wav).describe()}")
    log(f"Small cover  {workflow.load_media(small_png).describe()}")
    log()
    log("=" * 72)
    log()

    passed = []

    # P1 - image, short message, depth 2, plaintext.
    p1 = PROTECTED / "P1_image_short_n2.png"
    r = workflow.protect(cover_png, p1, SHORT, "learning-outcome.txt", KEY, 2, private_key)
    log(f"P1 protect: offset {r.offset:,}, {r.bytes_used:,} of {r.capacity:,} bytes at 2 LSB")
    passed.append(report("P1  image, short message, authentic", p1, verdict_of(p1), workflow.AUTHENTIC))

    # P2 - audio, large message, depth 4, plaintext. Different depth from P1
    # so the demo shows the selector actually changing the embedding.
    p2 = PROTECTED / "P2_audio_large_n4.wav"
    r = workflow.protect(cover_wav, p2, LARGE, "project-overview.txt", KEY, 4, private_key)
    log(f"P2 protect: offset {r.offset:,}, {r.bytes_used:,} of {r.capacity:,} bytes at 4 LSB")
    passed.append(report("P2  audio, large message, authentic", p2, verdict_of(p2), workflow.AUTHENTIC))

    # P3 - the custom payload, encrypted. Confidentiality as well as integrity.
    p3 = PROTECTED / "P3_image_custom_encrypted_n3.png"
    r = workflow.protect(
        cover_png, p3, CUSTOM, "release-authorisation.txt", KEY, 3, private_key, encrypt=True
    )
    log(f"P3 protect: offset {r.offset:,}, {r.plaintext_len:,} bytes in, {r.bytes_used:,} stored")
    passed.append(report("P3  image, custom encrypted payload, authentic", p3, verdict_of(p3), workflow.AUTHENTIC))

    # P4 - the same, on audio, so both cover objects show every feature.
    p4 = PROTECTED / "P4_audio_custom_encrypted_n2.wav"
    workflow.protect(
        cover_wav, p4, CUSTOM, "release-authorisation.txt", KEY, 2, private_key, encrypt=True
    )
    passed.append(report("P4  audio, custom encrypted payload, authentic", p4, verdict_of(p4), workflow.AUTHENTIC))

    log("=" * 72)
    log()

    # N1 - media edited after protection. Signature still valid; hash is not.
    outcome = attacks.run(attacks.BY_KEY["edit_media"], p1, KEY, security.load_public_key(PUBLIC), TAMPERED)
    n1 = TAMPERED / "N1_image_edited.png"
    Path(outcome.path).replace(n1)
    passed.append(report("N1  image edited outside the payload region", n1, verdict_of(n1), workflow.TAMPERED))

    # N2 - the right file, the wrong signer.
    passed.append(report(
        "N2  audio verified against a stranger's public key",
        p2, verdict_of(p2, public_key_path=STRANGER), workflow.SIGNATURE_INVALID,
    ))

    # N3 - payload larger than the cover can hold, refused before writing.
    log("OK N3  oversized payload blocked before embedding")
    log(f"     file      {small_png.relative_to(ROOT)}")
    try:
        workflow.protect(small_png, TAMPERED / "N3_never_written.png", LARGE, "x.txt", KEY, 1, private_key)
        log("     !! embedding was NOT blocked")
        passed.append(False)
    except workflow.CapacityError as exc:
        log(f"     verdict   refused   (expected refusal)")
        log(f"     reason    {exc}")
        log(f"     written   no output file was created")
        passed.append(True)
    log()

    # N4 - the wrong passphrase looks in the wrong place.
    passed.append(report(
        "N4  image opened with the wrong passphrase",
        p1, verdict_of(p1, key=b"the wrong key"), workflow.WRONG_START_LOCATION,
    ))

    # N5 - a cover that was never protected.
    passed.append(report("N5  unprotected audio", cover_wav, verdict_of(cover_wav), workflow.PAYLOAD_MISSING))

    # N6 - payload bytes themselves altered.
    outcome = attacks.run(attacks.BY_KEY["corrupt_record"], p2, KEY, security.load_public_key(PUBLIC), TAMPERED)
    n6 = TAMPERED / "N6_audio_payload_bits_flipped.wav"
    Path(outcome.path).replace(n6)
    passed.append(report("N6  audio payload bytes altered", n6, verdict_of(n6), workflow.SIGNATURE_INVALID))

    # N7 - not a media file at all, wearing a .png name.
    n7 = TAMPERED / "N7_not_an_image.png"
    n7.write_bytes(b"This is a text file that has simply been renamed. " * 8)
    passed.append(report("N7  a non-media file renamed to .png", n7, verdict_of(n7), workflow.CANNOT_VERIFY))

    # N8 - replay. A genuine, correctly signed payload moved into another
    # cover. Nothing is forged, and only the media hash notices.
    outcome = attacks.run(
        attacks.BY_KEY["transplant"], p1, KEY, security.load_public_key(PUBLIC), TAMPERED,
        target_path=cover_wav,
    )
    n8 = TAMPERED / "N8_audio_replayed_payload.wav"
    Path(outcome.path).replace(n8)
    passed.append(report("N8  a genuine payload replayed into another cover", n8, verdict_of(n8), workflow.TAMPERED))

    log("=" * 72)
    log("Attack simulation against P3 (encrypted image)")
    log()
    # The attacked copies are scratch: the log below is the evidence, and every
    # file is regenerable by re-running this script. Writing them into
    # evidence/ would bury the log under artefacts nobody reads.
    with tempfile.TemporaryDirectory() as scratch:
        simulated = attacks.run_all(
            p3, KEY, security.load_public_key(PUBLIC), scratch, target_path=cover_wav
        )
        for outcome in simulated:
            if not outcome.ran:
                log(f"-- {outcome.attack.label}: skipped, {outcome.note}")
                continue
            mark = "OK " if outcome.as_expected else "!! "
            log(f"{mark}{outcome.attack.label}")
            log(f"     did       {outcome.note}")
            log(f"     verdict   {outcome.verdict}   (predicted {outcome.expected})")
            if outcome.caveat:
                log(f"     caveat    {outcome.caveat}")
            log()
            passed.append(outcome.as_expected)

    log("=" * 72)
    log(f"{sum(passed)} of {len(passed)} cases produced the expected verdict")

    (EVIDENCE / "demo_run_log.txt").write_text("\n".join(log_lines), encoding="utf-8")
    print(f"\nWrote {EVIDENCE / 'demo_run_log.txt'}")
    return 0 if all(passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
