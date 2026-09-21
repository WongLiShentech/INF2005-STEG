"""Sanity checks for the failures that are expensive to discover during the demo."""

import hashlib
import io
import os
import re
import wave

import numpy as np
import pytest
from PIL import Image

import app as application
import attacks
import audio_helpers
import image_helpers
import security
import stego_utils as su
import video_helpers
import workflow

KEY = b"demo derivation key"


def make_carrier(size=20000, dtype=np.uint8):
    rng = np.random.default_rng(seed=1)
    high = np.iinfo(dtype).max
    return rng.integers(0, high, size=size, dtype=dtype)


@pytest.mark.parametrize("lsb_n", range(1, 9))
@pytest.mark.parametrize("dtype", [np.uint8, np.uint16])
def test_bits_round_trip_at_every_depth(lsb_n, dtype):
    carrier = make_carrier(dtype=dtype)
    data = bytes(range(256)) * 3

    su.embed(carrier, 500, data, lsb_n)
    assert su.extract(carrier, 500, len(data), lsb_n) == data


# n = 8 is excluded: on a uint8 carrier every bit becomes a payload bit,
# so there is nothing above the LSB region left to compare.
@pytest.mark.parametrize("lsb_n", range(1, 8))
def test_embedding_only_touches_the_low_bits(lsb_n):
    carrier = make_carrier()
    before = carrier.copy()

    su.embed(carrier, 100, b"a secret message", lsb_n)

    assert np.array_equal(before >> np.uint8(lsb_n), carrier >> np.uint8(lsb_n))


def test_header_round_trip():
    raw = su.build_header(lsb_n=3, flags=su.FLAG_ENCRYPTED, payload_len=412, sig_len=256)
    assert len(raw) == su.HEADER_SIZE

    fields = su.parse_header(raw)
    assert fields["version"] == su.VERSION
    assert fields["lsb_n"] == 3
    assert fields["flags"] == su.FLAG_ENCRYPTED
    assert fields["payload_len"] == 412
    assert fields["sig_len"] == 256


def test_header_rejects_foreign_bytes():
    assert su.parse_header(b"\x00" * su.HEADER_SIZE) is None
    assert su.parse_header(b"too short") is None


def test_header_survives_the_carrier_at_one_lsb():
    carrier = make_carrier()
    raw = su.build_header(lsb_n=5, flags=0, payload_len=1000, sig_len=256)

    su.embed(carrier, 42, raw, 1)
    assert su.parse_header(su.extract(carrier, 42, su.HEADER_SIZE, 1)) is not None


def test_offset_is_deterministic_and_key_dependent():
    seed = "800x600x3"
    units = 1_440_000

    first = su.derive_offset(b"team key", seed, units)
    assert first == su.derive_offset(b"team key", seed, units)
    assert first != su.derive_offset(b"other key", seed, units)
    assert 0 <= first < units // 2


def test_offset_does_not_depend_on_payload_size():
    """The verifier derives the offset before it knows the payload length."""
    units = 500_000
    assert su.derive_offset(b"k", "seed", units) == su.derive_offset(b"k", "seed", units)


def test_capacity_shrinks_by_the_offset_and_header():
    units, offset = 100_000, 10_000
    at_one = su.capacity_bytes(units, offset, 1)

    assert at_one == (units - offset - su.HEADER_UNITS) // 8
    assert su.capacity_bytes(units, offset, 2) == at_one * 2
    assert su.capacity_bytes(1000, 990, 1) == 0


def test_canonical_json_ignores_key_order():
    a = {"b": 2, "a": 1, "c": [1, 2]}
    b = {"c": [1, 2], "a": 1, "b": 2}
    assert security.canonical_json(a) == security.canonical_json(b)


def test_masked_hash_is_unchanged_by_embedding():
    """The design decision the whole verification workflow rests on."""
    for lsb_n in range(1, 9):
        carrier = make_carrier()
        before = security.masked_hash(carrier, lsb_n)

        su.embed(carrier, 300, b"payload bytes go here" * 10, lsb_n)

        assert security.masked_hash(carrier, lsb_n) == before


def test_masked_hash_catches_edits_above_the_lsb_region():
    carrier = make_carrier()
    before = security.masked_hash(carrier, 2)

    carrier[9000] ^= np.uint8(0b1000_0000)

    assert security.masked_hash(carrier, 2) != before


def test_sign_and_verify_round_trip():
    key = security.generate_keypair()
    payload = security.build_payload("image/png", "a" * 64, 2, b"hello", "note.txt", False)
    data = security.canonical_json(payload)

    signature = security.sign(key, data)
    assert security.verify(key.public_key(), signature, data)


def test_altered_payload_fails_verification():
    key = security.generate_keypair()
    payload = security.build_payload("image/png", "a" * 64, 2, b"hello", "note.txt", False)
    signature = security.sign(key, security.canonical_json(payload))

    payload["lsb_n"] = 3
    assert not security.verify(key.public_key(), signature, security.canonical_json(payload))


def test_wrong_public_key_fails_verification():
    signer = security.generate_keypair()
    stranger = security.generate_keypair()
    data = security.canonical_json(
        security.build_payload("audio/wav", "b" * 64, 1, b"hi", "note.txt", False)
    )

    signature = security.sign(signer, data)
    assert not security.verify(stranger.public_key(), signature, data)


def test_payload_carries_every_field_fr3_requires():
    payload = security.build_payload("image/png", "c" * 64, 4, b"secret", "msg.txt", True)

    for field in ("media_id", "timestamp", "hash", "nonce", "team", "issuer"):
        assert payload[field]
    assert payload["msg_len"] == 6
    assert payload["msg_encrypted"] is True


# --- image codec and verdict tree ---


@pytest.fixture(scope="module")
def signer():
    return security.generate_keypair()


@pytest.fixture
def cover(tmp_path):
    rng = np.random.default_rng(seed=7)
    pixels = rng.integers(0, 256, size=(150, 200, 3), dtype=np.uint8)
    path = tmp_path / "cover.png"
    Image.fromarray(pixels, "RGB").save(path)
    return path


def protect_to(cover, tmp_path, signer, message=b"a hidden message", lsb_n=2, name="stego.png"):
    out = tmp_path / name
    report = workflow.protect(cover, out, message, "note.txt", KEY, lsb_n, signer)
    return out, report


@pytest.mark.parametrize("lsb_n", range(1, 9))
def test_protected_image_verifies_at_every_depth(cover, tmp_path, signer, lsb_n):
    message = b"the quick brown fox" * 5
    out, _ = protect_to(cover, tmp_path, signer, message, lsb_n)

    result = workflow.verify(out, KEY, signer.public_key())

    assert result.verdict == workflow.AUTHENTIC
    assert result.message == message
    assert result.payload["lsb_n"] == lsb_n


def test_authentic_result_reports_the_signed_record(cover, tmp_path, signer):
    out, report = protect_to(cover, tmp_path, signer)

    result = workflow.verify(out, KEY, signer.public_key())

    assert result.payload["media_id"] == report.payload["media_id"]
    assert result.payload["issuer"] == security.ISSUER
    assert result.payload["timestamp"].endswith("Z")


def test_edit_outside_the_payload_region_is_tampered(cover, tmp_path, signer):
    out, _ = protect_to(cover, tmp_path, signer)

    media = image_helpers.load(out)
    media.carrier[-1] ^= np.uint8(0b1000_0000)
    media.save(out)

    result = workflow.verify(out, KEY, signer.public_key())
    assert result.verdict == workflow.TAMPERED


def test_edit_inside_the_payload_region_is_signature_invalid(cover, tmp_path, signer):
    out, report = protect_to(cover, tmp_path, signer)

    media = image_helpers.load(out)
    media.carrier[report.offset + su.HEADER_UNITS + 5] ^= np.uint8(0b0000_0011)
    media.save(out)

    result = workflow.verify(out, KEY, signer.public_key())
    assert result.verdict == workflow.SIGNATURE_INVALID


def test_wrong_public_key_is_signature_invalid(cover, tmp_path, signer):
    out, _ = protect_to(cover, tmp_path, signer)
    stranger = security.generate_keypair()

    result = workflow.verify(out, KEY, stranger.public_key())
    assert result.verdict == workflow.SIGNATURE_INVALID


def test_wrong_derivation_key_is_wrong_start_location(cover, tmp_path, signer):
    out, _ = protect_to(cover, tmp_path, signer)

    result = workflow.verify(out, b"not the right key", signer.public_key())
    assert result.verdict == workflow.WRONG_START_LOCATION


def test_unprotected_image_is_payload_missing(cover, signer):
    result = workflow.verify(cover, KEY, signer.public_key())
    assert result.verdict == workflow.PAYLOAD_MISSING


def test_reembedding_at_another_depth_is_tampered(cover, tmp_path, signer):
    """A validly signed payload re-embedded at a depth the record does not claim."""
    out, report = protect_to(cover, tmp_path, signer, b"lifted", 2)

    stego = image_helpers.load(out)
    header = su.parse_header(su.extract(stego.carrier, report.offset, su.HEADER_SIZE, 1))
    body_at, message_at = workflow.regions(
        report.offset, 2, header["payload_len"], header["sig_len"]
    )
    body = su.extract(stego.carrier, body_at, header["payload_len"] + header["sig_len"], 2)
    message = su.extract(stego.carrier, message_at, 6, 2)

    deeper = 3
    fresh = image_helpers.load(cover)
    su.embed(
        fresh.carrier,
        report.offset,
        su.build_header(deeper, 0, header["payload_len"], header["sig_len"]),
        1,
    )
    body_at, message_at = workflow.regions(
        report.offset, deeper, header["payload_len"], header["sig_len"]
    )
    su.embed(fresh.carrier, body_at, body, deeper)
    su.embed(fresh.carrier, message_at, message, deeper)

    moved = tmp_path / "moved.png"
    fresh.save(moved)

    result = workflow.verify(moved, KEY, signer.public_key())
    assert result.verdict == workflow.TAMPERED
    assert "re-embedded" in result.explanation


def test_oversized_payload_is_blocked_before_embedding(cover, tmp_path, signer):
    with pytest.raises(workflow.CapacityError) as excinfo:
        workflow.protect(cover, tmp_path / "x.png", b"A" * 200_000, "big.txt", KEY, 1, signer)

    assert "bytes" in str(excinfo.value)


def test_saving_to_a_lossy_format_is_refused(cover, tmp_path, signer):
    with pytest.raises(ValueError):
        workflow.protect(cover, tmp_path / "x.jpg", b"hi", "note.txt", KEY, 2, signer)


def test_resaving_as_jpeg_destroys_the_payload(cover, tmp_path, signer):
    out, _ = protect_to(cover, tmp_path, signer)

    lossy = tmp_path / "stego.jpg"
    with Image.open(out) as img:
        img.save(lossy, quality=90)

    result = workflow.verify(lossy, KEY, signer.public_key())
    assert result.verdict == workflow.PAYLOAD_MISSING


def test_non_media_file_cannot_be_verified(tmp_path, signer):
    path = tmp_path / "notes.txt"
    path.write_text("not a cover object")

    result = workflow.verify(path, KEY, signer.public_key())
    assert result.verdict == workflow.CANNOT_VERIFY


def test_capacity_report_covers_every_depth(cover):
    media = image_helpers.load(cover)
    report = workflow.capacity_report(media, KEY)

    assert report["units"] == 150 * 200 * 3
    assert 0 <= report["offset"] < report["units"] // 2
    assert sorted(report["capacity"]) == list(range(1, 9))
    assert report["capacity"][2] == report["capacity"][1] * 2


# --- web layer ---


@pytest.fixture
def client(cover):
    from app import app

    app.config.update(TESTING=True)
    return app.test_client(), cover.read_bytes()


def post_multipart(client, route, data):
    return client.post(route, data=data, content_type="multipart/form-data")


def test_pages_load(client):
    web, _ = client
    assert web.get("/").status_code == 200
    assert web.get("/verify").status_code == 200


def test_upload_reports_offset_and_every_capacity(client):
    web, image = client

    body = post_multipart(
        web, "/upload", {"file": (io.BytesIO(image), "cover.png"), "key": "k"}
    ).get_json()

    assert 0 <= body["offset"] < body["units"] // 2
    assert sorted(int(n) for n in body["capacity"]) == list(range(1, 9))


def test_protect_then_verify_through_the_web_app(client):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "shared key",
            "lsb_n": "2",
            "message": "a message only the holder of the key can find",
        },
    ).get_data(as_text=True)

    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "stego.png"), "key": "shared key"}
    ).get_data(as_text=True)

    assert workflow.AUTHENTIC in verdict_page
    assert "a message only the holder of the key can find" in verdict_page


def test_web_app_blocks_an_oversized_payload(client):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "k",
            "lsb_n": "1",
            "message": "A" * 200_000,
        },
    ).get_data(as_text=True)

    assert "too large" in page
    assert "stego.png" not in page


def test_web_app_rejects_an_unaccepted_upload(client):
    web, _ = client

    page = post_multipart(
        web, "/protect", {"file": (io.BytesIO(b"nope"), "notes.txt"), "key": "k", "lsb_n": "1"}
    ).get_data(as_text=True)

    assert "not an accepted format" in page


# --- audio codec ---


def write_wav(path, frames, channels=2, width=2, rate=44100, seed=11):
    rng = np.random.default_rng(seed=seed)
    dtype = {1: np.uint8, 2: np.int16, 4: np.int32}[width]
    info = np.iinfo(dtype)
    samples = rng.integers(info.min // 2, info.max // 2, size=frames * channels, dtype=dtype)
    with wave.open(str(path), "wb") as out:
        out.setnchannels(channels)
        out.setsampwidth(width)
        out.setframerate(rate)
        out.writeframes(samples.astype(dtype).tobytes())
    return path


@pytest.fixture
def wav(tmp_path):
    return write_wav(tmp_path / "cover.wav", frames=30000)


def protect_wav(wav, tmp_path, signer, message=b"a hidden message", lsb_n=2, **kwargs):
    out = tmp_path / "stego.wav"
    report = workflow.protect(wav, out, message, "note.txt", KEY, lsb_n, signer, **kwargs)
    return out, report


@pytest.mark.parametrize("width", [1, 2, 4])
def test_every_supported_sample_width_round_trips(tmp_path, signer, width):
    """8, 16 and 32-bit PCM all reduce to an unsigned carrier of that width."""
    source = write_wav(tmp_path / f"cover{width}.wav", frames=30000, width=width)
    out = tmp_path / f"stego{width}.wav"
    workflow.protect(source, out, b"width test", "note.txt", KEY, 2, signer)

    result = workflow.verify(out, KEY, signer.public_key())
    assert result.verdict == workflow.AUTHENTIC
    assert result.message == b"width test"


def test_unsupported_sample_width_is_refused(tmp_path):
    """24-bit has no native integer width, so its samples cannot be addressed."""
    path = tmp_path / "24bit.wav"
    with wave.open(str(path), "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(3)
        out.setframerate(44100)
        out.writeframes(b"\x00\x01\x02" * 1000)

    with pytest.raises(ValueError, match="24-bit"):
        audio_helpers.load(path)


def test_audio_save_preserves_the_container_format(wav, tmp_path, signer):
    out, _ = protect_wav(wav, tmp_path, signer)

    with wave.open(str(wav)) as before, wave.open(str(out)) as after:
        assert after.getnchannels() == before.getnchannels()
        assert after.getsampwidth() == before.getsampwidth()
        assert after.getframerate() == before.getframerate()
        assert after.getnframes() == before.getnframes()


@pytest.mark.parametrize("lsb_n", range(1, 9))
def test_protected_audio_verifies_at_every_depth(wav, tmp_path, signer, lsb_n):
    out, _ = protect_wav(wav, tmp_path, signer, lsb_n=lsb_n)

    result = workflow.verify(out, KEY, signer.public_key())
    assert result.verdict == workflow.AUTHENTIC
    assert result.message == b"a hidden message"


def test_audio_embedding_only_touches_the_low_bits(wav, tmp_path, signer):
    out, _ = protect_wav(wav, tmp_path, signer, lsb_n=2)

    before = audio_helpers.load(wav).carrier
    after = audio_helpers.load(out).carrier
    assert np.array_equal(before >> np.uint16(2), after >> np.uint16(2))


def test_audio_edit_outside_the_payload_region_is_tampered(wav, tmp_path, signer):
    out, _ = protect_wav(wav, tmp_path, signer)

    media = audio_helpers.load(out)
    media.carrier[-50] ^= np.uint16(0b1000_0000)   # above the LSB region
    media.save(out)

    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.TAMPERED


def test_audio_edit_inside_the_payload_region_is_signature_invalid(wav, tmp_path, signer):
    out, report = protect_wav(wav, tmp_path, signer)

    media = audio_helpers.load(out)
    media.carrier[report.offset + su.HEADER_UNITS + 40] ^= np.uint16(1)
    media.save(out)

    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.SIGNATURE_INVALID


def test_audio_wrong_public_key_is_signature_invalid(wav, tmp_path, signer):
    out, _ = protect_wav(wav, tmp_path, signer)
    stranger = security.generate_keypair()

    assert workflow.verify(out, KEY, stranger.public_key()).verdict == workflow.SIGNATURE_INVALID


def test_audio_wrong_derivation_key_is_wrong_start_location(wav, tmp_path, signer):
    out, _ = protect_wav(wav, tmp_path, signer)

    result = workflow.verify(out, b"not the key", signer.public_key())
    assert result.verdict == workflow.WRONG_START_LOCATION


def test_unprotected_audio_is_payload_missing(wav, signer):
    assert workflow.verify(wav, KEY, signer.public_key()).verdict == workflow.PAYLOAD_MISSING


def test_oversized_audio_payload_is_blocked_before_embedding(tmp_path, signer):
    small = write_wav(tmp_path / "small.wav", frames=400, channels=1)
    out = tmp_path / "stego.wav"

    with pytest.raises(workflow.CapacityError):
        workflow.protect(small, out, b"x" * 5000, "big.txt", KEY, 1, signer)

    assert not out.exists()


def test_audio_seed_is_read_from_the_container_not_the_filename(wav, tmp_path, signer):
    """The transfer case renames the file; verification must survive that."""
    out, _ = protect_wav(wav, tmp_path, signer)
    renamed = tmp_path / "downloaded (1).wav"
    renamed.write_bytes(out.read_bytes())

    assert workflow.verify(renamed, KEY, signer.public_key()).verdict == workflow.AUTHENTIC


def test_a_protected_audio_file_must_be_written_as_wav(wav, tmp_path, signer):
    with pytest.raises(ValueError, match=".wav"):
        workflow.protect(wav, tmp_path / "stego.png", b"hi", "n.txt", KEY, 1, signer)


def test_image_and_audio_share_one_codec(wav, cover, tmp_path, signer):
    """Both kinds run the identical embed/verify path; only loading differs."""
    image_out, _ = protect_to(cover, tmp_path, signer, message=b"same message")
    audio_out, _ = protect_wav(wav, tmp_path, signer, message=b"same message")

    for path in (image_out, audio_out):
        result = workflow.verify(path, KEY, signer.public_key())
        assert result.verdict == workflow.AUTHENTIC
        assert result.message == b"same message"


# --- video codec ---


def write_video(path, n_frames=8, width=32, height=24, fps=10, seed=21):
    rng = np.random.default_rng(seed=seed)
    frames = rng.integers(0, 256, size=(n_frames, height, width, 3), dtype=np.uint8)
    video_helpers.VideoCarrier(frames, fps).save(path)
    return path


@pytest.fixture
def video(tmp_path):
    return write_video(tmp_path / "cover.avi")


def protect_video(video, tmp_path, signer, message=b"a hidden message", lsb_n=2, **kwargs):
    out = tmp_path / "stego.avi"
    report = workflow.protect(video, out, message, "note.txt", KEY, lsb_n, signer, **kwargs)
    return out, report


def test_video_frame_stack_round_trips_through_save_and_load(tmp_path):
    """The FFV1 writer must be bit-exact, or embedded bits would not survive
    a save; confirmed once here rather than trusted, per the spike that
    picked FFV1 over HuffYUV, MJPEG and raw AVI in the first place."""
    rng = np.random.default_rng(seed=5)
    frames = rng.integers(0, 256, size=(6, 20, 30, 3), dtype=np.uint8)
    path = tmp_path / "round_trip.avi"
    video_helpers.VideoCarrier(frames, 15).save(path)

    reloaded = video_helpers.load(path)
    assert np.array_equal(reloaded.frames, frames)


@pytest.mark.parametrize("lsb_n", range(1, 9))
def test_protected_video_verifies_at_every_depth(video, tmp_path, signer, lsb_n):
    out, _ = protect_video(video, tmp_path, signer, lsb_n=lsb_n)

    result = workflow.verify(out, KEY, signer.public_key())
    assert result.verdict == workflow.AUTHENTIC
    assert result.message == b"a hidden message"


def test_video_embedding_only_touches_the_low_bits(video, tmp_path, signer):
    out, _ = protect_video(video, tmp_path, signer, lsb_n=2)

    before = video_helpers.load(video).carrier
    after = video_helpers.load(out).carrier
    assert np.array_equal(before >> np.uint8(2), after >> np.uint8(2))


def test_video_edit_outside_the_payload_region_is_tampered(video, tmp_path, signer):
    out, _ = protect_video(video, tmp_path, signer)

    media = video_helpers.load(out)
    media.carrier[-1] ^= np.uint8(0b1000_0000)
    media.save(out)

    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.TAMPERED


def test_video_edit_inside_the_payload_region_is_signature_invalid(video, tmp_path, signer):
    out, report = protect_video(video, tmp_path, signer)

    media = video_helpers.load(out)
    media.carrier[report.offset + su.HEADER_UNITS + 5] ^= np.uint8(0b0000_0011)
    media.save(out)

    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.SIGNATURE_INVALID


def test_video_wrong_public_key_is_signature_invalid(video, tmp_path, signer):
    out, _ = protect_video(video, tmp_path, signer)
    stranger = security.generate_keypair()

    assert workflow.verify(out, KEY, stranger.public_key()).verdict == workflow.SIGNATURE_INVALID


def test_video_wrong_derivation_key_is_wrong_start_location(video, tmp_path, signer):
    out, _ = protect_video(video, tmp_path, signer)

    result = workflow.verify(out, b"not the key", signer.public_key())
    assert result.verdict == workflow.WRONG_START_LOCATION


def test_unprotected_video_is_payload_missing(video, signer):
    assert workflow.verify(video, KEY, signer.public_key()).verdict == workflow.PAYLOAD_MISSING


def test_oversized_video_payload_is_blocked_before_embedding(tmp_path, signer):
    small = write_video(tmp_path / "small.avi", n_frames=2, width=8, height=8)
    out = tmp_path / "stego.avi"

    with pytest.raises(workflow.CapacityError):
        workflow.protect(small, out, b"x" * 5000, "big.txt", KEY, 1, signer)

    assert not out.exists()


def test_video_seed_is_read_from_the_container_not_the_filename(video, tmp_path, signer):
    """The transfer case renames the file; verification must survive that."""
    out, _ = protect_video(video, tmp_path, signer)
    renamed = tmp_path / "downloaded (1).avi"
    renamed.write_bytes(out.read_bytes())

    assert workflow.verify(renamed, KEY, signer.public_key()).verdict == workflow.AUTHENTIC


def test_a_protected_video_file_must_be_written_as_avi(video, tmp_path, signer):
    with pytest.raises(ValueError, match=".avi"):
        workflow.protect(video, tmp_path / "stego.png", b"hi", "n.txt", KEY, 1, signer)


def test_video_preview_is_playable_but_not_bit_exact(video, tmp_path):
    """The preview exists only because no browser can decode FFV1-in-AVI; it
    is lossy by construction (VP8) and must never be mistaken for the
    protected artifact itself. Muxed by a real ffmpeg binary rather than
    cv2.VideoWriter, so its round-trip is verified with cv2 as an
    independent reader, not the same code path that wrote it."""
    carrier = video_helpers.load(video)
    preview = tmp_path / "preview.webm"

    carrier.save_preview(preview)

    assert preview.is_file() and preview.stat().st_size > 0
    reloaded = read_all_frames(preview)
    assert reloaded.shape == carrier.frames.shape
    assert not np.array_equal(reloaded, carrier.frames)  # lossy, as expected


def read_all_frames(path):
    import cv2

    capture = cv2.VideoCapture(str(path))
    frames = []
    try:
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            frames.append(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
    finally:
        capture.release()
    return np.stack(frames)


def test_image_audio_and_video_share_one_codec(wav, cover, video, tmp_path, signer):
    """All three kinds run the identical embed/verify path; only loading differs."""
    image_out, _ = protect_to(cover, tmp_path, signer, message=b"same message")
    audio_out, _ = protect_wav(wav, tmp_path, signer, message=b"same message")
    video_out, _ = protect_video(video, tmp_path, signer, message=b"same message")

    for path in (image_out, audio_out, video_out):
        result = workflow.verify(path, KEY, signer.public_key())
        assert result.verdict == workflow.AUTHENTIC
        assert result.message == b"same message"


def test_web_app_protects_and_verifies_video(client, tmp_path):
    """A protected video must come back as .avi, not as the image default.

    cv2.VideoWriter needs a real file path, unlike the wave module used for
    audio, which can write straight into an in-memory buffer — so the source
    clip is built on disk via tmp_path and read back into bytes.
    """
    web, _ = client
    source = write_video(tmp_path / "cover.avi")
    video_bytes = source.read_bytes()

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(video_bytes), "cover.avi"),
            "key": "shared key",
            "lsb_n": "2",
            "message": "hidden inside a video file",
        },
    ).get_data(as_text=True)

    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.avi)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "stego.avi"), "key": "shared key"}
    ).get_data(as_text=True)

    assert workflow.AUTHENTIC in verdict_page
    assert "hidden inside a video file" in verdict_page


def test_web_app_video_pages_offer_a_playable_preview(client, tmp_path):
    """The compare figures must show a browser-playable preview, but the
    download link and everything verification reads must still be the real
    lossless AVI, never the lossy preview."""
    web, _ = client
    source = write_video(tmp_path / "cover.avi")
    video_bytes = source.read_bytes()

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(video_bytes), "cover.avi"),
            "key": "shared key",
            "lsb_n": "2",
            "message": "hidden inside a video file",
        },
    ).get_data(as_text=True)

    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.avi)", page).group(1)
    preview_url = re.search(r'<video controls src="(/media/[^"]+\.webm)">', page).group(1)
    download_href = re.search(r'<a class="download" href="([^"]+)"', page).group(1)

    assert download_href == f"/media/{stego_name}"  # the real file, not the preview
    assert web.get(preview_url).status_code == 200
    assert web.get(f"/media/{stego_name}").status_code == 200

    stego = web.get(f"/media/{stego_name}").get_data()
    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "stego.avi"), "key": "shared key"}
    ).get_data(as_text=True)
    assert workflow.AUTHENTIC in verdict_page
    assert re.search(r'<video controls src="(/media/[^"]+\.webm)">', verdict_page)


# --- key separation and message encryption ---


def test_subkeys_are_independent_and_deterministic():
    location, message = su.derive_subkeys(KEY)

    assert location != message
    assert len(location) == 32 and len(message) == 32
    assert su.derive_subkeys(KEY) == (location, message)
    assert su.derive_subkeys(b"another passphrase")[0] != location


def test_encrypt_round_trip_and_wrong_key():
    key, stranger = os.urandom(32), os.urandom(32)
    blob = security.encrypt_message(key, b"confidential")

    assert blob != b"confidential"
    assert security.decrypt_message(key, blob) == b"confidential"
    assert security.decrypt_message(stranger, blob) is None


def test_gcm_rejects_a_modified_ciphertext():
    key = os.urandom(32)
    blob = bytearray(security.encrypt_message(key, b"confidential"))
    blob[-1] ^= 0x01                               # corrupt the tag

    assert security.decrypt_message(key, bytes(blob)) is None


def test_encrypted_message_round_trips_through_both_media(wav, cover, tmp_path, signer):
    secret = b"Approved for release by the media desk."

    for path, helper, name in ((cover, image_helpers, "s.png"), (wav, audio_helpers, "s.wav")):
        out = tmp_path / name
        workflow.protect(path, out, secret, "note.txt", KEY, 2, signer, encrypt=True)

        result = workflow.verify(out, KEY, signer.public_key())
        assert result.verdict == workflow.AUTHENTIC
        assert result.message == secret
        assert result.encrypted is True


def read_stored_message(path, report):
    """Everything an attacker gets once they know the start location: the
    bytes sitting in the message region, with no key applied."""
    carrier = workflow.load_media(path).carrier
    payload_len = len(security.canonical_json(report.payload))
    sig_len = report.payload["msg_len"] and 256 or 256
    _, message_at = workflow.regions(report.offset, report.lsb_n, payload_len, sig_len)
    return su.extract(carrier, message_at, report.payload["msg_len"], report.lsb_n)


def test_plaintext_never_appears_in_an_encrypted_carrier(cover, tmp_path, signer):
    """The point of encrypting: finding the hiding place is no longer enough."""
    secret = b"MEETING AT MIDNIGHT BY THE DOCKS"

    plain, plain_report = protect_to(cover, tmp_path, signer, message=secret, name="plain.png")
    assert read_stored_message(plain, plain_report) == secret

    sealed = tmp_path / "sealed.png"
    sealed_report = workflow.protect(
        cover, sealed, secret, "note.txt", KEY, 2, signer, encrypt=True
    )
    stored = read_stored_message(sealed, sealed_report)

    assert secret not in stored
    assert stored != secret
    # And it is genuinely recoverable by the holder of the passphrase.
    _, message_key = su.derive_subkeys(KEY)
    assert security.decrypt_message(message_key, stored) == secret


def test_signed_digest_covers_the_stored_bytes_not_the_plaintext(cover, tmp_path, signer):
    """A plaintext digest in a record that travels in the clear would let a
    short message be recovered by hashing candidates until one matched."""
    secret = b"yes"
    out = tmp_path / "sealed.png"
    report = workflow.protect(cover, out, secret, "note.txt", KEY, 2, signer, encrypt=True)

    assert report.payload["msg_sha256"] != hashlib.sha256(secret).hexdigest()
    assert report.payload["msg_len"] > len(secret)     # nonce and tag included
    assert report.plaintext_len == len(secret)


def test_encryption_is_recorded_in_both_the_header_and_the_signed_record(cover, tmp_path, signer):
    out = tmp_path / "sealed.png"
    report = workflow.protect(cover, out, b"secret", "note.txt", KEY, 2, signer, encrypt=True)

    carrier = image_helpers.load(out).carrier
    header = su.parse_header(su.extract(carrier, report.offset, su.HEADER_SIZE, 1))

    assert header["flags"] & su.FLAG_ENCRYPTED
    assert report.payload["msg_encrypted"] is True


def test_flipping_the_header_encryption_flag_is_tampered(cover, tmp_path, signer):
    """The header is unsigned, so its flag is reconciled with the signed copy."""
    out = tmp_path / "sealed.png"
    report = workflow.protect(cover, out, b"secret", "note.txt", KEY, 2, signer, encrypt=True)

    media = image_helpers.load(out)
    header = su.build_header(report.lsb_n, 0, len(security.canonical_json(report.payload)), 256)
    su.embed(media.carrier, report.offset, header, 1)
    media.save(out)

    result = workflow.verify(out, KEY, signer.public_key())
    assert result.verdict == workflow.TAMPERED
    assert "flag" in result.explanation


def test_an_empty_message_is_never_marked_encrypted(cover, tmp_path, signer):
    out = tmp_path / "empty.png"
    report = workflow.protect(cover, out, b"", "note.txt", KEY, 2, signer, encrypt=True)

    assert report.encrypted is False
    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.AUTHENTIC


# --- the check trail ---


def test_authentic_trail_records_every_check(cover, tmp_path, signer):
    out, _ = protect_to(cover, tmp_path, signer)
    result = workflow.verify(out, KEY, signer.public_key())

    labels = [check["label"] for check in result.checks]
    assert labels == [
        "Container",
        "Start location",
        "Header",
        "Signature",
        "Depth",
        "Encryption flag",
        "Message digest",
        "Media hash",
    ]
    assert all(check["ok"] for check in result.checks)


def test_trail_stops_at_the_first_failure(cover, tmp_path, signer):
    out, _ = protect_to(cover, tmp_path, signer)
    stranger = security.generate_keypair()

    result = workflow.verify(out, KEY, stranger.public_key())

    assert result.checks[-1]["label"] == "Signature"
    assert result.checks[-1]["ok"] is False
    assert all(check["ok"] for check in result.checks[:-1])


def test_trail_shows_both_sides_of_the_hash_comparison(cover, tmp_path, signer):
    out, report = protect_to(cover, tmp_path, signer)
    result = workflow.verify(out, KEY, signer.public_key())

    media_hash = next(c for c in result.checks if c["label"] == "Media hash")
    signed, recomputed = media_hash["compared"]

    assert signed == ("signed", report.payload["hash"])
    assert recomputed[1] == report.payload["hash"]      # both sides, in full, for alignment


def test_decryption_step_appears_only_when_encrypted(cover, tmp_path, signer):
    plain, _ = protect_to(cover, tmp_path, signer, name="plain.png")
    sealed = tmp_path / "sealed.png"
    workflow.protect(cover, sealed, b"secret", "note.txt", KEY, 2, signer, encrypt=True)

    plain_labels = [c["label"] for c in workflow.verify(plain, KEY, signer.public_key()).checks]
    sealed_labels = [c["label"] for c in workflow.verify(sealed, KEY, signer.public_key()).checks]

    assert "Decryption" not in plain_labels
    assert "Decryption" in sealed_labels


# --- web app: audio and encryption ---


def wav_bytes(frames=30000, channels=2, width=2, rate=44100, seed=13):
    rng = np.random.default_rng(seed=seed)
    dtype = {1: np.uint8, 2: np.int16, 4: np.int32}[width]
    info = np.iinfo(dtype)
    samples = rng.integers(info.min // 2, info.max // 2, size=frames * channels, dtype=dtype)
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(channels)
        out.setsampwidth(width)
        out.setframerate(rate)
        out.writeframes(samples.astype(dtype).tobytes())
    return buffer.getvalue()


def test_web_app_protects_and_verifies_audio(client):
    """A protected sound must come back as .wav, not as the image default."""
    web, _ = client
    audio = wav_bytes()

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(audio), "cover.wav"),
            "key": "shared key",
            "lsb_n": "2",
            "message": "hidden inside a sound file",
        },
    ).get_data(as_text=True)

    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.wav)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "stego.wav"), "key": "shared key"}
    ).get_data(as_text=True)

    assert workflow.AUTHENTIC in verdict_page
    assert "hidden inside a sound file" in verdict_page


def test_web_app_round_trips_an_encrypted_message(client):
    web, image = client
    secret = "confidential until the key is supplied"

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "shared key",
            "lsb_n": "2",
            "message": secret,
            "encrypt": "on",
        },
    ).get_data(as_text=True)

    assert "msg_encrypted" in page and "true" in page   # JSON is HTML-escaped in the page

    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "stego.png"), "key": "shared key"}
    ).get_data(as_text=True)

    assert workflow.AUTHENTIC in verdict_page
    assert secret in verdict_page


def test_verify_page_shows_the_check_trail(client):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {"file": (io.BytesIO(image), "cover.png"), "key": "k", "lsb_n": "2", "message": "hi"},
    ).get_data(as_text=True)
    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "stego.png"), "key": "k"}
    ).get_data(as_text=True)

    for label in ("Start location", "Signature", "Message digest", "Media hash"):
        assert label in verdict_page


def test_web_app_reports_encryption_overhead(client):
    web, image = client

    body = post_multipart(
        web, "/upload", {"file": (io.BytesIO(image), "cover.png"), "key": "k"}
    ).get_json()

    assert body["encryption_overhead"] == security.NONCE_BYTES + 16


# --- payload rendering and safe serving ---


def test_payload_type_is_sniffed_from_bytes_not_the_name():
    png = io.BytesIO()
    Image.fromarray(np.zeros((4, 4, 3), dtype=np.uint8), "RGB").save(png, format="PNG")

    assert application.sniff_payload(png.getvalue()) == ("image", "image/png")
    assert application.sniff_payload(wav_bytes(frames=10))[0] == "audio"
    assert application.sniff_payload(b"plain words") == ("text", "text/plain")
    assert application.sniff_payload(b"\x00\x01\x02\xff\xfe") == ("binary", "application/octet-stream")


def test_html_payload_is_never_served_as_markup(client):
    """msg_name travels inside the payload, so it is chosen by whoever
    protected the file. Trusting it to pick a content type would let a hidden
    page run in the verifying browser."""
    web, image = client
    script = b"<html><script>alert(1)</script></html>"

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "k",
            "lsb_n": "2",
            "message_file": (io.BytesIO(script), "note.html"),
        },
    ).get_data(as_text=True)
    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "s.png"), "key": "k"}
    ).get_data(as_text=True)

    payload_url = re.search(r"/payload/([A-Za-z0-9_.]+)", verdict_page).group(0)
    served = web.get(payload_url)

    assert "text/html" not in served.headers["Content-Type"]
    assert served.data == script


def test_an_extracted_image_payload_is_displayed(client):
    """The spec asks the GUI to play or execute the payload, not just find it."""
    web, image = client
    hidden = io.BytesIO()
    Image.fromarray(np.full((8, 8, 3), 120, dtype=np.uint8), "RGB").save(hidden, format="PNG")
    hidden_bytes = hidden.getvalue()

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "k",
            "lsb_n": "4",
            "message_file": (io.BytesIO(hidden_bytes), "secret.png"),
        },
    ).get_data(as_text=True)
    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "s.png"), "key": "k"}
    ).get_data(as_text=True)

    assert workflow.AUTHENTIC in verdict_page
    assert "<img src=\"/payload/" in verdict_page

    payload_url = re.search(r"/payload/([A-Za-z0-9_.]+)", verdict_page).group(0)
    served = web.get(payload_url)
    assert served.headers["Content-Type"].startswith("image/png")
    assert served.data == hidden_bytes


def test_an_extracted_audio_payload_is_playable(client):
    web, image = client
    hidden = wav_bytes(frames=800, channels=1)

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "k",
            "lsb_n": "4",
            "message_file": (io.BytesIO(hidden), "secret.wav"),
        },
    ).get_data(as_text=True)
    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    verdict_page = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "s.png"), "key": "k"}
    ).get_data(as_text=True)

    assert "<audio controls src=\"/payload/" in verdict_page


def test_verify_shows_the_original_beside_the_received_file(client):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {"file": (io.BytesIO(image), "cover.png"), "key": "k", "lsb_n": "2", "message": "hi"},
    ).get_data(as_text=True)
    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    with_original = post_multipart(
        web,
        "/verify",
        {
            "file": (io.BytesIO(stego), "s.png"),
            "original": (io.BytesIO(image), "cover.png"),
            "key": "k",
        },
    ).get_data(as_text=True)
    caption = "<figcaption>Original cover &mdash; before protection</figcaption>"
    assert caption in with_original                  # the figure, not the form label

    # And the verdict must not depend on having it.
    without = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "s.png"), "key": "k"}
    ).get_data(as_text=True)
    assert workflow.AUTHENTIC in without
    assert caption not in without


def test_a_non_media_file_renamed_to_png_is_cannot_verify(tmp_path, signer):
    path = tmp_path / "not_an_image.png"
    path.write_bytes(b"just some text that has been renamed " * 10)

    assert workflow.verify(path, KEY, signer.public_key()).verdict == workflow.CANNOT_VERIFY


def test_every_verdict_category_is_reachable(cover, wav, tmp_path, signer):
    """All six verdicts exist in the code; all six must be demonstrable."""
    seen = set()

    out, report = protect_to(cover, tmp_path, signer)
    seen.add(workflow.verify(out, KEY, signer.public_key()).verdict)                  # Authentic
    seen.add(workflow.verify(out, KEY, security.generate_keypair().public_key()).verdict)
    seen.add(workflow.verify(out, b"wrong", signer.public_key()).verdict)             # Wrong Start
    seen.add(workflow.verify(cover, KEY, signer.public_key()).verdict)                # Missing

    junk = tmp_path / "junk.png"
    junk.write_bytes(b"not an image at all " * 20)
    seen.add(workflow.verify(junk, KEY, signer.public_key()).verdict)                 # Cannot Verify

    media = image_helpers.load(out)
    media.carrier[-20] ^= np.uint8(0b1000_0000)
    media.save(out)
    seen.add(workflow.verify(out, KEY, signer.public_key()).verdict)                  # Tampered

    assert seen == {
        workflow.AUTHENTIC,
        workflow.TAMPERED,
        workflow.SIGNATURE_INVALID,
        workflow.PAYLOAD_MISSING,
        workflow.WRONG_START_LOCATION,
        workflow.CANNOT_VERIFY,
    }


# --- selectable start location ---


def test_a_chosen_offset_is_used_verbatim(cover, tmp_path, signer):
    out = tmp_path / "stego.png"
    report = workflow.protect(cover, out, b"hi", "n.txt", KEY, 2, signer, offset=7777)

    assert report.offset == 7777
    assert workflow.verify(out, KEY, signer.public_key(), offset=7777).verdict == workflow.AUTHENTIC


def test_a_chosen_offset_reaches_past_the_derived_half(cover, tmp_path, signer):
    """The derivation is confined to the first half; choosing is not."""
    units = len(image_helpers.load(cover).carrier)
    late = int(units * 0.75)

    out = tmp_path / "stego.png"
    report = workflow.protect(cover, out, b"hi", "n.txt", KEY, 4, signer, offset=late)

    assert report.offset > units // 2
    assert workflow.verify(out, KEY, signer.public_key(), offset=late).verdict == workflow.AUTHENTIC


def test_the_verifier_must_be_told_a_chosen_offset(cover, tmp_path, signer):
    out = tmp_path / "stego.png"
    workflow.protect(cover, out, b"hi", "n.txt", KEY, 2, signer, offset=7777)

    # Deriving instead of being told looks in the wrong place.
    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.WRONG_START_LOCATION
    assert workflow.verify(out, KEY, signer.public_key(), 7778).verdict == workflow.WRONG_START_LOCATION


def test_a_chosen_offset_is_not_recorded_in_the_payload(cover, tmp_path, signer):
    """It cannot be: the verifier needs it before it can read anything."""
    out = tmp_path / "stego.png"
    report = workflow.protect(cover, out, b"hi", "n.txt", KEY, 2, signer, offset=7777)

    assert "7777" not in security.canonical_json(report.payload).decode()


def test_an_offset_beyond_the_carrier_is_refused(cover, tmp_path, signer):
    units = len(image_helpers.load(cover).carrier)

    with pytest.raises(ValueError, match="start location"):
        workflow.protect(cover, tmp_path / "s.png", b"hi", "n.txt", KEY, 2, signer, offset=units)
    with pytest.raises(ValueError, match="start location"):
        workflow.protect(cover, tmp_path / "s.png", b"hi", "n.txt", KEY, 2, signer, offset=-1)


def test_an_offset_too_late_to_fit_the_payload_is_a_capacity_error(cover, tmp_path, signer):
    units = len(image_helpers.load(cover).carrier)

    with pytest.raises(workflow.CapacityError):
        workflow.protect(cover, tmp_path / "s.png", b"x" * 400, "n.txt", KEY, 1, signer,
                         offset=units - 50)


def test_web_app_round_trips_a_chosen_offset(client):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {
            "file": (io.BytesIO(image), "cover.png"),
            "key": "k",
            "lsb_n": "2",
            "offset": "5000",
            "message": "chosen location",
        },
    ).get_data(as_text=True)
    assert "5,000" in page

    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    good = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "s.png"), "key": "k", "offset": "5000"}
    ).get_data(as_text=True)
    assert workflow.AUTHENTIC in good

    blank = post_multipart(
        web, "/verify", {"file": (io.BytesIO(stego), "s.png"), "key": "k"}
    ).get_data(as_text=True)
    assert workflow.WRONG_START_LOCATION in blank


def test_a_non_numeric_offset_is_rejected(client):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {"file": (io.BytesIO(image), "c.png"), "key": "k", "lsb_n": "2",
         "message": "x", "offset": "halfway"},
    ).get_data(as_text=True)

    assert "whole number" in page


# --- attack simulation module ---


@pytest.fixture
def attacked(cover, tmp_path, signer):
    source = tmp_path / "target.png"
    workflow.protect(cover, source, b"a secret worth protecting", "n.txt", KEY, 2, signer,
                     encrypt=True)
    return source


def test_every_attack_produces_the_verdict_it_predicts(attacked, wav, tmp_path, signer):
    outcomes = attacks.run_all(attacked, KEY, signer.public_key(), tmp_path, target_path=wav)

    assert len(outcomes) == len(attacks.ATTACKS)
    for outcome in outcomes:
        assert outcome.ran, f"{outcome.attack.key} was skipped: {outcome.note}"
        assert outcome.as_expected, (
            f"{outcome.attack.key}: predicted {outcome.expected}, got {outcome.verdict}"
        )


def test_the_attacks_between_them_reach_four_distinct_verdicts(attacked, wav, tmp_path, signer):
    verdicts = {o.verdict for o in attacks.run_all(attacked, KEY, signer.public_key(), tmp_path, wav)}

    assert verdicts == {
        workflow.TAMPERED,
        workflow.SIGNATURE_INVALID,
        workflow.PAYLOAD_MISSING,
        workflow.WRONG_START_LOCATION,
    }


def test_attacks_never_modify_the_file_they_are_given(attacked, wav, tmp_path, signer):
    before = attacked.read_bytes()
    attacks.run_all(attacked, KEY, signer.public_key(), tmp_path, target_path=wav)

    assert attacked.read_bytes() == before


def test_retouching_the_media_leaves_the_signature_valid(attacked, tmp_path, signer):
    """The whole reason a media hash is needed: the signature cannot see this."""
    outcome = attacks.run(attacks.BY_KEY["edit_media"], attacked, KEY, signer.public_key(), tmp_path)
    result = workflow.verify(outcome.path, KEY, signer.public_key())

    assert result.verdict == workflow.TAMPERED
    signature_check = next(c for c in result.checks if c["label"] == "Signature")
    assert signature_check["ok"] is True


def test_a_replayed_payload_is_genuinely_signed_but_still_rejected(attacked, wav, tmp_path, signer):
    """Nothing is forged. The record simply describes a different file."""
    outcome = attacks.run(
        attacks.BY_KEY["transplant"], attacked, KEY, signer.public_key(), tmp_path, target_path=wav
    )
    result = workflow.verify(outcome.path, KEY, signer.public_key())

    assert result.verdict == workflow.TAMPERED
    assert next(c for c in result.checks if c["label"] == "Signature")["ok"] is True
    assert next(c for c in result.checks if c["label"] == "Media hash")["ok"] is False


def test_media_edits_are_invisible_at_full_depth(cover, tmp_path, signer):
    """A real limit, reported rather than hidden: at 8 LSB the masked hash
    covers no bits at all, so it cannot detect an edit."""
    source = tmp_path / "full_depth.png"
    workflow.protect(cover, source, b"x", "n.txt", KEY, 8, signer)

    outcome = attacks.run(attacks.BY_KEY["edit_media"], source, KEY, signer.public_key(), tmp_path)

    assert outcome.expected == workflow.AUTHENTIC
    assert outcome.verdict == workflow.AUTHENTIC
    assert "8 LSB" in outcome.caveat


def test_replay_between_two_protections_of_one_cover_succeeds(cover, tmp_path, signer):
    """Also reported rather than hidden: the record binds to media content,
    not to one instance of it."""
    first, second = tmp_path / "first.png", tmp_path / "second.png"
    workflow.protect(cover, first, b"first", "n.txt", KEY, 2, signer)
    workflow.protect(cover, second, b"second", "n.txt", KEY, 2, signer)

    outcome = attacks.run(
        attacks.BY_KEY["transplant"], first, KEY, signer.public_key(), tmp_path, target_path=second
    )

    assert outcome.verdict == workflow.AUTHENTIC     # the weakness reproduces
    assert "same" in outcome.caveat


def test_attacks_skip_cleanly_when_they_cannot_apply(cover, tmp_path, signer):
    empty = tmp_path / "empty.png"
    workflow.protect(cover, empty, b"", "n.txt", KEY, 2, signer)

    no_message = attacks.run(attacks.BY_KEY["corrupt_message"], empty, KEY, signer.public_key(), tmp_path)
    no_target = attacks.run(attacks.BY_KEY["transplant"], empty, KEY, signer.public_key(), tmp_path)

    assert not no_message.ran and "no message" in no_message.note
    assert not no_target.ran and "second cover" in no_target.note


def test_attacking_an_unprotected_file_reports_that_there_is_nothing_to_attack(cover, tmp_path, signer):
    outcome = attacks.run(attacks.BY_KEY["edit_media"], cover, KEY, signer.public_key(), tmp_path)

    assert not outcome.ran
    assert "no payload" in outcome.note


def test_attack_page_runs_every_attack(client, tmp_path):
    web, image = client

    page = post_multipart(
        web,
        "/protect",
        {"file": (io.BytesIO(image), "c.png"), "key": "k", "lsb_n": "2", "message": "secret"},
    ).get_data(as_text=True)
    stego_name = re.search(r"/media/([A-Za-z0-9_]+_stego\.png)", page).group(1)
    stego = web.get(f"/media/{stego_name}").get_data()

    results = post_multipart(
        web,
        "/attack",
        {
            "file": (io.BytesIO(stego), "s.png"),
            "target": (io.BytesIO(wav_bytes()), "other.wav"),
            "key": "k",
        },
    ).get_data(as_text=True)

    assert "8 of 8 attacks produced" in results
    for attack in attacks.ATTACKS:
        assert attack.label in results


@pytest.fixture
def walkthrough_client(tmp_path, monkeypatch):
    monkeypatch.setattr(application, "WORKSPACE", tmp_path)
    application.app.config.update(TESTING=True)
    return application.app.test_client()


@pytest.mark.parametrize("sample", [
    "image_small.png", "image_medium.png", "image_large.png",
    "audio_short.wav", "audio_medium.wav", "audio_long.wav",
    "video_short.avi", "video_medium.avi", "video_long.avi",
])
def test_walkthrough_sample_round_trip(walkthrough_client, sample):
    web = walkthrough_client
    protected = web.post("/api/protect", data={
        "sample": sample, "key": "walkthrough key", "message": "live message",
        "lsb_n": "2", "encrypt": "on",
    })
    assert protected.status_code == 200, protected.get_data(as_text=True)
    report = protected.get_json()
    assert report["stored_bytes"] == len(b"live message") + 28
    assert report["used_bytes"] <= report["capacity"]
    assert report["changed"] > 0
    assert 0 < report["max_change"] <= 3
    assert report["psnr"] > 0
    assert web.get(report["output"]).status_code == 200
    if report["kind"] == "video":
        # No browser decodes the lossless AVI this tool actually protects,
        # so the walkthrough studio must also offer a playable preview.
        assert report["cover_preview"].endswith(".webm")
        assert report["output_preview"].endswith(".webm")
        assert web.get(report["cover_preview"]).status_code == 200
        assert web.get(report["output_preview"]).status_code == 200
    else:
        assert "cover_preview" not in report
    result = web.post("/api/verify", data={
        "id": report["id"], "key": "walkthrough key",
        "public_key_name": "demo_public.pem",
    }).get_json()
    assert result["verdict"] == workflow.AUTHENTIC
    assert result["message_text"] == "live message"
    assert web.get(result["payload_url"]).data == b"live message"
    assert any(check["label"] == "Decryption" for check in result["checks"])
    manifest = application.WORKSPACE / f"{report['id']}_run.json"
    assert "walkthrough key" not in manifest.read_text()


def test_walkthrough_negative_cases_preserve_protected_file(walkthrough_client):
    web = walkthrough_client
    report = web.post("/api/protect", data={
        "sample": "image_medium.png", "key": "correct", "message": "secret",
        "lsb_n": "2", "encrypt": "on", "offset": "1001",
    }).get_json()
    original = web.get(report["output"]).data
    cases = [
        ("intact", "other_public.pem", "correct", "1001", workflow.SIGNATURE_INVALID),
        ("tampered", "demo_public.pem", "correct", "1001", workflow.TAMPERED),
        ("original", "demo_public.pem", "correct", "1001", workflow.PAYLOAD_MISSING),
        ("intact", "demo_public.pem", "wrong", "1001", workflow.CANNOT_VERIFY),
        ("intact", "demo_public.pem", "correct", "1002", workflow.WRONG_START_LOCATION),
    ]
    for scenario, keyname, passphrase, offset, expected in cases:
        result = web.post("/api/verify", data={
            "id": report["id"], "key": passphrase, "offset": offset,
            "public_key_name": keyname, "scenario": scenario,
        }).get_json()
        assert result["verdict"] == expected
        assert result["payload_url"] is None
        assert web.get(report["output"]).data == original
    assert not list(application.WORKSPACE.glob("*_tampered*"))


def test_walkthrough_plaintext_file_and_metadata(walkthrough_client, cover):
    web = walkthrough_client
    report = web.post("/api/protect", data={
        "file": (io.BytesIO(cover.read_bytes()), "cover.png"),
        "message_file": (io.BytesIO(b"file message"), "message.txt"),
        "key": "k", "offset": "0", "lsb_n": "3",
    }).get_json()
    assert not report["encrypted"]
    assert report["stored_bytes"] == len(b"file message")
    assert report["regions"]["header"] == [0, 103]
    saved = workflow.load_media(application.WORKSPACE / report["output"].split("/")[-1])
    before = workflow.load_media(cover)
    for row in report["rows"]:
        assert row["before"] == int(before.carrier[row["index"]])
        assert row["after"] == int(saved.carrier[row["index"]])
    result = web.post("/api/verify", data={
        "id": report["id"], "key": "k", "offset": "0",
        "public_key_name": "demo_public.pem",
    }).get_json()
    assert result["message_text"] == "file message"
    assert "Decryption" not in [check["label"] for check in result["checks"]]


def test_walkthrough_rejects_paths_and_bad_requests(walkthrough_client):
    web = walkthrough_client
    assert web.post("/api/verify", data={"id": "../keys/demo_private.pem"}).status_code == 400
    assert web.post("/api/protect", data={
        "sample": "../keys/demo_private.pem", "key": "k", "message": "hi",
    }).status_code == 400
    assert web.post("/api/protect", data={
        "sample": "image_small.png", "key": "k", "message": "x" * 20000, "lsb_n": "1",
    }).status_code == 400
    assert not list(application.WORKSPACE.iterdir())
    assert web.post("/api/capacity", headers={"Origin": "https://untrusted.example"}).status_code == 403
    report = web.post("/api/protect", data={
        "sample": "image_small.png", "key": "k", "message": "hi",
    }).get_json()
    for extra in [
        {"public_key_name": "../demo_public.pem"}, {"scenario": "invented"},
    ]:
        response = web.post("/api/verify", data={"id": report["id"], "key": "k", **extra})
        assert response.status_code == 400
    manifest = application.WORKSPACE / f"{report['id']}_run.json"
    import json
    manifest.write_text(json.dumps({"cover": "../outside.png", "output": "valid.png", "depth": 2}))
    assert web.post("/api/verify", data={"id": report["id"], "key": "k"}).status_code == 400


def test_walkthrough_sample_options_and_capacity(walkthrough_client):
    web = walkthrough_client
    options = web.get("/api/options").get_json()
    assert len(options["samples"]) == 9
    assert sum(sample["default"] for sample in options["samples"]) == 3
    capacities = {}
    for sample in options["samples"]:
        assert web.get("/sample/" + sample["name"]).status_code == 200
        result = web.post("/api/capacity", data={
            "sample": sample["name"], "key": "k", "offset": "0",
        }).get_json()
        capacities[sample["name"]] = result["capacity"]["2"]
    assert capacities["image_small.png"] < capacities["image_medium.png"] < capacities["image_large.png"]
    assert capacities["audio_short.wav"] < capacities["audio_medium.wav"] < capacities["audio_long.wav"]
    assert capacities["video_short.avi"] < capacities["video_medium.avi"] < capacities["video_long.avi"]
    assert not list(application.WORKSPACE.iterdir())


def test_walkthrough_home_and_original_pages(walkthrough_client):
    web = walkthrough_client
    assert b"walkthrough.js" in web.get("/").data
    assert b"walkthrough.js" in web.get("/walkthrough").data
    for route in ("/protect", "/verify", "/attack", "/static/walkthrough.css", "/static/walkthrough.js"):
        assert web.get(route).status_code == 200
    limit = application.app.config["MAX_CONTENT_LENGTH"]
    try:
        application.app.config["MAX_CONTENT_LENGTH"] = 16
        result = web.post("/api/protect", data={"message": "x" * 100})
        assert result.status_code == 413
        assert result.is_json
    finally:
        application.app.config["MAX_CONTENT_LENGTH"] = limit


# --- steganalysis ---


@pytest.fixture
def measured(tmp_path, signer):
    """A protected cover plus the measurements taken from it."""
    import steganalysis

    source = tmp_path / "cover.wav"
    write_wav(source, frames=60000)
    out = tmp_path / "stego.wav"
    message = b"a payload large enough to occupy a visible share of the carrier " * 120
    report = workflow.protect(source, out, message, "n.txt", KEY, 2, signer, encrypt=True)
    used = workflow.units_required(
        2, len(security.canonical_json(report.payload)), 256, report.payload["msg_len"]
    )
    data = steganalysis.analyse(
        audio_helpers.load(source).carrier, audio_helpers.load(out).carrier,
        "audio", 2, report.offset, used,
    )
    return data, report, used


def test_analysis_reduces_every_series_to_a_drawable_size(measured):
    """A chart cannot render half a million samples and a browser should not
    be asked to hold them."""
    import steganalysis

    data, _report, _used = measured
    for series in (data["waveform"]["cover"]["high"], data["waveform"]["cover"]["low"],
                   data["difference"]["values"], data["lsb"]["cover"]["values"]):
        assert len(series) == steganalysis.POINTS
    assert len(data["chi"]["stego"]["values"]) == steganalysis.WINDOWS
    assert data["units"] > steganalysis.POINTS * 50


def test_waveform_is_drawn_from_signed_amplitudes(measured):
    """Audio is signed on disk. Drawn as unsigned, silence would appear as a
    full-scale block and the signal would be cut in half at zero."""
    data, _report, _used = measured
    low = data["waveform"]["cover"]["low"]

    assert min(low) < 0                       # the waveform swings below zero
    assert all(-1.01 <= v <= 1.01 for v in low + data["waveform"]["cover"]["high"])


def test_difference_is_zero_outside_the_payload_and_nonzero_inside(measured):
    """The point of the view: nothing outside the payload region was touched."""
    data, _report, _used = measured
    values = data["difference"]["values"]
    start, end = data["region"]
    span = len(values)

    inside = [v for i, v in enumerate(values) if start <= (i + 0.5) / span < end]
    # A bucket straddling either edge of the region genuinely holds changed
    # samples, so the two boundary buckets are excluded rather than asserted
    # to be clean: that overlap is bucketing, not embedding.
    edge = 1.5 / span
    outside = [
        v for i, v in enumerate(values)
        if (i + 0.5) / span < start - edge or (i + 0.5) / span > end + edge
    ]

    assert max(inside) > 0
    assert max(outside) == 0
    assert len(outside) > span // 3
    assert data["difference"]["max"] <= 3       # two low bits at depth 2


def test_difference_agrees_with_a_direct_count(measured, tmp_path):
    data, report, _used = measured
    before = audio_helpers.load(tmp_path / "cover.wav").carrier.astype(np.int64)
    after = audio_helpers.load(report.output_path).carrier.astype(np.int64)

    assert data["difference"]["changed"] == int(np.count_nonzero(before != after))


def test_region_matches_where_the_payload_was_actually_written(measured):
    data, report, used = measured
    start, end = data["region"]

    assert abs(start - report.offset / data["units"]) < 1e-4
    assert abs(end - (report.offset + used) / data["units"]) < 1e-4


def test_chi_square_scores_stay_in_range(measured):
    data, _report, _used = measured
    for side in ("cover", "stego"):
        assert all(0.0 <= v <= 1.0 for v in data["chi"][side]["values"])


def test_detection_is_reported_against_the_cover_as_a_control(measured):
    """This test both misses real payloads and fires on untouched covers, so
    it is never reported as a bare verdict."""
    data, _report, _used = measured
    detection = data["detection"]

    assert detection["separation"] in {"clear", "partial", "none"}
    assert "control_peak" in detection and "stego_peak" in detection
    assert len(detection["note"]) > 60


def test_an_untouched_cover_compared_with_itself_shows_no_difference(tmp_path, signer):
    import steganalysis

    source = tmp_path / "flat.wav"
    write_wav(source, frames=40000)
    carrier = audio_helpers.load(source).carrier

    data = steganalysis.analyse(carrier, carrier.copy(), "audio", 2, 0, 0)

    assert data["difference"]["max"] == 0
    assert data["difference"]["changed"] == 0
    assert data["detection"]["separation"] == "none"


def test_analysis_runs_for_every_cover_kind(tmp_path, cover, signer):
    import steganalysis

    wav_path = tmp_path / "c.wav"
    write_wav(wav_path, frames=40000)
    for source, kind in ((cover, "image"), (wav_path, "audio")):
        out = tmp_path / f"s_{kind}{workflow.STEGO_SUFFIX[kind]}"
        report = workflow.protect(source, out, b"payload " * 400, "n.txt", KEY, 2, signer)
        used = workflow.units_required(
            2, len(security.canonical_json(report.payload)), 256, report.payload["msg_len"]
        )
        data = steganalysis.analyse(
            workflow.load_media(source).carrier, workflow.load_media(out).carrier,
            kind, 2, report.offset, used,
        )
        assert data["kind"] == kind
        assert max(data["difference"]["values"]) > 0


def test_analysis_endpoint_serves_the_measurements(walkthrough_client):
    protected = post_multipart(walkthrough_client, "/api/protect", {
        "sample": "audio_medium.wav", "key": "analysis pass", "lsb_n": "2",
        "message": "a hidden message for the analysis panel",
    }).get_json()

    data = post_multipart(
        walkthrough_client, "/api/analysis", {"id": protected["id"]}
    ).get_json()

    assert data["kind"] == "audio"
    assert len(data["waveform"]["stego"]["high"]) > 100
    assert data["detection"]["separation"] in {"clear", "partial", "none"}


def test_analysis_endpoint_rejects_unknown_and_malformed_runs(walkthrough_client):
    for run_id in ("", "not-hex", "a" * 31, "z" * 32):
        response = post_multipart(walkthrough_client, "/api/analysis", {"id": run_id})
        assert response.status_code == 400

    missing = post_multipart(walkthrough_client, "/api/analysis", {"id": "b" * 32})
    assert missing.status_code == 400


# --- live comparison monitor ---


def test_live_monitor_script_loads_before_the_walkthrough(walkthrough_client):
    """Both scripts are deferred, so document order is execution order: the
    walkthrough can only mount the monitor if it has already been defined."""
    page = walkthrough_client.get("/walkthrough").get_data(as_text=True)

    assert "monitor.js" in page
    assert page.index("monitor.js") < page.index("walkthrough.js")
    assert walkthrough_client.get("/static/monitor.js").status_code == 200


def test_charts_are_drawn_for_audio_runs_only():
    """Image and video runs show only PSNR, values changed and largest
    change; every chart, the live comparison included, is audio-only."""
    import pathlib

    script = (pathlib.Path(__file__).parent / "static" / "walkthrough.js").read_text(encoding="utf-8")

    assert "if(d.kind==='audio')attachCharts(card,d.id);" in script
    assert "charts.insertBefore(monitor.element, charts.firstChild)" in script


@pytest.mark.parametrize("sample, charted", [
    ("audio_short.wav", True),
    ("image_small.png", False),
    ("video_short.avi", False),
])
def test_measurements_are_taken_for_audio_only(walkthrough_client, sample, charted):
    protected = post_multipart(walkthrough_client, "/api/protect", {
        "sample": sample, "key": "kind pass", "lsb_n": "4", "message": "x",
    }).get_json()

    # The three figures every run shows, whatever its kind.
    for figure in ("psnr", "changed", "max_change"):
        assert figure in protected

    response = post_multipart(walkthrough_client, "/api/analysis", {"id": protected["id"]})
    assert (response.status_code == 200) is charted


def test_audio_served_to_the_monitor_is_the_protected_file_itself(walkthrough_client, tmp_path):
    """The monitor compares the two files sample by sample in the browser, so
    what it downloads must be the real protected WAV, byte for byte, and not
    a preview or a re-encoding."""
    protected = post_multipart(walkthrough_client, "/api/protect", {
        "sample": "audio_short.wav", "key": "monitor pass", "lsb_n": "2",
        "message": "compared sample by sample in the browser",
    }).get_json()

    served = walkthrough_client.get(protected["output"]).get_data()
    assert served[:4] == b"RIFF" and served[8:12] == b"WAVE"

    copy = tmp_path / "served.wav"
    copy.write_bytes(served)
    public = security.load_public_key(
        __import__("pathlib").Path(__file__).parent / "keys" / "demo_public.pem"
    )
    assert workflow.verify(copy, b"monitor pass", public).verdict == workflow.AUTHENTIC


def test_eight_bit_audio_waveform_is_centred_on_silence(tmp_path):
    """8-bit PCM is unsigned: silence is 128. Drawn without centring, every
    waveform would sit above its axis and loud passages would be clipped."""
    import steganalysis

    path = tmp_path / "eight.wav"
    rate, frames = 8000, 8000
    tone = (128 + 90 * np.sin(2 * np.pi * 440 * np.arange(frames) / rate)).astype(np.uint8)
    with wave.open(str(path), "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(1)
        out.setframerate(rate)
        out.writeframes(tone.tobytes())

    drawn = steganalysis.waveform(audio_helpers.load(path).carrier, "audio")

    assert min(drawn["low"]) < -0.5 < 0.5 < max(drawn["high"])
    assert abs(max(drawn["high"]) + min(drawn["low"])) < 0.05     # symmetric about zero


def test_eight_bit_audio_distortion_is_large_enough_to_hear(tmp_path, signer):
    """The reason to demo on 8-bit audio: the same depth that is inaudible in
    16-bit moves each sample by a large share of its range."""
    source = tmp_path / "eight.wav"
    write_wav(source, frames=40000, width=1)
    out = tmp_path / "stego.wav"
    workflow.protect(source, out, b"x" * 8000, "n.txt", KEY, 4, signer)

    before = audio_helpers.load(source).carrier.astype(int)
    after = audio_helpers.load(out).carrier.astype(int)

    assert np.abs(after - before).max() == 15              # 15 of a 256-level range
    assert workflow.verify(out, KEY, signer.public_key()).verdict == workflow.AUTHENTIC
