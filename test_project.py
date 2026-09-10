"""Sanity checks for the failures that are expensive to discover during the demo."""

import io
import re

import numpy as np
import pytest
from PIL import Image

import image_helpers
import security
import stego_utils as su
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
