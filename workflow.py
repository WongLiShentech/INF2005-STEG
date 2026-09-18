"""Protect and verify a cover object end to end, and decide the verdict."""

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

import audio_helpers
import image_helpers
import security
import stego_utils as su
import video_helpers

AUTHENTIC = "Authentic"
TAMPERED = "Tampered"
SIGNATURE_INVALID = "Signature Invalid"
PAYLOAD_MISSING = "Payload Missing"
WRONG_START_LOCATION = "Wrong Start Location"
CANNOT_VERIFY = "Cannot Verify"

IMAGE_SUFFIXES = {".png", ".bmp", ".jpg", ".jpeg"}
AUDIO_SUFFIXES = {".wav"}
VIDEO_SUFFIXES = video_helpers.READABLE_SUFFIXES

# The suffix a protected file must be written with, per cover kind. All three
# are lossless: writing a stego object to a lossy format would discard the
# very bits the payload lives in.
STEGO_SUFFIX = {"image": ".png", "audio": ".wav", "video": ".avi"}

# Hard ceiling on the fallback search, independent of file size.
SCAN_UNIT_CAP = 2_000_000


class CapacityError(Exception):
    pass


class UnsupportedMedia(Exception):
    pass


@dataclass
class Result:
    verdict: str
    explanation: str
    payload: dict = None
    message: bytes = b""
    # The ordered trail of checks that produced the verdict. Each entry is
    # {label, ok, detail}. A verdict on its own asks the reader to trust it;
    # the trail shows the comparison each step actually made.
    checks: list = field(default_factory=list)
    encrypted: bool = False


@dataclass
class ProtectReport:
    output_path: str
    offset: int
    lsb_n: int
    payload: dict = field(default_factory=dict)
    bytes_used: int = 0
    capacity: int = 0
    encrypted: bool = False
    plaintext_len: int = 0


def _check(trail, label, ok, detail, compared=None):
    """Record one check.

    `compared` holds the two values a check weighed against each other, as
    (name, value) pairs. Keeping them apart from the prose lets the interface
    align them character by character, which is the only way a reader spots
    where two digests diverge.
    """
    trail.append({"label": label, "ok": ok, "detail": detail, "compared": compared or []})
    return trail


def _short(digest):
    """Enough of a hash to compare by eye, without filling the page."""
    return f"{digest[:16]}..." if digest else "-"


def media_kind(path):
    """'image', 'audio' or 'video', decided by suffix. Raises for anything else."""
    suffix = Path(path).suffix.lower()
    if suffix in IMAGE_SUFFIXES:
        return "image"
    if suffix in AUDIO_SUFFIXES:
        return "audio"
    if suffix in VIDEO_SUFFIXES:
        return "video"
    raise UnsupportedMedia(f"{suffix or 'that file'} is not a supported cover object")


def load_media(path):
    """All three kinds return an object exposing .carrier, .seed, .media_type,
    .describe() and .save(). Nothing below this line knows or cares which."""
    kind = media_kind(path)
    if kind == "image":
        return image_helpers.load(path)
    if kind == "video":
        return video_helpers.load(path)
    return audio_helpers.load(path)


def regions(offset, lsb_n, payload_len, sig_len):
    """Unit positions of the body and the message.

    Each region starts on a carrier-unit boundary so that extraction never has
    to track a partial unit. Both directions call this, so they cannot drift.
    """
    body_at = offset + su.HEADER_UNITS
    message_at = body_at + su.units_needed(payload_len + sig_len, lsb_n)
    return body_at, message_at


def units_required(lsb_n, payload_len, sig_len, msg_len):
    return (
        su.HEADER_UNITS
        + su.units_needed(payload_len + sig_len, lsb_n)
        + su.units_needed(msg_len, lsb_n)
    )


def resolve_offset(media, derivation_key, offset=None):
    """The start location, either chosen outright or derived from the passphrase.

    A chosen offset cannot be recorded in the payload: the verifier has to know
    where to look before it can read anything. It therefore travels out of band
    with the passphrase, and both sides must supply the same one.
    """
    units = len(media.carrier)
    if offset is not None:
        if not 0 <= offset < units:
            raise ValueError(f"the start location must be between 0 and {units - 1:,}")
        return int(offset)
    location_key, _ = su.derive_subkeys(derivation_key)
    return su.derive_offset(location_key, media.seed, units)


def capacity_report(media, derivation_key, offset=None):
    units = len(media.carrier)
    offset = resolve_offset(media, derivation_key, offset)
    return {
        "offset": offset,
        "units": units,
        "header_units": su.HEADER_UNITS,
        "capacity": {n: su.capacity_bytes(units, offset, n) for n in range(1, 9)},
        # Encryption adds a 12-byte nonce and a 16-byte tag to whatever the
        # user types, so the browser needs the overhead to size a message.
        "encryption_overhead": security.NONCE_BYTES + 16,
    }


def protect(
    cover_path,
    output_path,
    message,
    message_name,
    derivation_key,
    lsb_n,
    private_key,
    encrypt=False,
    offset=None,
):
    if not 1 <= lsb_n <= 8:
        raise ValueError("LSB depth must be between 1 and 8")

    expected = STEGO_SUFFIX[media_kind(cover_path)]
    if Path(output_path).suffix.lower() != expected:
        raise ValueError(f"a protected {media_kind(cover_path)} must be written as {expected}")

    media = load_media(cover_path)
    carrier = media.carrier
    units = len(carrier)

    _, message_key = su.derive_subkeys(derivation_key)
    offset = resolve_offset(media, derivation_key, offset)

    plaintext_len = len(message)
    stored = security.encrypt_message(message_key, message) if (encrypt and message) else message
    encrypted = encrypt and bool(message)

    media_hash = security.masked_hash(carrier, lsb_n)
    payload = security.build_payload(
        media.media_type, media_hash, lsb_n, stored, message_name, encrypted
    )
    payload_bytes = security.canonical_json(payload)
    signature = security.sign(private_key, payload_bytes)

    needed = units_required(lsb_n, len(payload_bytes), len(signature), len(stored))
    capacity = su.capacity_bytes(units, offset, lsb_n)
    if offset + needed > units:
        raise CapacityError(
            f"this payload needs {len(payload_bytes) + len(signature) + len(stored):,} bytes "
            f"but the cover holds {capacity:,} bytes at {lsb_n} LSB"
        )

    body_at, message_at = regions(offset, lsb_n, len(payload_bytes), len(signature))
    flags = su.FLAG_ENCRYPTED if encrypted else 0
    header = su.build_header(lsb_n, flags, len(payload_bytes), len(signature))

    su.embed(carrier, offset, header, 1)
    su.embed(carrier, body_at, payload_bytes + signature, lsb_n)
    if stored:
        su.embed(carrier, message_at, stored, lsb_n)

    media.save(output_path)
    return ProtectReport(
        output_path=str(output_path),
        offset=offset,
        lsb_n=lsb_n,
        payload=payload,
        bytes_used=len(payload_bytes) + len(signature) + len(stored),
        capacity=capacity,
        encrypted=encrypted,
        plaintext_len=plaintext_len,
    )


def protection_evidence(cover_path, report):
    """Measure saved output for the GUI without changing the protection flow."""
    original = load_media(cover_path)
    before = original.carrier
    after = load_media(report.output_path).carrier
    depth = report.lsb_n
    header = su.parse_header(su.extract(after, report.offset, su.HEADER_SIZE, 1))
    body_at, message_at = regions(
        report.offset, depth, header["payload_len"], header["sig_len"]
    )
    used = units_required(
        depth, header["payload_len"], header["sig_len"], report.payload["msg_len"]
    )
    peak = 255
    if media_kind(cover_path) == "audio" and before.dtype.itemsize > 1:
        # PCM amplitudes are signed even though embedding uses unsigned bit patterns.
        dtype = np.dtype(f"<i{before.dtype.itemsize}")
        delta = after.view(dtype).astype(np.float64) - before.view(dtype).astype(np.float64)
        peak = (1 << (before.dtype.itemsize * 8 - 1)) - 1
    else:
        delta = after.astype(np.float64) - before.astype(np.float64)
    mse = float(np.mean(delta ** 2))
    changed = int(np.count_nonzero(before != after))
    rows = []
    for label, start, end, bits in (
        ("Header", report.offset, body_at, 1),
        ("Message", message_at, report.offset + used, depth),
    ):
        for index in range(start, min(start + 4, end)):
            rows.append({
                "region": label, "index": index, "depth": bits,
                "width": before.dtype.itemsize * 8,
                "before": int(before[index]), "after": int(after[index]),
            })
    return {
        "description": original.describe(), "offset": report.offset, "depth": depth,
        "used_bytes": report.bytes_used, "capacity": report.capacity,
        "input_bytes": report.plaintext_len, "stored_bytes": report.payload["msg_len"],
        "encrypted": bool(report.encrypted), "record": report.payload,
        "record_json": security.canonical_json(report.payload).decode(),
        "changed": changed, "changed_percent": 100 * changed / len(before),
        "max_change": float(np.max(np.abs(delta))),
        "psnr": round(10 * math.log10(peak * peak / mse), 2) if mse else None,
        "rows": rows,
        "regions": {
            "header": [report.offset, body_at - 1],
            "record_signature": [body_at, message_at - 1],
            "message": [message_at, report.offset + used - 1],
        },
    }


def verify(path, derivation_key, public_key, offset=None):
    """Walk the checks in order, recording each one, and stop at the first
    failure. The trail is returned either way so the reader can see the
    comparison behind the verdict rather than being asked to trust it."""
    trail = []

    try:
        media = load_media(path)
    except (UnsupportedMedia, OSError, ValueError) as exc:
        return Result(CANNOT_VERIFY, str(exc), checks=_check(trail, "Container", False, str(exc)))

    _check(trail, "Container", True, media.describe())

    carrier = media.carrier
    units = len(carrier)
    _, message_key = su.derive_subkeys(derivation_key)

    try:
        offset = resolve_offset(media, derivation_key, offset)
    except ValueError as exc:
        return Result(CANNOT_VERIFY, str(exc), checks=_check(trail, "Start location", False, str(exc)))

    header = su.parse_header(su.extract(carrier, offset, su.HEADER_SIZE, 1))
    if header is None:
        return _explain_missing_header(carrier, offset, trail)

    _check(trail, "Start location", True, f"payload marker found at offset {offset:,}")

    if header["version"] != su.VERSION:
        detail = f"payload format version {header['version']} is not supported"
        return Result(CANNOT_VERIFY, detail, checks=_check(trail, "Header", False, detail))

    lsb_n = header["lsb_n"]
    payload_len, sig_len = header["payload_len"], header["sig_len"]
    if not 1 <= lsb_n <= 8 or offset + units_required(lsb_n, payload_len, sig_len, 0) > units:
        detail = "the header describes a payload that does not fit this file"
        return Result(CANNOT_VERIFY, detail, checks=_check(trail, "Header", False, detail))

    header_encrypted = bool(header["flags"] & su.FLAG_ENCRYPTED)
    _check(
        trail,
        "Header",
        True,
        f"version {header['version']}, depth {lsb_n} LSB, "
        f"{payload_len:,}-byte record, {sig_len:,}-byte signature, "
        f"message {'encrypted' if header_encrypted else 'plaintext'}",
    )

    body_at, message_at = regions(offset, lsb_n, payload_len, sig_len)
    body = su.extract(carrier, body_at, payload_len + sig_len, lsb_n)
    payload_bytes, signature = body[:payload_len], body[payload_len:]

    # Authenticate before parsing: never interpret bytes we have not verified.
    if not security.verify(public_key, signature, payload_bytes):
        detail = (
            "the signature does not verify under this public key. Either the payload bytes "
            "were altered or the file was signed by a different key."
        )
        return Result(
            SIGNATURE_INVALID, detail, checks=_check(trail, "Signature", False, detail)
        )

    _check(trail, "Signature", True, "RSA-2048 PSS over the signed record verifies")

    payload = json.loads(payload_bytes)

    if payload["lsb_n"] != lsb_n:
        detail = (
            f"the header claims {lsb_n} LSB but the signed record says {payload['lsb_n']}. "
            "A valid payload has been re-embedded at a different depth."
        )
        return Result(TAMPERED, detail, payload, checks=_check(trail, "Depth", False, detail))

    _check(trail, "Depth", True, f"signed record and header agree on {lsb_n} LSB")

    # The header travels unsigned, so its encryption flag has to be reconciled
    # with the signed copy. Flipping the flag alone would otherwise change how
    # the verifier interprets the extracted bytes.
    if payload["msg_encrypted"] != header_encrypted:
        detail = (
            f"the header says the message is {'encrypted' if header_encrypted else 'plaintext'} "
            f"but the signed record says {'encrypted' if payload['msg_encrypted'] else 'plaintext'}. "
            "The header flag has been altered."
        )
        return Result(
            TAMPERED, detail, payload, checks=_check(trail, "Encryption flag", False, detail)
        )

    _check(
        trail,
        "Encryption flag",
        True,
        f"signed record and header agree: message is "
        f"{'encrypted' if header_encrypted else 'stored as plaintext'}",
    )

    msg_len = payload["msg_len"]
    if offset + units_required(lsb_n, payload_len, sig_len, msg_len) > units:
        detail = "the signed message length does not fit this file"
        return Result(
            CANNOT_VERIFY, detail, payload, checks=_check(trail, "Message", False, detail)
        )

    stored = su.extract(carrier, message_at, msg_len, lsb_n) if msg_len else b""
    stored_digest = hashlib.sha256(stored).hexdigest()
    if stored_digest != payload["msg_sha256"]:
        detail = "the hidden message does not hash to the value the signed record commits to"
        return Result(
            TAMPERED,
            detail + ", so it was altered after signing.",
            payload,
            checks=_check(
                trail, "Message digest", False, detail,
                [("signed", payload["msg_sha256"]), ("extracted", stored_digest)],
            ),
        )

    _check(
        trail,
        "Message digest",
        True,
        f"the {msg_len:,} bytes recovered from the carrier hash to the value the record commits to",
        [("signed", payload["msg_sha256"]), ("extracted", stored_digest)],
    )

    message = stored
    if payload["msg_encrypted"]:
        message = security.decrypt_message(message_key, stored)
        if message is None:
            # The location key and the message key come from the same
            # passphrase, so a wrong passphrase would have failed at the start
            # location long before here. Reaching this point means the
            # authenticated ciphertext did not open despite matching its
            # signed digest, which no ordinary tampering produces.
            detail = "the message could not be decrypted with the key derived from this passphrase"
            return Result(
                CANNOT_VERIFY, detail, payload, checks=_check(trail, "Decryption", False, detail)
            )
        _check(
            trail,
            "Decryption",
            True,
            f"AES-256-GCM opened and authenticated {len(message):,} bytes of plaintext",
        )

    current_hash = security.masked_hash(carrier, lsb_n)
    if current_hash != payload["hash"]:
        detail = (
            "the signature is valid, so the record is genuine, but the file no longer "
            "hashes to the value that record commits to. The media was edited outside "
            "the payload region."
        )
        return Result(
            TAMPERED, detail, payload, message,
            _check(
                trail, "Media hash", False, detail,
                [("signed", payload["hash"]), ("recomputed", current_hash)],
            ),
        )

    _check(
        trail,
        "Media hash",
        True,
        f"the file itself still hashes to the value the record commits to, "
        f"measured above the {lsb_n} low bits the payload occupies",
        [("signed", payload["hash"]), ("recomputed", current_hash)],
    )

    return Result(
        AUTHENTIC,
        f"signed by {payload['issuer']} at {payload['timestamp']}, and the media is unchanged.",
        payload,
        message,
        trail,
        encrypted=payload["msg_encrypted"],
    )


def _explain_missing_header(carrier, offset, trail):
    found = _scan_for_magic(carrier)
    if found is None:
        detail = (
            "no payload marker anywhere in the searched region. This file does not "
            "appear to carry a payload."
        )
        return Result(
            PAYLOAD_MISSING, detail, checks=_check(trail, "Start location", False, detail)
        )
    detail = (
        f"no marker at offset {offset:,}, but one was found at {found:,}. The file "
        "carries a payload; the passphrase or the chosen start location is wrong."
    )
    return Result(
        WRONG_START_LOCATION, detail, checks=_check(trail, "Start location", False, detail)
    )


def _scan_for_magic(carrier):
    """Bounded search for the marker, used to tell a wrong key from no payload.

    The search covers only the region our own derivation can produce. Searching
    every carrier position would itself be a steganalysis technique rather than
    a verification step, so the range is capped and stated.
    """
    limit = min(len(carrier) // 2 + su.HEADER_UNITS, SCAN_UNIT_CAP)
    plane = (carrier[:limit] & 1).astype(np.uint8)
    magic = su.bytes_to_bits(su.MAGIC)

    positions = len(plane) - len(magic)
    if positions <= 0:
        return None

    match = np.ones(positions, dtype=bool)
    for index, bit in enumerate(magic):
        match &= plane[index : index + positions] == bit

    hits = np.flatnonzero(match)
    return int(hits[0]) if len(hits) else None
