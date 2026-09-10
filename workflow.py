"""Protect and verify a cover object end to end, and decide the verdict."""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

import image_helpers
import security
import stego_utils as su

AUTHENTIC = "Authentic"
TAMPERED = "Tampered"
SIGNATURE_INVALID = "Signature Invalid"
PAYLOAD_MISSING = "Payload Missing"
WRONG_START_LOCATION = "Wrong Start Location"
CANNOT_VERIFY = "Cannot Verify"

IMAGE_SUFFIXES = {".png", ".bmp", ".jpg", ".jpeg"}

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


@dataclass
class ProtectReport:
    output_path: str
    offset: int
    lsb_n: int
    payload: dict = field(default_factory=dict)
    bytes_used: int = 0
    capacity: int = 0


def load_media(path):
    suffix = Path(path).suffix.lower()
    if suffix in IMAGE_SUFFIXES:
        return image_helpers.load(path)
    raise UnsupportedMedia(f"{suffix or 'that file'} is not a supported cover object")


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


def capacity_report(media, derivation_key):
    units = len(media.carrier)
    offset = su.derive_offset(derivation_key, media.seed, units)
    return {
        "offset": offset,
        "units": units,
        "capacity": {n: su.capacity_bytes(units, offset, n) for n in range(1, 9)},
    }


def protect(cover_path, output_path, message, message_name, derivation_key, lsb_n, private_key):
    if not 1 <= lsb_n <= 8:
        raise ValueError("LSB depth must be between 1 and 8")

    media = load_media(cover_path)
    carrier = media.carrier
    units = len(carrier)
    offset = su.derive_offset(derivation_key, media.seed, units)

    media_hash = security.masked_hash(carrier, lsb_n)
    payload = security.build_payload(
        media.media_type, media_hash, lsb_n, message, message_name, False
    )
    payload_bytes = security.canonical_json(payload)
    signature = security.sign(private_key, payload_bytes)

    needed = units_required(lsb_n, len(payload_bytes), len(signature), len(message))
    capacity = su.capacity_bytes(units, offset, lsb_n)
    if offset + needed > units:
        raise CapacityError(
            f"this payload needs {len(payload_bytes) + len(signature) + len(message):,} bytes "
            f"but the cover holds {capacity:,} bytes at {lsb_n} LSB"
        )

    body_at, message_at = regions(offset, lsb_n, len(payload_bytes), len(signature))
    header = su.build_header(lsb_n, 0, len(payload_bytes), len(signature))

    su.embed(carrier, offset, header, 1)
    su.embed(carrier, body_at, payload_bytes + signature, lsb_n)
    if message:
        su.embed(carrier, message_at, message, lsb_n)

    media.save(output_path)
    return ProtectReport(
        output_path=str(output_path),
        offset=offset,
        lsb_n=lsb_n,
        payload=payload,
        bytes_used=len(payload_bytes) + len(signature) + len(message),
        capacity=capacity,
    )


def verify(path, derivation_key, public_key):
    try:
        media = load_media(path)
    except (UnsupportedMedia, OSError, ValueError) as exc:
        return Result(CANNOT_VERIFY, str(exc))

    carrier = media.carrier
    units = len(carrier)
    offset = su.derive_offset(derivation_key, media.seed, units)

    header = su.parse_header(su.extract(carrier, offset, su.HEADER_SIZE, 1))
    if header is None:
        return _explain_missing_header(carrier, offset)

    if header["version"] != su.VERSION:
        return Result(CANNOT_VERIFY, f"payload format version {header['version']} is not supported")

    lsb_n = header["lsb_n"]
    payload_len, sig_len = header["payload_len"], header["sig_len"]
    if not 1 <= lsb_n <= 8 or offset + units_required(lsb_n, payload_len, sig_len, 0) > units:
        return Result(CANNOT_VERIFY, "the header describes a payload that does not fit this file")

    body_at, message_at = regions(offset, lsb_n, payload_len, sig_len)
    body = su.extract(carrier, body_at, payload_len + sig_len, lsb_n)
    payload_bytes, signature = body[:payload_len], body[payload_len:]

    # Authenticate before parsing: never interpret bytes we have not verified.
    if not security.verify(public_key, signature, payload_bytes):
        return Result(
            SIGNATURE_INVALID,
            "the signature does not verify under this public key. Either the payload bytes "
            "were altered or the file was signed by a different key.",
        )

    payload = json.loads(payload_bytes)

    if payload["lsb_n"] != lsb_n:
        return Result(
            TAMPERED,
            f"the header claims {lsb_n} LSB but the signed record says {payload['lsb_n']}. "
            "A valid payload has been re-embedded at a different depth.",
            payload,
        )

    msg_len = payload["msg_len"]
    if offset + units_required(lsb_n, payload_len, sig_len, msg_len) > units:
        return Result(CANNOT_VERIFY, "the signed message length does not fit this file", payload)

    message = su.extract(carrier, message_at, msg_len, lsb_n) if msg_len else b""
    if hashlib.sha256(message).hexdigest() != payload["msg_sha256"]:
        return Result(
            TAMPERED,
            "the hidden message does not match the digest in the signed record.",
            payload,
        )

    if security.masked_hash(carrier, lsb_n) != payload["hash"]:
        return Result(
            TAMPERED,
            "the signature is valid but the media no longer matches the signed hash. "
            "The file was edited outside the payload region.",
            payload,
            message,
        )

    return Result(
        AUTHENTIC,
        f"signed by {payload['issuer']} at {payload['timestamp']}, and the media is unchanged.",
        payload,
        message,
    )


def _explain_missing_header(carrier, offset):
    found = _scan_for_magic(carrier)
    if found is None:
        return Result(
            PAYLOAD_MISSING,
            "no payload marker anywhere in the searched region. This file does not "
            "appear to carry a payload.",
        )
    return Result(
        WRONG_START_LOCATION,
        f"no marker at the derived offset {offset:,}, but one was found at {found:,}. "
        "The file carries a payload; the derivation key is wrong.",
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
