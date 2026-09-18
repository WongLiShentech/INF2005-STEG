"""Attack simulation.

Each attack below stages one thing an adversary might realistically do to a
protected file, or one mistake a verifier might make, and states the verdict
the system should return. Running them together turns the negative cases from
a set of hand-made files into something reproducible: point it at any
protected object and watch every failure path fire.

Two attacks are deliberately included because they do *not* always produce the
verdict you would hope for. `edit_media` at 8 LSB and `transplant` between two
protections of the same cover both expose real limits of the design, and a
module that quietly omitted them would be worth less than one that reports
them.
"""

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import security
import stego_utils as su
import workflow


@dataclass
class Layout:
    """Where each part of the payload sits inside a protected carrier."""

    media: object
    offset: int
    lsb_n: int
    flags: int
    payload_len: int
    sig_len: int
    msg_len: int
    body_at: int
    message_at: int
    message_end: int


def inspect(path, derivation_key, offset=None):
    """Read the header of a protected file and work out its layout.

    An attacker who has the passphrase knows all of this, so nothing here is
    privileged: the point of the module is to show what such an attacker can
    and cannot achieve.
    """
    media = workflow.load_media(path)
    offset = workflow.resolve_offset(media, derivation_key, offset)

    header = su.parse_header(su.extract(media.carrier, offset, su.HEADER_SIZE, 1))
    if header is None:
        raise ValueError("no payload found at that start location, so there is nothing to attack")

    lsb_n = header["lsb_n"]
    payload_len, sig_len = header["payload_len"], header["sig_len"]
    body_at, message_at = workflow.regions(offset, lsb_n, payload_len, sig_len)

    # The message length is not in the header; it is in the signed record.
    body = su.extract(media.carrier, body_at, payload_len + sig_len, lsb_n)
    msg_len = json.loads(body[:payload_len])["msg_len"]

    return Layout(
        media=media,
        offset=offset,
        lsb_n=lsb_n,
        flags=header["flags"],
        payload_len=payload_len,
        sig_len=sig_len,
        msg_len=msg_len,
        body_at=body_at,
        message_at=message_at,
        message_end=message_at + su.units_needed(msg_len, lsb_n),
    )


def _flip_low_bit(carrier, index):
    carrier[index] ^= carrier.dtype.type(1)


def _flip_high_bit(carrier, index):
    carrier[index] ^= carrier.dtype.type(1 << (carrier.dtype.itemsize * 8 - 1))


# --- file attacks: each mutates a copy and returns a note for the report ---


def save_bit_flipped_copy(source, destination, depth):
    """Flip one unmasked bit for the walkthrough, preserving the source file."""
    media = workflow.load_media(source)
    if not 1 <= depth < media.carrier.dtype.itemsize * 8:
        raise ValueError("no unmasked bits remain; choose a lower depth for this test")
    media.carrier[0] ^= media.carrier.dtype.type(1 << depth)
    media.save(destination)


def edit_media(layout, _key, _extra):
    """Retouch the picture or the sound the way an editor would, leaving the
    hidden payload untouched. The signature stays valid; only the media hash
    notices."""
    carrier = layout.media.carrier
    outside = [i for i in range(0, len(carrier), max(1, len(carrier) // 400))
               if not layout.offset <= i < layout.message_end]
    if not outside:
        raise ValueError("the payload fills this carrier, leaving nothing to edit around it")
    for index in outside:
        _flip_high_bit(carrier, index)
    return f"altered {len(outside):,} carrier values outside the payload region"


def corrupt_record(layout, _key, _extra):
    """Change the signed record itself, as an attacker rewriting the claim
    would have to."""
    _flip_low_bit(layout.media.carrier, layout.body_at + 40)
    return f"flipped one bit inside the signed record at unit {layout.body_at + 40:,}"


def corrupt_message(layout, _key, _extra):
    """Swap out the secret while leaving the record that describes it intact."""
    if not layout.msg_len:
        raise ValueError("this file carries no message, so there is nothing to corrupt")
    _flip_low_bit(layout.media.carrier, layout.message_at)
    return f"flipped one bit inside the hidden message at unit {layout.message_at:,}"


def flip_encryption_flag(layout, _key, _extra):
    """The header travels unsigned. Flipping its encryption flag changes how
    the verifier would interpret the message bytes."""
    flags = layout.flags ^ su.FLAG_ENCRYPTED
    header = su.build_header(layout.lsb_n, flags, layout.payload_len, layout.sig_len)
    su.embed(layout.media.carrier, layout.offset, header, 1)
    was = "encrypted" if layout.flags & su.FLAG_ENCRYPTED else "plaintext"
    return f"rewrote the unsigned header flag, which claimed {was}"


def erase_payload(layout, _key, _extra):
    """Destroy the payload without touching how the file looks or sounds."""
    blank = bytes(su.HEADER_SIZE)
    su.embed(layout.media.carrier, layout.offset, blank, 1)
    return f"zeroed the {su.HEADER_SIZE}-byte header, removing the marker the verifier looks for"


def transplant(layout, derivation_key, target_path):
    """Replay: lift a genuine, correctly signed payload out of one file and
    drop it into another.

    Nothing is forged. The record verifies perfectly, because it is the real
    one. What it no longer describes is the file it now sits in, and only the
    media hash can tell.
    """
    if target_path is None:
        raise ValueError("this attack needs a second cover object to transplant the payload into")

    carrier = layout.media.carrier
    stolen = su.extract(
        carrier, layout.offset, su.HEADER_SIZE, 1
    ), su.extract(
        carrier,
        layout.body_at,
        layout.payload_len + layout.sig_len + layout.msg_len,
        layout.lsb_n,
    )

    target = workflow.load_media(target_path)
    offset = workflow.resolve_offset(target, derivation_key)
    needed = workflow.units_required(
        layout.lsb_n, layout.payload_len, layout.sig_len, layout.msg_len
    )
    if offset + needed > len(target.carrier):
        raise ValueError("the second cover object is too small to hold the transplanted payload")

    body_at, _ = workflow.regions(offset, layout.lsb_n, layout.payload_len, layout.sig_len)
    su.embed(target.carrier, offset, stolen[0], 1)
    su.embed(target.carrier, body_at, stolen[1], layout.lsb_n)

    # The attacked object is now the second file, not the first.
    layout.media = target
    return f"moved a genuine signed payload into a different cover object at offset {offset:,}"


# --- verification-side attacks: the file is untouched ---


def wrong_public_key(_layout, _key, _extra):
    return "checked a genuine file against a public key that does not match the signer"


def wrong_passphrase(_layout, _key, _extra):
    return "looked for the payload at the location a different passphrase derives"


@dataclass
class Attack:
    key: str
    label: str
    intent: str
    expected: str
    apply: object = None
    needs_target: bool = False
    caveat: object = None
    tags: list = field(default_factory=list)


def _edit_media_expected(layout):
    """At 8 LSB the masked hash covers nothing, so this attack goes unnoticed."""
    if layout.lsb_n == 8:
        return workflow.AUTHENTIC
    return workflow.TAMPERED


def _edit_media_caveat(layout):
    if layout.lsb_n == 8:
        return (
            "At 8 LSB the integrity hash masks every bit of each value, so it is computed "
            "over constant zeros and cannot see this edit. The payload is still authentic; "
            "the media is not, and the system cannot tell. Use a lower depth if media "
            "integrity matters."
        )
    return None


ATTACKS = [
    Attack(
        "edit_media",
        "Retouch the media",
        "Edit the picture or sound after protection, leaving the payload alone.",
        _edit_media_expected,
        edit_media,
        caveat=_edit_media_caveat,
        tags=["file"],
    ),
    Attack(
        "corrupt_record",
        "Rewrite the signed record",
        "Alter the verification record, as forging a claim would require.",
        workflow.SIGNATURE_INVALID,
        corrupt_record,
        tags=["file"],
    ),
    Attack(
        "corrupt_message",
        "Corrupt the hidden message",
        "Change the secret itself while leaving its record untouched.",
        workflow.TAMPERED,
        corrupt_message,
        tags=["file"],
    ),
    Attack(
        "flip_flag",
        "Flip the unsigned header flag",
        "Change how the verifier is told to read the message bytes.",
        workflow.TAMPERED,
        flip_encryption_flag,
        tags=["file"],
    ),
    Attack(
        "erase_payload",
        "Erase the payload",
        "Strip the hidden data out without changing how the file looks.",
        workflow.PAYLOAD_MISSING,
        erase_payload,
        tags=["file"],
    ),
    Attack(
        "transplant",
        "Replay a genuine payload elsewhere",
        "Move a correctly signed payload into a different cover object.",
        workflow.TAMPERED,
        transplant,
        needs_target=True,
        caveat=lambda _layout: (
            "Between two protections of the *same* cover this attack succeeds: the masked "
            "media hash is identical, so the replayed record still describes the file it "
            "was moved into. The record binds to media content, not to one instance of it."
        ),
        tags=["file"],
    ),
    Attack(
        "wrong_key",
        "Verify with the wrong public key",
        "An impostor's key, or a file signed by someone else entirely.",
        workflow.SIGNATURE_INVALID,
        wrong_public_key,
        tags=["verify"],
    ),
    Attack(
        "wrong_passphrase",
        "Verify with the wrong passphrase",
        "The verifier looks in the wrong place for the payload.",
        workflow.WRONG_START_LOCATION,
        wrong_passphrase,
        tags=["verify"],
    ),
]

BY_KEY = {attack.key: attack for attack in ATTACKS}


@dataclass
class Outcome:
    attack: Attack
    ran: bool
    note: str = ""
    expected: str = ""
    verdict: str = ""
    explanation: str = ""
    caveat: str = ""
    path: str = ""

    @property
    def as_expected(self):
        return self.ran and self.verdict == self.expected


def run(attack, source, derivation_key, public_key, output_dir, target_path=None, offset=None):
    """Stage one attack against a protected file and report what the verifier
    then says. The original is never modified: file attacks work on a copy."""
    try:
        layout = inspect(source, derivation_key, offset)
    except (ValueError, workflow.UnsupportedMedia, OSError) as exc:
        return Outcome(attack, ran=False, note=str(exc))

    expected = attack.expected(layout) if callable(attack.expected) else attack.expected
    caveat = attack.caveat(layout) if callable(attack.caveat) else attack.caveat

    if "verify" in attack.tags:
        # Nothing about the file changes; the mistake is made at check time.
        note = attack.apply(layout, derivation_key, target_path)
        if attack.key == "wrong_key":
            stranger = security.generate_keypair().public_key()
            result = workflow.verify(source, derivation_key, stranger, offset)
        else:
            result = workflow.verify(source, derivation_key + b"!", public_key)
        return Outcome(
            attack, True, note, expected, result.verdict, result.explanation, caveat or "",
            str(source),
        )

    destination = Path(output_dir) / f"attacked_{attack.key}{Path(source).suffix}"
    shutil.copy(source, destination)

    try:
        note = attack.apply(layout, derivation_key, target_path)
    except ValueError as exc:
        destination.unlink(missing_ok=True)
        return Outcome(attack, ran=False, note=str(exc), expected=expected)

    # transplant swaps the carrier for the second file, so save whatever the
    # attack ended up holding, and under the right suffix for that media.
    destination.unlink(missing_ok=True)
    destination = Path(output_dir) / (
        f"attacked_{attack.key}"
        f"{workflow.STEGO_SUFFIX[workflow.media_kind(target_path if attack.needs_target else source)]}"
    )
    layout.media.save(destination)

    # A transplanted payload sits where the *second* file's passphrase puts it,
    # which is the offset the verifier will derive anyway.
    check_offset = None if attack.needs_target else offset
    result = workflow.verify(destination, derivation_key, public_key, check_offset)
    return Outcome(
        attack, True, note, expected, result.verdict, result.explanation, caveat or "",
        str(destination),
    )


def run_all(source, derivation_key, public_key, output_dir, target_path=None, offset=None):
    return [
        run(attack, source, derivation_key, public_key, output_dir, target_path, offset)
        for attack in ATTACKS
    ]
