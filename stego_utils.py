"""Bit-level operations shared by the image and audio carriers.

Both media types are reduced to a flat NumPy array of integer carrier units
(uint8 for image channels, uint16 for audio samples), so LSB replacement is
written once here instead of once per format.
"""

import hashlib
import hmac
import struct

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"ACW1"
VERSION = 1
HEADER_SIZE = 13
FLAG_ENCRYPTED = 0x01

# One key, one purpose. The user types a single passphrase, but using those
# same bytes both to place the payload and to encrypt the message would tie
# two unrelated jobs to one secret: anything that weakened one would weaken
# the other. HKDF expands the passphrase into independent subkeys instead.
INFO_LOCATION = b"ACW1 start-location derivation"
INFO_MESSAGE = b"ACW1 message encryption"

# The header is always written at 1 LSB so the decoder can read it without
# knowing the body depth yet. One bit per carrier unit means 13 bytes = 104 units.
HEADER_UNITS = HEADER_SIZE * 8


def bytes_to_bits(data):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits):
    return np.packbits(bits).tobytes()


def build_header(lsb_n, flags, payload_len, sig_len):
    return MAGIC + struct.pack(">BBBIH", VERSION, lsb_n, flags, payload_len, sig_len)


def parse_header(raw):
    """Return the header fields, or None if this is not one of our headers."""
    if len(raw) != HEADER_SIZE or raw[:4] != MAGIC:
        return None
    version, lsb_n, flags, payload_len, sig_len = struct.unpack(">BBBIH", raw[4:])
    return {
        "version": version,
        "lsb_n": lsb_n,
        "flags": flags,
        "payload_len": payload_len,
        "sig_len": sig_len,
    }


def derive_subkeys(passphrase):
    """Split the user's passphrase into two independent 32-byte subkeys.

    HKDF-SHA256 with a distinct info string per purpose. Recovering one
    subkey tells an attacker nothing about the other, so the location key and
    the encryption key can be reasoned about separately even though the user
    only ever types one secret.

    No salt: a salt would have to travel with the file or be re-derived, and
    both parties already share the passphrase out of band. HKDF is defined to
    fall back to a zero salt, and the info strings still separate the outputs.
    """
    material = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=INFO_LOCATION + INFO_MESSAGE
    ).derive(passphrase)
    return material[:32], material[32:]


def derive_offset(key, seed, usable_units):
    """Keyed start location. Nothing about the offset travels with the file.

    The modulus is deliberately a constant fraction of the carrier and never a
    function of payload length: the verifier must derive the identical offset
    before it has found the header, so it cannot know how long the payload is.
    Confining the offset to the first half also guarantees room for a body.
    """
    digest = hmac.new(key, seed.encode(), hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % max(1, usable_units // 2)


def capacity_bytes(usable_units, offset, lsb_n):
    body_units = usable_units - offset - HEADER_UNITS
    return max(0, body_units * lsb_n // 8)


def _low_bit_mask(carrier, lsb_n):
    full = (1 << (carrier.dtype.itemsize * 8)) - 1
    return carrier.dtype.type(full ^ ((1 << lsb_n) - 1))


def units_needed(n_bytes, lsb_n):
    return -(-n_bytes * 8 // lsb_n)


def embed(carrier, start, data, lsb_n):
    """LSB replacement: overwrite the low lsb_n bits of consecutive units."""
    bits = bytes_to_bits(data)
    padding = -len(bits) % lsb_n
    if padding:
        bits = np.concatenate([bits, np.zeros(padding, dtype=np.uint8)])

    chunks = bits.reshape(-1, lsb_n)
    weights = (1 << np.arange(lsb_n - 1, -1, -1)).astype(np.uint32)
    values = (chunks * weights).sum(axis=1).astype(carrier.dtype)

    end = start + len(values)
    if end > len(carrier):
        raise ValueError("payload does not fit in the carrier at this start location")
    window = carrier[start:end]
    carrier[start:end] = (window & _low_bit_mask(carrier, lsb_n)) | values


def extract(carrier, start, n_bytes, lsb_n):
    total_bits = n_bytes * 8
    units = units_needed(n_bytes, lsb_n)
    end = start + units
    if end > len(carrier):
        raise ValueError("requested payload runs past the end of the carrier")

    values = carrier[start:end].astype(np.uint32) & ((1 << lsb_n) - 1)
    shifts = np.arange(lsb_n - 1, -1, -1)
    bits = ((values[:, None] >> shifts) & 1).astype(np.uint8).ravel()[:total_bits]
    return bits_to_bytes(bits)
