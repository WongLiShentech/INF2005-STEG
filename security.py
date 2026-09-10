"""Verification payloads, stable hashing and RSA digital signatures."""

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# The one place to edit if the team label changes. It is FR3 "team-defined
# metadata" only; nothing in the format depends on its value.
TEAM = "P1-4"
ISSUER = "INF2005 ACW1 Media Verification"

PAYLOAD_VERSION = 1


def canonical_json(payload):
    """The single serialisation used for signing, verifying and embedding.

    Key order and whitespace must be identical in all three places or a
    perfectly authentic file fails signature verification.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def masked_hash(carrier, lsb_n):
    """SHA-256 of the carrier with the lowest lsb_n bits of every unit zeroed.

    Embedding only ever writes into those bits, so this hash is identical
    before and after embedding. The trade-off is that changes confined to the
    lowest lsb_n bits are outside the integrity guarantee.
    """
    mask = carrier.dtype.type(((1 << (carrier.dtype.itemsize * 8)) - 1) ^ ((1 << lsb_n) - 1))
    return hashlib.sha256((carrier & mask).tobytes()).hexdigest()


def new_media_id(media_type):
    kind = "IMG" if media_type.startswith("image") else "AUD"
    return f"{TEAM}-{kind}-{uuid.uuid4().hex[:8].upper()}"


def build_payload(media_type, media_hash, lsb_n, message, message_name, encrypted):
    """FR3 verification record, plus a description of the hidden message.

    The message itself is carried after the signature rather than inside this
    JSON, so a large message is not inflated by base64. Its length and digest
    live here, which means both are covered by the signature: an attacker
    cannot lie about how long the message is.
    """
    return {
        "v": PAYLOAD_VERSION,
        "media_id": new_media_id(media_type),
        "media_type": media_type,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hash": media_hash,
        "nonce": base64.b64encode(os.urandom(16)).decode(),
        "lsb_n": lsb_n,
        "team": TEAM,
        "issuer": ISSUER,
        "msg_len": len(message),
        "msg_sha256": hashlib.sha256(message).hexdigest(),
        "msg_name": message_name,
        "msg_encrypted": encrypted,
    }


def sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def generate_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def load_private_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def load_public_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_public_key(handle.read())


def private_key_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_pem(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
