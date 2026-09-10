"""Create the demo RSA-2048 keypair in keys/. Run once: python generate_key.py"""

import os

import security

KEY_DIR = "keys"


def main():
    os.makedirs(KEY_DIR, exist_ok=True)
    private_path = os.path.join(KEY_DIR, "demo_private.pem")
    public_path = os.path.join(KEY_DIR, "demo_public.pem")

    if os.path.exists(private_path):
        print(f"{private_path} already exists. Delete it first if you want a new keypair.")
        return

    key = security.generate_keypair()
    with open(private_path, "wb") as handle:
        handle.write(security.private_key_pem(key))
    with open(public_path, "wb") as handle:
        handle.write(security.public_key_pem(key))

    # A second public key belonging to nobody we sign with, so the failed
    # signature case can be demonstrated without generating a key on the spot.
    # Its private half is deliberately discarded.
    other_path = os.path.join(KEY_DIR, "other_public.pem")
    with open(other_path, "wb") as handle:
        handle.write(security.public_key_pem(security.generate_keypair()))

    print(f"Wrote {private_path}, {public_path} and {other_path}")


if __name__ == "__main__":
    main()
