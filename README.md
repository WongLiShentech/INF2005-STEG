# INF2005 ACW1: Steganographic Integrity Verification

A web tool that hides a signed record inside an image, a sound file or a video, and later checks whether the file is genuine. It uses LSB replacement to hide the data, SHA-256 to fingerprint the file and RSA-2048 to sign it.

## Setup

Needs Python 3.11 or newer.

```
git clone https://github.com/WongLiShentech/INF2005-STEG.git
cd INF2005-STEG
python -m venv .venv
.venv\Scripts\activate        (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## Commands

| Command | What it does |
|---|---|
| `python -m flask --app app run` | Starts the app at http://127.0.0.1:5000 |
| `pytest` | Runs the tests |
| `python make_demo_files.py` | Rebuilds `testFiles/` and `evidence/demo_run_log.txt` |
| `python generate_key.py` | Makes a new demo key pair (only if `keys/` is deleted) |

Python files are only read when the server starts, so restart it after pulling changes to any `.py` file.

## Using it

Open the app and pick a role.

**Sender**
1. Choose a cover (image, audio or video) and type the secret message.
2. Set a passphrase and an LSB depth from 1 to 8. Depth 1 or 2 is invisible; higher depths hold more but damage the cover.
3. Press Protect, then download the stego file or open a Gmail or Outlook draft and attach it.
4. Give the receiver the passphrase some other way. It is not in the email.

**Receiver**
1. Upload the file you were sent and the sender's public key (a `.pem` file).
2. Enter the passphrase and press Verify.
3. Read the verdict and the checks behind it. If the file is genuine, the hidden message is shown.

`/walkthrough` runs the whole journey, sender and receiver, on one page.

## How it works

1. The cover is hashed with its lowest `n` bits set to zero. Hiding only changes those bits, so the hash is the same before and after.
2. A short record is built: media ID, timestamp, nonce, the cover hash, the message hash and the depth. It is signed with RSA-2048 (PSS padding).
3. HKDF turns the passphrase into two keys. One decides where to hide; the other encrypts the message with AES-256-GCM.
4. The start position is an HMAC of the location key and the cover's dimensions, reduced to the first half of the file. It is calculated, never stored.
5. A 13-byte header, the record, the signature and the message are written into the lowest `n` bits from that position.
6. Verifying repeats the calculation, reads the data back, checks the signature and compares the hashes.

| Verdict | Meaning |
|---|---|
| Authentic | Signature valid, media and message unchanged |
| Tampered | Signature valid, but the media or message no longer matches it |
| Signature Invalid | The record was altered, or a different key signed it |
| Payload Missing | Nothing hidden in this file |
| Wrong Start Location | A payload exists, but not where this passphrase points |
| Cannot Verify | The file could not be read as image, audio or video |

## Files

```
app.py            web routes
workflow.py       protect() and verify(), including the verdict logic
security.py       record, hashing, RSA signing, AES-GCM
stego_utils.py    header, key derivation, LSB embed and extract
image_helpers.py, audio_helpers.py, video_helpers.py
                  load and save each media type as a flat list of numbers
make_demo_files.py  builds the sample files
generate_key.py   makes the demo key pair
test_project.py   tests
templates/ static/  pages, styles and scripts
testFiles/        original, protected and tampered samples
keys/             demo key pair
evidence/         log of the demo run
```

## Keys

`keys/demo_private.pem` is committed on purpose. It was made for this assignment, signs only the demo files and protects nothing real, so anyone can reproduce the results. A real signer would keep it secret and publish only the public key.

## Sample files

Passphrase `team demo key`, public key `keys/demo_public.pem`.

| File | Verdict |
|---|---|
| `protected/P1_image_short_n2.png` | Authentic |
| `protected/P2_audio_large_n4.wav` | Authentic |
| `protected/P3_image_custom_encrypted_n3.png` | Authentic (encrypted message) |
| `protected/P4_audio_custom_encrypted_n2.wav` | Authentic (encrypted message) |
| `protected/P5_video_short_n2.avi` | Authentic |
| `protected/receiver_demo_stego.png` | Authentic |
| `tampered/receiver_demo_stego_tampered.png` | Tampered |
| `tampered/N1_image_edited.png` | Tampered (edited outside the payload) |
| `tampered/N8_audio_replayed_payload.wav` | Tampered (real payload moved to another cover) |
| `tampered/N9_video_edited.avi` | Tampered |
| `tampered/N6_audio_payload_bits_flipped.wav` | Signature Invalid |
| `tampered/N7_not_an_image.png` | Cannot Verify |
| `original/` covers | Payload Missing |

Other cases need no extra file. `keys/other_public.pem` gives Signature Invalid on any protected file, and a wrong passphrase gives Wrong Start Location.

## Limits

- LSB replacement can be detected statistically, and at high depths the damage is visible or audible. Verification still passes at depth 8, but the hiding has failed.
- The `ACW1` marker means anyone who knows the format can find the payload by scanning, without the passphrase. The start position gives obscurity, not secrecy. The encryption is what protects the message.
- The passphrase goes through HKDF only, with no slow password hashing, so a weak passphrase can be guessed offline.
- The hash ignores the lowest `n` bits, so edits there are not caught. At depth 8 the hash covers nothing.
- A signed payload copied into another protection of the same cover still verifies.
- The receiver must already have the genuine public key. There are no certificates.
- Both sides need the same passphrase before they start, and it has to travel separately.
- Re-saving as JPEG or MP3, resizing or resampling destroys the payload.
- 24-bit audio is not supported. Protected video is stored uncompressed, so the files are large.
