# INF2005 ACW1 — Steganographic Image and Audio Integrity Verification

A web-based tool that hides a signed verification payload inside a PNG or WAV file
using LSB replacement, then later checks whether the file is authentic.

## Setup

You need Python 3.11 or newer. Nothing else — no AI tooling is required to build,
run, test or change anything in this repository.

```bash
git clone <your repo url>
cd INF2005-STEG

python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
```

The demo keypair is already committed in `keys/`, so there is nothing else to set up.

## Commands

| Command | What it does |
|---|---|
| `pytest` | Runs the test suite. Everything should pass before you commit. |
| `python generate_key.py` | Creates a fresh demo keypair. Only needed if you delete `keys/`. |
| `flask --app app run` | Starts the web interface at http://127.0.0.1:5000 *(from Phase 3)* |

## Project layout

```
app.py             Flask routes: upload, protect, verify, capacity, serve media
workflow.py        protect() and verify() end to end, including the verdict tree
image_helpers.py   PNG load/save, carrier array, capacity, seed string
audio_helpers.py   WAV/PCM load/save, carrier array, capacity, seed string
security.py        Payload record, canonical JSON, media hash, RSA sign/verify
stego_utils.py     Bit conversion, header, keyed offset, LSB embed/extract
generate_key.py    One-off demo keypair script
test_project.py    Test suite
templates/         HTML pages
static/            CSS and JavaScript
testFiles/         Demo media: original/, protected/, tampered/
keys/              Demo RSA keypair
evidence/          Screenshots and logs for each test case
workspace/         Scratch space the running server writes to (not committed)
```

Both media types are reduced to a flat array of integer carrier units — image
channel values or audio samples — so the LSB replacement code in `stego_utils.py`
is written once and shared. `image_helpers.py` and `audio_helpers.py` differ only
in how they load and save that array.

## Design decisions

### 1. What gets hashed

Embedding changes the file, so hashing the raw file would make every authentic
file report as tampered. Instead we hash the **canonical form**: the media with
the lowest `n` bits of every carrier unit forced to zero. Embedding only ever
writes into those bits, so the hash is identical before and after.

The cost, which we state openly: changes confined to the lowest `n` bits outside
the payload region are not detected by the hash. That is the price of making the
hash stable under embedding.

### 2. Framing

A 13-byte length-prefixed header, not a delimiter. The hidden data contains a
binary RSA signature in which any byte sequence can occur, including whatever
sentinel we might have chosen — a delimiter would truncate extraction
unpredictably. A length prefix also makes extraction bounded, so a file with no
payload reports `Payload Missing` instead of scanning forever.

| Field | Bytes | Purpose |
|---|---|---|
| magic | 4 | `ACW1`. Confirms a payload exists and the start location is right |
| version | 1 | Lets the decoder reject formats it does not know |
| lsb_n | 1 | Body depth, cross-checked against the signed copy |
| flags | 1 | Bit 0: message is encrypted |
| payload_len | 4 | Length of the JSON payload |
| sig_len | 2 | Length of the signature |

The header is always written at 1 LSB so the decoder can read it without already
knowing the body depth. The body follows immediately at `n` LSBs.

### 3. Start location

The offset is derived, never stored:

```
offset = HMAC-SHA256(key, seed) mod (usable_units // 2)
```

The seed is read from the container before any extraction — `width x height x
channels` for images, `frames x channels x sample_width` for audio. It is
deliberately **not** the filename, because one of our test cases emails the file
to another party and downloads are frequently renamed.

The modulus is a constant fraction of the carrier and never a function of payload
length. The verifier has to derive the same offset *before* it has found the
header, so it cannot know how long the payload is. Confining the offset to the
first half also guarantees room for a body.

Nothing about the location travels with the file, so security rests on the key
alone.

### 4. Signature

RSA-2048 with PSS padding and SHA-256, over the canonical JSON of the payload.
Signing the payload — which itself contains the media hash — chains media
integrity to signer authenticity in one step.

Canonical JSON means `sort_keys=True, separators=(',', ':')`, written once in
`security.py` and never inlined anywhere else. Python's default `json.dumps`
produces different bytes for the same object depending on key order, which would
fail verification on files that are perfectly authentic.

### 5. Payload

```json
{
  "v": 1,
  "media_id": "P1-4-IMG-3F9A2B10",
  "media_type": "image/png",
  "timestamp": "2026-09-10T14:30:00Z",
  "hash": "<sha256 of the masked canonical form>",
  "nonce": "<16 random bytes, base64>",
  "lsb_n": 2,
  "team": "P1-4",
  "issuer": "INF2005 ACW1 Media Verification",
  "msg_len": 812,
  "msg_sha256": "<sha256 of the hidden message>",
  "msg_name": "overview.txt",
  "msg_encrypted": false
}
```

The hidden message is written **after** the signature, not inside this JSON. Base64
would inflate a large message by a third for no benefit. Its length and digest are
in the signed record, so the signature still covers the message and an attacker
cannot lie about its length — which would be possible if the length lived in the
plaintext header.

The nonce makes two protections of the same file produce different signed
payloads, so one cannot be lifted and replayed. Note that this gives uniqueness,
not prevention: detecting an actual replay needs a verifier that remembers the
nonces it has already seen.

To change the team label, edit `TEAM` at the top of `security.py`. Do it before
generating the demo sample files, since the value is signed into each one.

### 6. Verdicts

| Step | Check | Verdict on failure |
|---|---|---|
| 1 | File opens as PNG/WAV | Cannot Verify |
| 2 | Magic found at the derived offset | Payload Missing / Wrong Start Location |
| 3 | Version known, lengths within capacity | Cannot Verify |
| 4 | Signature valid under the public key | Signature Invalid |
| 5 | Signed `lsb_n` matches header `lsb_n` | Tampered |
| 6 | Recomputed canonical hash matches | Tampered |
| 7 | — | Authentic |

Step 4 comes before the JSON is parsed: untrusted input should be authenticated
before it is interpreted.

Steps 2, 5 and 6 need a word of explanation.

**Payload Missing vs Wrong Start Location.** A missing magic value has two causes:
the file never carried a payload, or the key was wrong so we are looking in the
wrong place. We tell them apart with a bounded scan — if the magic turns up
elsewhere, the payload exists and the derivation was wrong. The scan is capped
deliberately, because an unbounded one would itself be a steganalysis technique.

**Step 5 catches re-embedding.** Someone can lift a validly signed payload and
re-embed it at a different depth with a matching header. The body reads cleanly
and the signature verifies, but the depth inside the signed record no longer
matches the header, so it reports Tampered.

**Two independent tamper paths.** Editing bytes *inside* the payload region breaks
the signature (`Signature Invalid`). Editing the media *outside* it, above the LSB
planes, leaves the signature perfectly valid and is caught by the hash instead
(`Tampered`). Different mechanisms, different verdicts.

## Keys

`keys/demo_private.pem` is committed on purpose. It was generated only for this
assignment, is used only to sign demo files, and protects nothing real — the
specification permits this so the marker can reproduce every result. A real
deployment would never publish a private key; the signer would hold it and
distribute only `demo_public.pem`.

## Limitations

- LSB replacement is statistically detectable. Replacement pairs values, so heavy
  embedding pushes the counts within each pair towards equality, which a
  chi-square test on parity picks up.
- Concealment degrades as depth rises. Verification still returns Authentic at
  `n = 8`; what fails is the hiding, not the security.
- The integrity hash deliberately excludes the lowest `n` bit planes.
- Security rests entirely on the derivation key. Steganography adds obscurity,
  not strength.
- The signature proves origin, not provenance. It shows a key holder protected
  this file at this time, not that the recording is a truthful capture of anything.
- No robustness to processing. Recompression, resampling or format conversion
  destroys the payload — re-saving a stego PNG as JPEG loses it entirely.
- The derivation key is typed into a web form. On `127.0.0.1` that is fine, but
  over a network it would need HTTPS.

## Status

Phases 0 and 1 complete: security foundations, shared bit operations, the PNG
codec and the full verdict tree, all covered by the test suite. A protected and
a tampered sample are in `testFiles/`.

Audio codec and the web interface follow.
