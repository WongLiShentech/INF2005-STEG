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
| `flask --app app run` | Starts the web interface at http://127.0.0.1:5000 |
| `pytest` | Runs the test suite. Everything should pass before you commit. |
| `python make_demo_files.py` | Rebuilds every sample in `testFiles/` and writes `evidence/demo_run_log.txt`. |
| `python generate_key.py` | Creates a fresh demo keypair. Only needed if you delete `keys/`. |

Run `make_demo_files.py` after any change to the payload format, the key
derivation or the demo messages, or the committed samples will no longer match
the code that reads them.

## Project layout

```
app.py             Flask routes: upload, protect, verify, capacity, serve media
workflow.py        protect() and verify() end to end, including the verdict tree
image_helpers.py   PNG load/save, carrier array, capacity, seed string
audio_helpers.py   WAV/PCM load/save, carrier array, capacity, seed string
video_helpers.py   Lossless AVI (FFV1) load/save, carrier array, capacity, seed string
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

All three media types are reduced to a flat array of integer carrier units —
image channel values, audio samples, or video frame pixels — so the LSB
replacement code in `stego_utils.py` is written once and shared.
`image_helpers.py`, `audio_helpers.py` and `video_helpers.py` differ only in
how they load and save that array.

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

The offset may be chosen outright or, by default, derived. A chosen offset can
reach anywhere in the carrier; a derived one lands in the first half. Either
way it is never written into the file — the verifier has to know where to look
before it can read anything, so a chosen offset travels out of band alongside
the passphrase, and deriving it means nothing extra has to travel at all.

Deriving is the stronger option and is what the samples use. A number a person
picks by hand tends to be round and near the start, which is where anyone
searching would look first.

The derivation:

```
location_key, message_key = HKDF-SHA256(passphrase)
offset = HMAC-SHA256(location_key, seed) mod (usable_units // 2)
```

The user types one passphrase, but placing the payload and encrypting the
message are unrelated jobs, and tying both to the same bytes would mean
anything that weakened one weakened the other. HKDF expands the passphrase into
two independent 32-byte subkeys with a distinct info string each, so recovering
one tells an attacker nothing about the other.

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

### 5. Message confidentiality

Steganography hides that a message exists. It does not protect the message once
found: without a cipher, anyone who learns the start location reads the text
straight out of the carrier. Concealment is not confidentiality, so encryption
is offered per message and recorded in both the header flag and the signed
record.

AES-256-GCM, keyed by the message subkey, with a random 12-byte nonce per
message. GCM is authenticated encryption, so a modified ciphertext fails to open
rather than decrypting to garbage.

`msg_sha256` covers the bytes **as stored** — ciphertext when encrypted. That is
deliberate twice over. The verifier can confirm the extracted bytes are intact
before it tries to decrypt them, and no plaintext fingerprint travels in a
record that is readable in the clear: digesting the plaintext of a short,
guessable message would let it be recovered by hashing candidates until one
matched, undoing the encryption. Plaintext integrity is not lost, because GCM's
tag covers it and the tag sits inside the ciphertext the digest commits to.

### 6. Payload

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

### 7. Serving an extracted payload

The interface displays an extracted image and plays extracted audio, rather
than only reporting that a payload was found.

The content type is decided by reading the payload's own leading bytes, never
its name. `msg_name` travels inside the payload, so it is chosen by whoever
protected the file: letting it pick a content type would allow a hidden
`note.html` containing script to be served back as markup and run in the
verifying browser. Anything not positively identified is sent as a generic
attachment, so an extracted file is never interpreted by the browser checking
it.

### 8. Attack simulation

`attacks.py` stages eight attacks against a protected file and states the
verdict each should produce. Six mutate a copy of the file; two are mistakes
made at verification time. Running them together turns the negative cases from
a set of hand-made files into something reproducible against any protected
object, and `make_demo_files.py` runs the whole set as part of generating the
samples.

The most useful of them is the replay: a genuine, correctly signed payload is
lifted out of one file and dropped into another. Nothing is forged and the
signature verifies perfectly. What the record no longer describes is the file
it now sits in, and only the media hash can tell. It is the clearest argument
for why the hash is needed at all.

Two attacks are included because they do **not** produce the verdict we would
want, and the module reports the reason rather than omitting the case:

- **Retouching at 8 LSB goes undetected.** The integrity hash masks the lowest
  `n` bits, so at `n = 8` it masks every bit of every value and is computed over
  constant zeros. It cannot see any edit. The payload is still authentic; the
  media is not, and the system cannot tell.
- **Replay within one cover succeeds.** Two protections of the same cover share
  a masked media hash, so a record moved between them still describes the file
  it lands in. The record binds to media content, not to one instance of it. A
  per-instance binding would need something the cover itself cannot supply.

### 9. Verdicts

| Step | Check | Verdict on failure |
|---|---|---|
| 1 | File opens as PNG/WAV | Cannot Verify |
| 2 | Magic found at the derived offset | Payload Missing / Wrong Start Location |
| 3 | Version known, lengths within capacity | Cannot Verify |
| 4 | Signature valid under the public key | Signature Invalid |
| 5 | Signed `lsb_n` matches header `lsb_n` | Tampered |
| 6 | Signed `msg_encrypted` matches the header flag | Tampered |
| 7 | Extracted message matches `msg_sha256` | Tampered |
| 8 | Ciphertext opens under the message subkey | Cannot Verify |
| 9 | Recomputed canonical hash matches | Tampered |
| 10 | — | Authentic |

Every check is recorded as it runs and returned with the verdict, so the
interface can show the comparison each step made — both hashes side by side,
not just the word `Tampered`. The trail stops at the first failure.

Step 4 comes before the JSON is parsed: untrusted input should be authenticated
before it is interpreted.

Steps 2, 5 and 6 need a word of explanation.

**Payload Missing vs Wrong Start Location.** A missing magic value has two causes:
the file never carried a payload, or the key was wrong so we are looking in the
wrong place. We tell them apart with a bounded scan — if the magic turns up
elsewhere, the payload exists and the derivation was wrong. The scan is capped
deliberately, because an unbounded one would itself be a steganalysis technique.

**Steps 5 and 6 reconcile the unsigned header.** The header has to be readable
before anything is authenticated, so it travels unsigned. Both of the fields
that change how the body is interpreted — the depth and the encryption flag —
therefore have a signed counterpart, and a mismatch is reported as tampering.

**Step 5 catches re-embedding.** Someone can lift a validly signed payload and
re-embed it at a different depth with a matching header. The body reads cleanly
and the signature verifies, but the depth inside the signed record no longer
matches the header, so it reports Tampered.

**Two independent tamper paths.** Editing bytes *inside* the payload region breaks
the signature (`Signature Invalid`). Editing the media *outside* it, above the LSB
planes, leaves the signature perfectly valid and is caught by the hash instead
(`Tampered`). Different mechanisms, different verdicts.

### 10. Video cover object (optional challenge)

Video is not required by the spec, only permitted as an optional extension.
The design goal was to add it without writing a second embedding path:
`video_helpers.py` reads every frame of a clip into one `(frames, height,
width, 3)` array and flattens it exactly the way `image_helpers.py` flattens
a single frame's pixel grid. Once flattened, it is indistinguishable from an
image carrier to everything downstream — `stego_utils.py`, `workflow.py` and
`security.py` needed no changes at all.

That has a direct consequence for start-location security (FR7). The keyed
offset derivation was already confined to the first half of the carrier, for
the same reason it is for images: a payload has to land *somewhere*, and
which frame(s) it lands in falls straight out of where that offset happens
to sit inside the flattened array. No separate "pick a frame" step was
designed or is needed — the existing pixel-level derivation already secures
a frame-level decision, because a video's carrier is only pixels with one
more dimension folded in before the flatten.

**Output is always lossless AVI, written with the FFV1 codec.** The same
"we never write JPEG" rule `image_helpers.py` already enforces for images
applies here: FFV1 was chosen over MJPEG, raw/uncompressed AVI and HuffYUV
after a round-trip spike confirmed it is the only one of the four, among the
codecs available through OpenCV's bundled FFmpeg backend on this machine,
that returns bit-exact frames — MJPEG and raw AVI both altered pixel values
on read-back, which would have silently corrupted the low bits the payload
lives in. Input can be a wider set of containers (MP4, MOV, MKV) than we
ever write, mirroring how an image cover can be uploaded as JPEG even though
protected output is always PNG.

**The masked media hash covers every frame**, not only the frame(s) the
payload happened to land in — `security.masked_hash()` is called on the
whole flattened carrier, unchanged from the image and audio paths. An edit
to any frame, whether or not it carries payload bits, is caught by `Tampered`
the same way an edit anywhere in an image or a waveform already is.

**No browser reliably plays the protected file back.** FFV1-in-AVI is
bit-exact, which is what verification needs, but it is not something any
major browser's `<video>` element is guaranteed to decode — an attempt to
switch the codec itself to lossless H.264 (CRF/QP 0, universally
browser-playable) found that this OpenCV build has no H.264 encoder
available at all. Every check, hash and verdict is still computed correctly
against the real file regardless — this is a display limitation, not a
correctness one — but seeing a video cover or stego object play in the
interface itself cannot be relied on; download the file and open it in a
dedicated player (VLC, ffplay) to actually watch it.

Uncompressed frame data is large, stated openly rather than hidden: a short,
modest-resolution demo clip (320×240, a few seconds) runs a few megabytes to
a few tens of megabytes once written losslessly, and the whole clip is held
in memory as one NumPy array during both protection and verification. This
is the video equivalent of the existing PNG-not-JPEG and WAV-not-MP3
trade-off, just more visible: a longer or higher-resolution source video
needs proportionally more memory and produces a proportionally larger stego
file. The walkthrough demo's video samples are kept deliberately short and
small for this reason.

## Interface

Three pages, one job each: **Protect** embeds and signs, **Verify** checks and
explains, **Attack** stages the failure cases.

The verdict is the loudest thing on the page and everything else is kept quiet
around it. Beneath it, each check that weighed two values against each other
prints both, aligned in the same columns and set in a monospaced face, so a
divergence is visible by eye rather than asserted in prose — a reader can see
*where* two digests part company, not merely that they do.

Amber carries the interface: focus rings, the active tab, the primary button.
Green and red are reserved for pass and fail alone, so nothing decorative ever
competes with the one distinction the tool exists to draw.

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
  destroys the payload — re-saving a stego PNG as JPEG, or a stego WAV as MP3,
  loses it entirely.
- Audio hides less than it appears to. A quiet or near-silent passage has
  little to mask the altered low bits, so depth that is inaudible in music can
  be plainly audible in speech with pauses.
- 24-bit PCM is unsupported: its samples have no native integer width, so they
  cannot be addressed as whole carrier units without a bespoke packing step.
- Protected video is written uncompressed (FFV1), so a stego file is
  routinely several times the size of a normally-encoded source clip, and a
  long or high-resolution clip loads the entire frame stack into memory at
  once. Frame count is read by decoding to the end rather than trusted from
  container metadata, because some containers misreport it.
- No browser reliably plays the protected AVI/FFV1 file back in the
  interface itself. Every check, hash and verdict is still computed
  correctly against the real file — this is a display limitation, not a
  correctness one — but a video cover or stego object should be downloaded
  and opened in a dedicated player to actually watch it.
- Encryption protects the message, not the record. The payload JSON — media ID,
  timestamp, team, issuer — is readable by anyone who finds the start location,
  because the verifier has to read it before deciding anything.
- A hand-chosen start location is only as good as the number chosen. The
  derivation exists because people pick round numbers near the beginning.
- The derivation key is typed into a web form. On `127.0.0.1` that is fine, but
  over a network it would need HTTPS.
- An extracted payload is still untrusted content. We fix its content type
  ourselves and refuse to serve anything unrecognised inline, but a verified
  signature only proves who protected the file, not that its payload is safe
  to open.
- Comparing the stego object against the original is a convenience, not part of
  verification. A real verifier rarely holds the original, which is why the
  verdict is reached from the received file alone.

## Sample files

Rebuild all of these with `python make_demo_files.py`. The passphrase is
`team demo key`.

| File | Case |
|---|---|
| `protected/P1_image_short_n2.png` | Image, short message, 2 LSB, plaintext |
| `protected/P2_audio_large_n4.wav` | Audio, large message, 4 LSB, plaintext |
| `protected/P3_image_custom_encrypted_n3.png` | Image, custom payload, 3 LSB, encrypted |
| `protected/P4_audio_custom_encrypted_n2.wav` | Audio, custom payload, 2 LSB, encrypted |
| `tampered/N1_image_edited.png` | Media edited outside the payload region |
| `tampered/N6_audio_payload_bits_flipped.wav` | Payload bytes altered |
| `tampered/N7_not_an_image.png` | Not a media file, renamed |
| `tampered/N8_audio_replayed_payload.wav` | Genuine payload replayed into another cover |
| `protected/P5_video_short_n2.avi` | Video (optional cover object), short message, 2 LSB, plaintext |
| `tampered/N9_video_edited.avi` | Video media edited outside the payload region |
| `original/small_cover.png` | Too small to hold the large message |

The remaining negative cases need no file of their own: `other_public.pem`
against `P2` gives Signature Invalid, the wrong passphrase against `P1` gives
Wrong Start Location, and either untouched cover gives Payload Missing.

All six verdict categories are reachable, and `make_demo_files.py` demonstrates
every one of them.

## Status

Image and audio codecs, key separation, message encryption, the full verdict
tree and the web interface are complete and covered by the test suite. The
optional video cover object (FR13/optional challenge) shares the same
verdict tree, capacity math and start-location derivation unchanged, backed
by a lossless (FFV1) AVI codec in `video_helpers.py`. Every sample in
`testFiles/` is regenerated by `make_demo_files.py`, which also writes the
run log in `evidence/`.
