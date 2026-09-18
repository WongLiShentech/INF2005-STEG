"""Web interface. Routes validate input and display results; the security
workflow itself lives in workflow.py."""

import hashlib
import json
import shutil
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

import attacks
import make_demo_files
import security
import workflow

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

ROOT = Path(app.root_path)
WORKSPACE = ROOT / "workspace"
DEFAULT_PUBLIC_KEY = ROOT / "keys" / "demo_public.pem"
DEFAULT_PRIVATE_KEY = ROOT / "keys" / "demo_private.pem"

MEDIA_SUFFIXES = {".png", ".bmp", ".jpg", ".jpeg", ".wav"}
KEY_SUFFIXES = {".pem"}

WORKSPACE.mkdir(exist_ok=True)


class InputError(Exception):
    pass


def store_upload(field, allowed=MEDIA_SUFFIXES, required=True):
    """Save an uploaded file under a fresh name and return (stored name, path).

    The client-supplied filename is never trusted as a path, and the suffix
    whitelist keeps arbitrary uploads out of the workspace.
    """
    upload = request.files.get(field)
    if upload is None or not upload.filename:
        if required:
            raise InputError("choose a file first")
        return None, None

    name = secure_filename(upload.filename)
    suffix = Path(name).suffix.lower()
    if suffix not in allowed:
        raise InputError(f"{suffix or 'that file'} is not an accepted format")

    stored = f"{uuid.uuid4().hex[:8]}_{name}"
    path = WORKSPACE / stored
    upload.save(path)
    return stored, path


def chosen_offset():
    """The start location the user typed, or None to derive it."""
    raw = (request.form.get("offset") or "").strip().replace(",", "")
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise InputError("the start location must be a whole number, or left blank")
    if value < 0:
        raise InputError("the start location cannot be negative")
    return value


def derivation_key():
    key = request.form.get("key", "").strip()
    if not key:
        raise InputError("a derivation key is required")
    return key.encode()


def message_from_form():
    upload = request.files.get("message_file")
    if upload is not None and upload.filename:
        name = secure_filename(upload.filename)
        return upload.read(), name

    text = request.form.get("message", "")
    if not text.strip():
        raise InputError("enter a message or choose a payload file")
    return text.encode(), "message.txt"


def available_public_keys():
    return sorted(path.name for path in (ROOT / "keys").glob("*_public.pem"))


def public_key_from_form():
    """An uploaded key wins; otherwise use the one picked from keys/."""
    _, uploaded = store_upload("public_key", allowed=KEY_SUFFIXES, required=False)
    source = uploaded
    if source is None:
        chosen = secure_filename(request.form.get("public_key_name", DEFAULT_PUBLIC_KEY.name))
        source = ROOT / "keys" / chosen
        if not source.exists():
            raise InputError(f"{chosen} is not in the keys folder")

    pem = source.read_bytes()
    fingerprint = hashlib.sha256(pem).hexdigest()[:16]
    return security.load_public_key(source), source.name, fingerprint


@app.get("/")
@app.get("/walkthrough")
def walkthrough_page():
    return render_template("walkthrough.html")


@app.get("/protect")
def protect_page():
    return render_template("protect.html")


@app.get("/verify")
def verify_page():
    return render_template("verify.html", public_keys=available_public_keys())


@app.get("/media/<path:filename>")
def media(filename):
    return send_from_directory(WORKSPACE, filename)


@app.get("/payload/<path:filename>")
def payload(filename):
    """Serve an extracted message under a content type we determined ourselves.

    Anything we cannot positively identify is sent as an attachment with a
    generic type, so an extracted file is never interpreted as markup by the
    browser that is checking it.
    """
    path = WORKSPACE / secure_filename(filename)
    if not path.is_file():
        abort(404)

    kind, mimetype = sniff_payload(path.read_bytes())
    inline = kind in {"image", "audio", "text"}
    return send_from_directory(
        WORKSPACE,
        path.name,
        mimetype=mimetype,
        as_attachment=not inline,
        download_name=path.name,
    )


@app.post("/upload")
def upload():
    """Store a cover object and report its capacity at every depth at once,
    so moving the depth selector needs no further round trip."""
    try:
        stored, path = store_upload("file")
        media_object = workflow.load_media(path)
        report = workflow.capacity_report(media_object, derivation_key(), chosen_offset())
    except (InputError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(
        {
            "stored": stored,
            "describe": media_object.describe(),
            "url": url_for("media", filename=stored),
            **report,
        }
    )


@app.post("/capacity")
def capacity():
    """Recompute the offset when the derivation key changes."""
    try:
        path = WORKSPACE / secure_filename(request.form["stored"])
        report = workflow.capacity_report(workflow.load_media(path), derivation_key())
    except (InputError, KeyError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(report)


@app.post("/protect")
def protect():
    context = {}
    try:
        stored, cover_path = store_upload("file")
        key = derivation_key()
        lsb_n = int(request.form.get("lsb_n", 1))
        message, message_name = message_from_form()

        kind = workflow.media_kind(cover_path)
        context["cover_url"] = url_for("media", filename=stored)
        context["cover"] = workflow.load_media(cover_path).describe()
        context["kind"] = kind

        # The protected file has to keep its own kind: a WAV written with a
        # .png suffix would be unopenable by either decoder.
        output_name = f"{uuid.uuid4().hex[:8]}_stego{workflow.STEGO_SUFFIX[kind]}"
        report = workflow.protect(
            cover_path,
            WORKSPACE / output_name,
            message,
            message_name,
            key,
            lsb_n,
            security.load_private_key(DEFAULT_PRIVATE_KEY),
            encrypt=request.form.get("encrypt") == "on",
            offset=chosen_offset(),
        )

        context["report"] = report
        context["payload_json"] = json.dumps(report.payload, indent=2)
        context["stego_url"] = url_for("media", filename=output_name)
    except workflow.CapacityError as exc:
        context["capacity_error"] = str(exc)
    except (InputError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        context["error"] = str(exc)

    return render_template("protect.html", **context)


@app.post("/verify")
def verify():
    context = {"public_keys": available_public_keys()}
    try:
        stored, path = store_upload("file")
        key = derivation_key()
        public_key, key_name, fingerprint = public_key_from_form()

        context["stego_url"] = url_for("media", filename=stored)
        context["key_name"] = key_name
        context["key_fingerprint"] = fingerprint
        context["kind"] = workflow.media_kind(path)

        # Optional: the untouched cover, so the two can be compared on screen.
        original_name, original_path = store_upload("original", required=False)
        if original_name:
            context["cover_url"] = url_for("media", filename=original_name)
            context["cover_kind"] = workflow.media_kind(original_path)

        result = workflow.verify(path, key, public_key, chosen_offset())
        context["result"] = result

        if result.payload:
            context["payload_json"] = json.dumps(result.payload, indent=2)
        if result.message:
            context.update(present_message(result))
    except (InputError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        context["error"] = str(exc)

    return render_template("verify.html", **context)


# Sniffed from the bytes themselves, never from the name. The name travels
# inside the payload, so it is chosen by whoever protected the file: trusting
# it to pick a content type would let a hidden "note.html" full of script be
# served back as HTML and run in the verifier's browser.
MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image", "image/png"),
    (b"\xff\xd8\xff", "image", "image/jpeg"),
    (b"GIF87a", "image", "image/gif"),
    (b"GIF89a", "image", "image/gif"),
    (b"BM", "image", "image/bmp"),
)


def sniff_payload(data):
    """Return (kind, mimetype) for an extracted message."""
    for prefix, kind, mimetype in MAGIC:
        if data.startswith(prefix):
            return kind, mimetype
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "audio", "audio/wav"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", "application/octet-stream"
    return "text", "text/plain"


def present_message(result):
    """Render a payload the GUI can display or play; offer the rest as a
    download. The spec asks the interface to play or execute the payload, not
    just report that one was found."""
    name = result.payload.get("msg_name", "payload.bin")
    kind, mimetype = sniff_payload(result.message)

    stored = f"{uuid.uuid4().hex[:8]}_{secure_filename(name)}"
    (WORKSPACE / stored).write_bytes(result.message)

    context = {
        "message_url": url_for("payload", filename=stored),
        "message_name": name,
        "message_kind": kind,
        "message_bytes": len(result.message),
    }
    if kind == "text":
        context["message_text"] = result.message.decode("utf-8")
    return context


@app.get("/attack")
def attack_page():
    return render_template("attack.html", attacks=attacks.ATTACKS, keys=available_public_keys())


@app.post("/attack")
def attack():
    context = {"attacks": attacks.ATTACKS, "keys": available_public_keys()}
    try:
        stored, path = store_upload("file")
        _, target = store_upload("target", required=False)
        public_key, key_name, fingerprint = public_key_from_form()

        outcomes = attacks.run_all(
            path, derivation_key(), public_key, WORKSPACE, target, chosen_offset()
        )
        context.update(
            outcomes=outcomes,
            stego_url=url_for("media", filename=stored),
            kind=workflow.media_kind(path),
            key_name=key_name,
            key_fingerprint=fingerprint,
            ran=sum(1 for o in outcomes if o.ran),
            matched=sum(1 for o in outcomes if o.as_expected),
        )
    except (InputError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        context["error"] = str(exc)
    return render_template("attack.html", **context)


@app.errorhandler(413)
def too_large(_):
    if request.path.startswith("/api/"):
        return jsonify(error="that request is larger than the 32 MB limit"), 413
    return render_template("protect.html", error="that file is larger than the 32 MB limit"), 413


def walkthrough_samples():
    directory = ROOT / "testFiles" / "original"
    make_demo_files.make_walkthrough_samples(directory)
    return {
        name: (directory / name, label, kind)
        for name, label, kind, _size in make_demo_files.WALKTHROUGH_SAMPLES
    }


def walkthrough_cover():
    upload = request.files.get("file")
    if upload and upload.filename:
        return store_upload("file")[1]
    samples = walkthrough_samples()
    name = request.form.get("sample", "")
    if name not in samples:
        raise InputError("choose a cover first")
    source = samples[name][0]
    target = WORKSPACE / f"{uuid.uuid4().hex}{source.suffix}"
    shutil.copyfile(source, target)
    return target


@app.before_request
def check_walkthrough_origin():
    # Reject cross-origin browser submissions to the state-changing demo API.
    if request.path.startswith("/api/") and request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            abort(403)


@app.get("/api/options")
def walkthrough_options():
    samples = [
        {"name": name, "label": label, "kind": kind, "default": label == "Medium",
         "description": workflow.load_media(path).describe()}
        for name, (path, label, kind) in walkthrough_samples().items()
    ]
    return jsonify(samples=samples, keys=available_public_keys())


@app.get("/sample/<name>")
def walkthrough_sample(name):
    samples = walkthrough_samples()
    if name not in samples:
        abort(404)
    return send_from_directory(samples[name][0].parent, name)


@app.post("/api/capacity")
def walkthrough_capacity():
    cover = None
    try:
        offset = chosen_offset()
        has_key = bool(request.form.get("key", "").strip())
        key = derivation_key() if has_key else b""
        upper_bound = not has_key and offset is None
        if upper_bound:
            offset = 0  # Maximum capacity, not a derived start position.
        cover = walkthrough_cover()
        media_object = workflow.load_media(cover)
        report = workflow.capacity_report(media_object, key, offset)
        report["upper_bound"] = upper_bound
        if "payload_size" in request.form:
            size = int(request.form["payload_size"])
            depth = int(request.form.get("lsb_n", 2))
            if size < 0 or not 1 <= depth <= 8:
                raise ValueError("invalid payload size or LSB depth")
            encrypted = request.form.get("encrypt") == "on" and size > 0
            stored_size = size + (report["encryption_overhead"] if encrypted else 0)
            name = secure_filename(request.form.get("payload_name", "message.txt"))
            # Only lengths are needed: hashes, nonce and IDs have fixed lengths.
            # Use the same record serializer and unit rounding as protection.
            record = security.build_payload(media_object.media_type, "0" * 64,
                                            depth, b"", name, encrypted)
            record["msg_len"] = stored_size
            record_size = len(security.canonical_json(record))
            signature_size = security.load_private_key(DEFAULT_PRIVATE_KEY).key_size // 8
            needed = workflow.units_required(depth, record_size, signature_size, stored_size)
            report.update(stored_bytes=stored_size,
                          required_bytes=record_size + signature_size + stored_size,
                          fits=report["offset"] + needed <= report["units"])
        return jsonify(description=media_object.describe(), **report)
    except (InputError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        return jsonify(error=str(exc)), 400
    finally:
        if cover is not None:
            cover.unlink(missing_ok=True)


@app.post("/api/protect")
def walkthrough_protect():
    cover = output = None
    try:
        key, offset = derivation_key(), chosen_offset()
        depth = int(request.form.get("lsb_n", 2))
        message, name = message_from_form()
        cover = walkthrough_cover()
        kind = workflow.media_kind(cover)
        run_id = uuid.uuid4().hex
        output = WORKSPACE / f"{run_id}_stego{workflow.STEGO_SUFFIX[kind]}"
        report = workflow.protect(
            cover, output, message, name, key, depth,
            security.load_private_key(DEFAULT_PRIVATE_KEY),
            encrypt=request.form.get("encrypt") == "on", offset=offset,
        )
        evidence = workflow.protection_evidence(cover, report)
        # Retain only filenames and depth, never the passphrase or private key.
        (WORKSPACE / f"{run_id}_run.json").write_text(json.dumps({
            "cover": cover.name, "output": output.name, "depth": depth,
        }), encoding="utf-8")
        return jsonify(
            id=run_id, kind=kind, cover=url_for("media", filename=cover.name),
            output=url_for("media", filename=output.name), **evidence,
        )
    except (InputError, workflow.CapacityError, workflow.UnsupportedMedia, OSError, ValueError) as exc:
        for path in (cover, output):
            if path is not None:
                path.unlink(missing_ok=True)
        return jsonify(error=str(exc)), 400


def walkthrough_run():
    run_id = request.form.get("id", "")
    if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
        raise InputError("protect a cover first; invalid run identifier")
    manifest = WORKSPACE / f"{run_id}_run.json"
    if not manifest.is_file():
        raise InputError("that protected file is no longer available")
    run = json.loads(manifest.read_text(encoding="utf-8"))
    for field in ("cover", "output"):
        name = run.get(field, "")
        if not name or secure_filename(name) != name:
            raise InputError("invalid stored filename")
        path = (WORKSPACE / name).resolve()
        if path.parent != WORKSPACE.resolve() or not path.is_file():
            raise InputError("stored file is missing or outside the workspace")
        run[field] = path
    return run


@app.post("/api/verify")
def walkthrough_verify():
    tampered = None
    try:
        run = walkthrough_run()
        key, offset = derivation_key(), chosen_offset()
        selected_key = request.form.get("public_key_name", DEFAULT_PUBLIC_KEY.name)
        if selected_key not in available_public_keys():
            raise InputError("choose an available public key")
        public_key = security.load_public_key(ROOT / "keys" / selected_key)
        fingerprint = hashlib.sha256((ROOT / "keys" / selected_key).read_bytes()).hexdigest()
        scenario = request.form.get("scenario", "intact")
        path = run["output"]
        if scenario == "original":
            path = run["cover"]
        elif scenario == "tampered":
            tampered = WORKSPACE / f"{uuid.uuid4().hex}_tampered{path.suffix}"
            attacks.save_bit_flipped_copy(path, tampered, run["depth"])
            path = tampered
        elif scenario != "intact":
            raise InputError("choose a supported test scenario")
        result = workflow.verify(path, key, public_key, offset)
        response = {
            "verdict": result.verdict, "explanation": result.explanation,
            "checks": result.checks, "record": result.payload, "key": selected_key,
            "public_fingerprint": fingerprint, "message_bytes": len(result.message),
            "payload_url": None, "payload_type": None, "message_text": None,
        }
        if result.verdict == workflow.AUTHENTIC and result.message:
            presented = present_message(result)
            _kind, mimetype = sniff_payload(result.message)
            response.update(
                payload_url=presented["message_url"], payload_type=mimetype,
                message_text=presented.get("message_text"),
            )
        return jsonify(response)
    except (InputError, workflow.UnsupportedMedia, OSError, ValueError, KeyError, TypeError) as exc:
        return jsonify(error=str(exc)), 400
    finally:
        if tampered is not None:
            tampered.unlink(missing_ok=True)


if __name__ == "__main__":
    app.run(debug=True)
