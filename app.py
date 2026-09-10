"""Web interface. Routes validate input and display results; the security
workflow itself lives in workflow.py."""

import hashlib
import json
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

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
def protect_page():
    return render_template("protect.html")


@app.get("/verify")
def verify_page():
    return render_template("verify.html", public_keys=available_public_keys())


@app.get("/media/<path:filename>")
def media(filename):
    return send_from_directory(WORKSPACE, filename)


@app.post("/upload")
def upload():
    """Store a cover object and report its capacity at every depth at once,
    so moving the depth selector needs no further round trip."""
    try:
        stored, path = store_upload("file")
        media_object = workflow.load_media(path)
        report = workflow.capacity_report(media_object, derivation_key())
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

        context["cover_url"] = url_for("media", filename=stored)
        context["cover"] = workflow.load_media(cover_path).describe()

        output_name = f"{uuid.uuid4().hex[:8]}_stego.png"
        report = workflow.protect(
            cover_path,
            WORKSPACE / output_name,
            message,
            message_name,
            key,
            lsb_n,
            security.load_private_key(DEFAULT_PRIVATE_KEY),
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

        result = workflow.verify(path, key, public_key)
        context["result"] = result

        if result.payload:
            context["payload_json"] = json.dumps(result.payload, indent=2)
        if result.message:
            context.update(present_message(result))
    except (InputError, OSError, ValueError) as exc:
        context["error"] = str(exc)

    return render_template("verify.html", **context)


def present_message(result):
    """Show a text payload inline; offer any other payload as a download."""
    name = result.payload.get("msg_name", "payload.bin")
    stored = f"{uuid.uuid4().hex[:8]}_{secure_filename(name)}"
    (WORKSPACE / stored).write_bytes(result.message)

    context = {"message_url": url_for("media", filename=stored), "message_name": name}
    try:
        context["message_text"] = result.message.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return context


@app.errorhandler(413)
def too_large(_):
    return render_template("protect.html", error="that file is larger than the 32 MB limit"), 413


if __name__ == "__main__":
    app.run(debug=True)
