"""Flask server that receives signed messages and serves them back.

Local run (HTTPS, self-signed):   python server/app.py
Hosted (e.g. Render):             gunicorn --chdir server app:app
When the PORT environment variable is set, TLS is assumed to be terminated by the platform.
"""
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request, send_file

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import parse_signed_text

app = Flask(__name__, static_folder="static", static_url_path="/")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KB is plenty for a message + signature

SERVER_DIR = Path(__file__).resolve().parent
BASE_DIR = SERVER_DIR.parent
RECEIVER_FOLDER = BASE_DIR / "receiver"
CHECKED_MESSAGE_PATH = RECEIVER_FOLDER / "checked_message.txt"
CERT_FILE = SERVER_DIR / "cert.pem"
KEY_FILE = SERVER_DIR / "key.pem"

RECEIVER_FOLDER.mkdir(exist_ok=True)


@app.route("/api/receive", methods=["POST"])
def receive_message():
    signed_message = request.form.get("signed_message", "")
    if not signed_message.strip():
        return jsonify({"error": "No signed message received."}), 400

    try:
        message, signature = parse_signed_text(signed_message)
    except ValueError as exc:
        return jsonify({"error": f"Invalid format: {exc}"}), 400

    # Normalise line endings (browsers send CRLF) so verification sees what was signed.
    CHECKED_MESSAGE_PATH.write_text(f"{message}\n{signature}")
    return jsonify({"success": "Message received and saved successfully."})


@app.route("/api/download", methods=["GET"])
def download_message():
    if not CHECKED_MESSAGE_PATH.exists():
        return jsonify({"error": "No checked message found to download."}), 404
    return send_file(CHECKED_MESSAGE_PATH, as_attachment=True)


@app.route("/")
def home():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    if os.environ.get("PORT"):
        app.run(host="0.0.0.0", port=port)  # hosted: platform handles TLS
    elif CERT_FILE.exists() and KEY_FILE.exists():
        app.run(host=host, port=port, ssl_context=(str(CERT_FILE), str(KEY_FILE)))
    else:
        # No certificate files: Flask generates a temporary self-signed one (needs `cryptography`).
        app.run(host=host, port=port, ssl_context="adhoc")
