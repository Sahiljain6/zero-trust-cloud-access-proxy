"""Educational zero-trust cloud access proxy simulation.

The application demonstrates an active-device allowlist and HMAC-SHA256
payload integrity verification. EAP/NAC checks and cloud forwarding are
simulated; this is not a production gateway or a post-quantum implementation.
"""

import base64
import hashlib
import hmac
import os
import re

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
MAX_DEVICE_ID_LENGTH = 100
MAX_PAYLOAD_LENGTH = 8_000

# Demo fallback keeps the educational demo runnable without configuration.
# Set PROXY_SHARED_SECRET outside source control for local/private deployments.
# This fallback is public demo material and is not suitable for production.
SHARED_SECRET = os.environ.get(
    "PROXY_SHARED_SECRET", "cns_secure_proxy_key_2026"
).encode("utf-8")

# A simple in-memory device registry for the EAP/NAC-inspired demonstration.
# This registry is not a real identity provider or an 802.1X/EAP implementation.
AUTHORIZED_DEVICES = {
    "device_node_01": "active",
    "admin_node": "active",
}


def secure_payload(data: str, secret_key: bytes) -> dict:
    """Encode text and produce an HMAC-SHA256 integrity tag for the demo."""
    message_bytes = data.encode("utf-8")
    integrity_tag = hmac.new(
        secret_key, message_bytes, hashlib.sha256
    ).hexdigest()
    encoded_data = base64.b64encode(message_bytes).decode("ascii")
    return {"payload": encoded_data, "integrity_hash": integrity_tag}


def authenticate_and_forward(device_id: str, client_request: dict) -> dict:
    """Check simulated device authorization and verify the payload integrity.

    The return message describes simulated forwarding only; no cloud resource
    or upstream service is contacted by this function.
    """
    if AUTHORIZED_DEVICES.get(device_id) != "active":
        return {
            "status": "error",
            "message": (
                "Access Denied: EAP-style device authorization failed "
                "(Zero-Trust policy violation)."
            ),
        }

    if not isinstance(client_request, dict):
        return {"status": "error", "message": "Malformed payload."}

    encoded_payload = client_request.get("payload")
    received_hash = client_request.get("integrity_hash")
    if not isinstance(encoded_payload, str) or not isinstance(received_hash, str):
        return {"status": "error", "message": "Malformed payload."}
    if not re.fullmatch(r"[0-9a-f]{64}", received_hash):
        return {"status": "error", "message": "Malformed payload."}

    try:
        received_bytes = base64.b64decode(encoded_payload, validate=True)
        decoded_message = received_bytes.decode("utf-8")
        expected_hash = hmac.new(
            SHARED_SECRET, received_bytes, hashlib.sha256
        ).hexdigest()
    except (ValueError, UnicodeDecodeError):
        return {"status": "error", "message": "Malformed payload."}

    # Compare tags in constant time rather than using ordinary string equality.
    if not hmac.compare_digest(expected_hash, received_hash):
        return {
            "status": "error",
            "message": (
                "Security Alert: Payload integrity mismatch "
                "(potential tampering detected)."
            ),
        }

    return {
        "status": "success",
        "message": (
            "Access Granted: Device and payload checks passed. "
            "Simulated cloud proxy accepted payload -> "
            f"{decoded_message}"
        ),
    }


@app.after_request
def add_security_headers(response):
    """Add baseline browser headers appropriate for this small demo."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/simulate")
def simulate():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"status": "error", "message": "Expected a JSON object."}), 400

    device_id = body.get("device_id")
    data = body.get("data")
    tamper_payload = body.get("tamper_payload", False)

    if not isinstance(device_id, str) or not device_id.strip():
        return jsonify({"status": "error", "message": "Device ID is required."}), 400
    device_id = device_id.strip()
    if len(device_id) > MAX_DEVICE_ID_LENGTH:
        return jsonify({"status": "error", "message": "Device ID is too long."}), 400
    if not isinstance(data, str):
        return jsonify({"status": "error", "message": "Data payload must be text."}), 400
    if len(data) > MAX_PAYLOAD_LENGTH:
        return jsonify({"status": "error", "message": "Data payload is too long for this demo."}), 400
    if not isinstance(tamper_payload, bool):
        return jsonify({"status": "error", "message": "tamper_payload must be a boolean."}), 400

    # The server creates the sample tag so the shared key never needs to be
    # embedded in browser code. The checkbox intentionally corrupts that tag.
    client_request = secure_payload(data, SHARED_SECRET)
    if tamper_payload:
        original_hash = client_request["integrity_hash"]
        replacement = "0" if original_hash[0] != "0" else "1"
        client_request["integrity_hash"] = replacement + original_hash[1:]

    return jsonify(authenticate_and_forward(device_id, client_request))


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(_error):
    return jsonify({"status": "error", "message": "Request is too large for this demo."}), 413


@app.errorhandler(400)
def handle_bad_request(_error):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "Invalid JSON request."}), 400
    return "Bad request.", 400


@app.errorhandler(404)
def handle_not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "API route not found."}), 404
    return "Page not found.", 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
