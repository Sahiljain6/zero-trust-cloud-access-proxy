"""HTTP routes for the dashboard and zero-trust request pipeline."""
import hmac
import time
import uuid
from flask import current_app, jsonify, render_template, request
from .security import DEVICE_ID_PATTERN, NONCE_PATTERN, SIGNATURE_PATTERN, decode_payload, sign_request
from .storage import get_device, list_audit_events, list_devices, record_audit, record_nonce_and_audit, set_device_active

def _check(name, status, detail):
    return {"name": name, "status": status, "detail": detail}

def _deny(request_id, device_id, reason, http_status, checks, *, audit=True):
    if audit:
        record_audit(request_id, device_id, "DENY", reason)
    return jsonify({"status": "error", "decision": "DENY", "request_id": request_id, "message": reason, "checks": checks}), http_status

def register_routes(app):
    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "zero-trust-cloud-access-proxy"})

    @app.get("/api/devices")
    def api_devices():
        return jsonify({"devices": [{"device_id": d["device_id"], "display_name": d["display_name"], "status": "active" if d["active"] and d["device_id"] in current_app.config["DEVICE_SECRETS"] else "disabled", "created_at": d["created_at"]} for d in list_devices()]})

    @app.get("/api/audit")
    def api_audit():
        return jsonify({"events": list_audit_events(40)})

    @app.post("/api/verify")
    def verify_request():
        request_id = str(uuid.uuid4())
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return _deny(request_id, None, "Expected a JSON object.", 400, [_check("Input validation", "failed", "Request body must be a JSON object.")])
        device_id, payload_b64, timestamp, nonce, signature = (body.get("device_id"), body.get("payload_b64"), body.get("timestamp"), body.get("nonce"), body.get("signature"))
        if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
            return _deny(request_id, None, "Invalid device ID format.", 400, [_check("Input validation", "failed", "Device ID format is invalid.")])
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            return _deny(request_id, device_id, "Invalid request timestamp.", 400, [_check("Input validation", "failed", "Timestamp must be an integer Unix timestamp.")])
        if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
            return _deny(request_id, device_id, "Invalid request nonce.", 400, [_check("Input validation", "failed", "Nonce format is invalid.")])
        if not isinstance(payload_b64, str):
            return _deny(request_id, device_id, "Invalid payload encoding.", 400, [_check("Input validation", "failed", "Payload must be base64-encoded text.")])
        if not isinstance(signature, str) or not SIGNATURE_PATTERN.fullmatch(signature):
            return _deny(request_id, device_id, "Invalid signature format.", 400, [_check("Input validation", "failed", "Signature must be a SHA-256 HMAC in lowercase hexadecimal.")])
        try:
            _raw, payload_text = decode_payload(payload_b64, current_app.config["MAX_PAYLOAD_BYTES"])
        except ValueError as exc:
            return _deny(request_id, device_id, str(exc), 400, [_check("Input validation", "failed", str(exc))])
        checks = [_check("Input validation", "passed", "Request fields and payload format are valid.")]
        device = get_device(device_id)
        secret = current_app.config["DEVICE_SECRETS"].get(device_id)
        if not device or not device["active"] or not secret:
            checks.append(_check("Device authorization", "failed", "Device is unknown, disabled, or has no configured verification key."))
            return _deny(request_id, device_id, "Device authorization failed.", 403, checks)
        checks.append(_check("Device authorization", "passed", "Device is registered and active."))
        now_epoch = int(time.time())
        ttl = int(current_app.config["REQUEST_TTL_SECONDS"])
        if abs(now_epoch - timestamp) > ttl:
            checks.append(_check("Freshness", "failed", f"Request timestamp is outside the allowed {ttl}-second window."))
            return _deny(request_id, device_id, "Request timestamp expired or is too far in the future.", 403, checks)
        checks.append(_check("Freshness", "passed", "Timestamp is within the allowed freshness window."))
        expected = sign_request(device_id, timestamp, nonce, payload_b64, secret)
        if not hmac.compare_digest(expected, signature):
            checks.append(_check("Payload integrity", "failed", "HMAC-SHA256 signature does not match the signed request."))
            return _deny(request_id, device_id, "Payload integrity verification failed.", 403, checks)
        checks.append(_check("Payload integrity", "passed", "HMAC-SHA256 signature matches using constant-time comparison."))
        accepted = record_nonce_and_audit(device_id, nonce, now_epoch, request_id, "Device active; timestamp fresh; HMAC valid; nonce accepted.")
        if not accepted:
            checks.append(_check("Replay protection", "failed", "This nonce has already been used for this device."))
            return _deny(request_id, device_id, "Replay detected: request nonce has already been used.", 409, checks)
        checks.append(_check("Replay protection", "passed", "Nonce has not been seen before and is now recorded."))
        return jsonify({"status": "success", "decision": "ALLOW", "request_id": request_id, "message": "Request accepted by the local zero-trust policy engine. No upstream cloud resource is contacted by this demo.", "payload_preview": payload_text[:240], "checks": checks})

    @app.patch("/api/devices/<device_id>")
    def patch_device(device_id):
        provided = request.headers.get("X-Admin-Token", "")
        expected = current_app.config.get("ADMIN_TOKEN", "")
        if not expected or not hmac.compare_digest(provided, expected):
            return jsonify({"status": "error", "message": "Device management requires a valid admin token."}), 403
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("active"), bool):
            return jsonify({"status": "error", "message": "Expected JSON with an active boolean."}), 400
        if device_id not in current_app.config["DEVICE_SECRETS"]:
            return jsonify({"status": "error", "message": "Device is not configured with a server-side key."}), 404
        if not set_device_active(device_id, body["active"]):
            return jsonify({"status": "error", "message": "Device not found."}), 404
        request_id = str(uuid.uuid4())
        state = "active" if body["active"] else "disabled"
        record_audit(request_id, device_id, "ADMIN", f"Admin changed device state to {state}.")
        return jsonify({"status": "success", "message": f"Device {device_id} is now {state}.", "device_id": device_id, "device_status": state})
