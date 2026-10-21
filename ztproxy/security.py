"""Cryptographic helpers for the signed-request demonstration."""
import base64
import hashlib
import hmac
import re

DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
SIGNATURE_PATTERN = re.compile(r"^[0-9a-f]{64}$")

def canonical_message(device_id, timestamp, nonce, payload_b64):
    """Return the versioned message the client and proxy both sign."""
    return f"v1\n{device_id}\n{timestamp}\n{nonce}\n{payload_b64}".encode("utf-8")

def sign_request(device_id, timestamp, nonce, payload_b64, secret):
    """Create a lowercase hexadecimal HMAC-SHA256 request signature."""
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac.new(key, canonical_message(device_id, timestamp, nonce, payload_b64), hashlib.sha256).hexdigest()

def decode_payload(payload_b64, max_bytes):
    """Decode bounded base64 text and require valid UTF-8 for this text demo."""
    if not isinstance(payload_b64, str) or len(payload_b64) > ((max_bytes + 2) // 3) * 4 + 8:
        raise ValueError("Payload encoding is invalid or too large.")
    try:
        raw = base64.b64decode(payload_b64, validate=True)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Payload must be valid base64-encoded UTF-8 text.") from exc
    if len(raw) > max_bytes:
        raise ValueError("Payload exceeds the configured byte limit.")
    return raw, decoded
