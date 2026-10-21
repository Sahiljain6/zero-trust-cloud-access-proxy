"""Application factory and runtime configuration."""
import json
import os
from pathlib import Path
from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge
from .routes import register_routes
from .storage import init_db

DEVELOPMENT_DEVICE_SECRETS = {
    "device_node_01": "local-demo-device-key-change-this-001",
    "admin_node": "local-demo-admin-key-change-this-002",
}

def _device_secrets_from_environment():
    raw = os.environ.get("DEVICE_SECRETS_JSON", "").strip()
    if not raw:
        return dict(DEVELOPMENT_DEVICE_SECRETS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("DEVICE_SECRETS_JSON must be valid JSON.") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise RuntimeError("DEVICE_SECRETS_JSON must be a non-empty JSON object.")
    if any(not isinstance(device_id, str) or not device_id or not isinstance(secret, str) or len(secret) < 24 for device_id, secret in parsed.items()):
        raise RuntimeError("Each device ID must map to a secret of at least 24 characters.")
    return parsed

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        APP_ENV=os.environ.get("APP_ENV", "development").lower(),
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-flask-key"),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "zero_trust_proxy.sqlite3")),
        DEVICE_SECRETS=_device_secrets_from_environment(),
        ADMIN_TOKEN=os.environ.get("ADMIN_TOKEN", "local-admin-token-change-this-value"),
        REQUEST_TTL_SECONDS=int(os.environ.get("REQUEST_TTL_SECONDS", "300")),
        MAX_PAYLOAD_BYTES=int(os.environ.get("MAX_PAYLOAD_BYTES", "8192")),
        MAX_CONTENT_LENGTH=24 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if app.config["APP_ENV"] == "production":
        if len(app.config["SECRET_KEY"]) < 32 or app.config["SECRET_KEY"] == "dev-only-change-this-flask-key":
            raise RuntimeError("Production requires a unique FLASK_SECRET_KEY of at least 32 characters.")
        if len(app.config["ADMIN_TOKEN"]) < 24 or app.config["ADMIN_TOKEN"] == "local-admin-token-change-this-value":
            raise RuntimeError("Production requires a private ADMIN_TOKEN of at least 24 characters.")
        if not os.environ.get("DEVICE_SECRETS_JSON") or not app.config["DEVICE_SECRETS"] or any(len(secret) < 32 or secret in DEVELOPMENT_DEVICE_SECRETS.values() for secret in app.config["DEVICE_SECRETS"].values()):
            raise RuntimeError("Production requires unique per-device secrets of at least 32 characters, supplied via DEVICE_SECRETS_JSON.")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_db(app)
    register_routes(app)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify({"status": "error", "decision": "DENY", "message": "Request exceeds the configured size limit."}), 413

    @app.errorhandler(400)
    def bad_request(_error):
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "decision": "DENY", "message": "The request could not be parsed."}), 400
        return "Bad request.", 400

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "decision": "DENY", "message": "API route not found."}), 404
        return "Page not found.", 404
    return app
