# Zero-Trust Cloud Access Proxy

A structured Flask web application for the Cryptography and Network Security microproject by **Sahil Rajkumar Jain** and **Dhruv Gada**. It demonstrates a zero-trust request pipeline with device allowlisting, client-side HMAC-SHA256 signing, freshness validation, replay protection, persistent decisions, and an audit trail.

**Scope:** this application implements local signed-request validation and device state. It does not implement EAP/802.1X or connect to a RADIUS server. It does not forward requests to a real cloud resource. HMAC-SHA256 is implemented; a post-quantum cryptographic algorithm is not. The architecture leaves clear integration points for those extensions.

## Features

- Client-side HMAC-SHA256 signing through the browser Web Crypto API. The shared key is not included in the API request.
- Device authorization checks against a SQLite registry.
- Timestamp freshness checks (default ±300 seconds).
- Unique per-device nonce stored in SQLite to reject replayed signed requests.
- Constant-time signature comparison with hmac.compare_digest.
- Persistent audit events for decisions and device-state changes. Raw payloads, secrets, and signatures are not stored in the audit log.
- Admin-token-protected device enable/disable controls.
- Request and payload limits, restrictive browser security headers, and a responsive frontend.
- Integration tests and a GitHub Actions workflow.

## Architecture

    Browser Client Simulator
       | UTF-8 payload + nonce + timestamp + HMAC-SHA256
       v
    Flask API / Input Boundary
       | JSON validation + request limits
       v
    Zero-Trust Policy Pipeline
       1. Device active?
       2. Timestamp fresh?
       3. HMAC matches?
       4. Nonce already seen?
       | DENY                 | ALLOW (local simulation only)
       v                      v
    SQLite device state, replay-protection store, and audit events

### Request-signing format

The client base64-encodes its UTF-8 payload and signs this versioned canonical string:

    v1
    <device_id>
    <unix_timestamp_seconds>
    <nonce>
    <payload_base64>

The proxy reconstructs the exact message, calculates HMAC-SHA256 with that device's server-configured key, and compares signatures in constant time. The request is denied when the device is inactive, the timestamp is outside the allowed window, the signature mismatches, or the nonce has already been used. Nonce reservation and the successful audit entry are committed atomically in SQLite.

## Project structure

    .
    ├── app.py
    ├── wsgi.py
    ├── ztproxy/
    │   ├── __init__.py
    │   ├── routes.py
    │   ├── security.py
    │   └── storage.py
    ├── templates/index.html
    ├── static/css/app.css
    ├── static/js/app.js
    ├── tests/test_app.py
    ├── .env.example
    ├── requirements.txt
    ├── Dockerfile / .dockerignore
    ├── Procfile
    └── .github/workflows/tests.yml

## Run locally (Windows PowerShell)

Python 3.10+ is recommended.

    git clone https://github.com/Sahiljain6/zero-trust-cloud-access-proxy.git
    cd zero-trust-cloud-access-proxy
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    Copy-Item .env.example .env
    python app.py

Open http://127.0.0.1:5000. On macOS/Linux, create and activate a virtual environment, install requirements.txt, copy .env.example to .env, then run python app.py.

### Test the normal flow

1. Select device_node_01 in the dashboard.
2. Copy that device's key from the local .env file into Client-side shared secret. The browser signs with Web Crypto; the secret is not sent in the API request.
3. Click Run zero-trust checks. Expected: ALLOW, with five passing checks.
4. Turn on Simulate a man-in-the-middle modification and retry. Expected: payload integrity is rejected.
5. Use the Device Registry controls with the admin token to disable the device, then retry. The request should be denied.

The keys in .env.example are public development examples. Replace them before deployment. Never paste real production credentials into a public/shared browser.

## Configuration

app.py loads .env using python-dotenv.

| Variable | Purpose |
|---|---|
| APP_ENV | development or production; production checks required secrets |
| FLASK_SECRET_KEY | Unique Flask secret key; at least 32 characters for production |
| ADMIN_TOKEN | Token for device enable/disable control; at least 24 characters for production |
| DEVICE_SECRETS_JSON | JSON mapping of configured device IDs to unique HMAC keys; each at least 32 characters for production |
| DATABASE_PATH | SQLite database path; use durable private storage when deployed |
| REQUEST_TTL_SECONDS | Allowed clock skew in seconds (default 300) |
| MAX_PAYLOAD_BYTES | Maximum decoded payload (default 8192) |
| PORT / HOST | Local bind address and port |

For production, set environment values through the hosting provider's secret configuration, use HTTPS, rotate keys, secure the database, restrict administrative access, and monitor logs. SQLite and the demo device configuration are suitable for a small educational deployment, not horizontally scaled production traffic.

## API reference

- GET /api/health — service health.
- GET /api/devices — configured device IDs and statuses; never returns keys.
- POST /api/verify — verify a signed request.
- GET /api/audit — latest audit events without payloads, signatures, or secrets.
- PATCH /api/devices/{device_id} — enable/disable a configured device with the X-Admin-Token header and JSON body {"active": false}. Adding a device requires its server-side key to be configured first.

Example signed envelope for POST /api/verify:

    {
      "device_id": "device_node_01",
      "timestamp": 1792600000,
      "nonce": "9f1b229cab814da0b10001c3b5a5abcd",
      "payload_b64": "UmVxdWVzdGluZyBzZWN1cmUgcmVjb3Jkcw==",
      "signature": "64 lowercase hexadecimal characters"
    }

The signature must be HMAC-SHA256 over the canonical message above, generated with the configured key and a current timestamp.

## Container and hosted deployment

The repository includes a non-root Docker image and a Procfile for Linux hosts that support Gunicorn. For Docker, first create a private production environment file with APP_ENV=production, a unique FLASK_SECRET_KEY (32+ characters), a private ADMIN_TOKEN (24+ characters), and a DEVICE_SECRETS_JSON mapping whose unique device secrets are each at least 32 characters. Do not deploy the example credentials from .env.example.

    docker build -t zero-trust-cloud-access-proxy .
    docker run --env-file .env -p 5000:5000 -v ztproxy-data:/data zero-trust-cloud-access-proxy

The named volume keeps SQLite device and audit data across container recreation. Production hosting must use HTTPS, persistent writable storage, and secret/environment settings. The app intentionally refuses to start in production if required secrets are missing or still use public development keys.

## Run tests

    python -m unittest discover -v

GitHub Actions runs this suite on pushes and pull requests.

## Security limits and future integrations

- **EAP/802.1X/RADIUS:** this build uses a SQLite device policy registry, not a genuine EAP exchange. A real integration needs a deployed identity/access-control service.
- **Cloud forwarding:** the policy engine currently produces an allow/deny decision only. It deliberately does not proxy to an arbitrary URL. A future connector should use a fixed allowlisted upstream, TLS verification, timeouts, and explicit authorization mapping.
- **Post-quantum cryptography:** not implemented. Evaluate an appropriate standardized scheme independently and document its exact role and benchmarks before claiming it is implemented.
- **Client key entry:** intended only for local learning. A deployed design must provision client keys securely rather than ask people to paste production secrets into a shared browser.
- **Replay storage:** SQLite demonstrates transactional nonce storage locally. A multi-instance service needs a shared transactional datastore.
- **Administration:** the admin token is a demonstration control, not a complete identity provider or role-based access-management system.

Future work stays on the same Zero-Trust Cloud Access Proxy pipeline rather than adding unrelated features.
