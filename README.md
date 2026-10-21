# Zero-Trust Cloud Access Proxy

A structured Flask + Streamlit web application for the Cryptography and Network Security microproject by **Sahil Rajkumar Jain** and **Dhruv Gada**. The Streamlit dashboard demonstrates device allowlisting, HMAC-SHA256 request integrity, timestamp freshness, replay protection, device-state controls, and an audit trail.

> **Important scope:** the Streamlit deployment runs the client simulator and policy engine in one Python process. It is a demonstrator, not a production trust boundary. EAP/802.1X or RADIUS is not integrated, requests are not forwarded to a real cloud resource, and a post-quantum algorithm is not implemented. The Flask routes remain for tests and future service integration; this Streamlit deployment does not expose them as independent public HTTP endpoints.

## Deploy to Streamlit Community Cloud

1. Push the repository to GitHub (this repo is already configured).
2. Open https://share.streamlit.io/ and sign in with the GitHub account that can access this repository.
3. Select **Create app**.
4. Choose repository `Sahiljain6/zero-trust-cloud-access-proxy`, branch `main`, and main file path `streamlit_app.py`.
5. Open **Advanced settings**, select Python 3.12, and deploy.
6. Before using it as a public demo, open app settings and add the secrets below, then reboot if necessary.

Community Cloud installs dependencies from the root `requirements.txt`. The theme is configured in `.streamlit/config.toml`.

### Required deployment secrets

In Streamlit app **Settings → Secrets**, paste a TOML configuration with unique random values. Replace every value below; do not commit real secrets.

```toml
APP_ENV = "production"
FLASK_SECRET_KEY = "REPLACE_WITH_A_UNIQUE_RANDOM_VALUE_AT_LEAST_32_CHARACTERS"
ADMIN_TOKEN = "REPLACE_WITH_A_PRIVATE_RANDOM_ADMIN_TOKEN_AT_LEAST_24_CHARACTERS"
DEVICE_SECRETS_JSON = '{"device_node_01":"REPLACE_WITH_UNIQUE_DEVICE_KEY_A_32_CHARS","admin_node":"REPLACE_WITH_DIFFERENT_DEVICE_KEY_B_32_CHARS"}'
```

Each production device key must be different and at least 32 characters long. Store actual values only in Streamlit Secrets. Production startup checks required configuration.

## Run locally

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
streamlit run streamlit_app.py
```

Open the local URL printed in the terminal, normally http://localhost:8501. macOS/Linux: create and activate a virtual environment, install requirements, copy `.env.example` to `.env`, then run `streamlit run streamlit_app.py`.

## How to use the dashboard

1. Select `device_node_01` and click **Run zero-trust checks**. Expected: ALLOW when the key is configured correctly.
2. Enable the tampering control and retry. The changed payload should fail integrity verification.
3. Click **Replay the last signed request**. The reused nonce should be rejected.
4. Open **Device Registry**, enter the admin token from your secrets, and disable a device. New requests should fail device authorization.
5. Open **Audit Trail** to inspect decisions. The audit table does not store payload contents, keys, or signatures.

The Streamlit edition builds a simulated client envelope using the server-configured demo key. This is explicit simulation behavior because Streamlit runs Python on the server; it is not proof of independent client authentication. A genuine client/server design would deploy the policy layer as a separate API and provision keys securely to client devices.

## Architecture and structure

```text
.
├── streamlit_app.py        # Streamlit Community Cloud entry point
├── app.py / wsgi.py        # Flask WSGI entry points for local/API integration
├── ztproxy/
│   ├── __init__.py         # Flask app factory and configuration checks
│   ├── routes.py           # Verify, devices, health, audit routes
│   ├── security.py         # Canonical request, HMAC, payload decoding
│   └── storage.py          # SQLite device state, nonces, audit trail
├── templates/index.html    # Flask dashboard retained for standalone mode
├── static/css/app.css
├── static/js/app.js
├── .streamlit/config.toml
├── tests/test_app.py
└── requirements.txt
```

### Policy checks

1. Validate envelope fields and bounded base64 payload.
2. Confirm the device exists, is active, and has a configured verification key.
3. Reject timestamps outside the allowed ±300-second window.
4. Recompute HMAC-SHA256 over a versioned canonical message and compare in constant time.
5. Atomically reserve the device/nonce pair and record an allow decision; reused nonces are rejected.
6. Record denials and admin state changes in the audit trail.

## Persistence warning

Streamlit Community Cloud does **not guarantee persistence of local filesystem data**. The SQLite device state, nonce, and audit database may reset on restart or redeploy. This is acceptable for an educational demo, but not for durable audit history or reliable replay defense. For durable use, move the tables to a managed database with transactions and shared nonce storage.

## Run tests

```bash
python -m unittest discover -v
```

GitHub Actions also runs the test suite on pushes and pull requests.

## Future integrations that stay on-topic

- Replace the simulated device registry with an actual EAP/802.1X or RADIUS-backed verification flow.
- Forward allowed requests only to an explicit allowlisted cloud resource with TLS verification and strict timeouts.
- Evaluate an appropriate post-quantum scheme separately and document exact implementation details and benchmarks.
- Replace demo key entry with secure device enrollment and a managed secret store.
- Move SQLite to a managed transactional database before multi-instance hosting.
