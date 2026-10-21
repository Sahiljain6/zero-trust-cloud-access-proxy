# Zero-Trust Cloud Access Proxy

A small, interactive Python/Flask microproject demonstrating a zero-trust-style request gate. Each simulated request is checked against a device allowlist and its payload is verified with an HMAC-SHA256 integrity tag before the demo reports acceptance.

**Project scope:** this is an educational simulation. It does not implement the EAP protocol or a RADIUS/802.1X service, connect to a real cloud resource, or provide a production access gateway. The current code demonstrates HMAC-SHA256; it does **not** implement a post-quantum cryptographic algorithm. The academic report discusses post-quantum cryptography as a comparison/trade-off, while this lightweight implementation uses HMAC-SHA256 for its working integrity demonstration.

## What it demonstrates

- **Zero-trust-style request checks:** requests are not accepted solely because of network location.
- **Device authorization:** only device IDs marked `active` in the in-memory registry are accepted.
- **Payload integrity:** the proxy recalculates HMAC-SHA256 and uses `hmac.compare_digest` for a constant-time tag comparison.
- **Tampering scenario:** the UI can intentionally modify the integrity tag to demonstrate rejection.
- **Input handling:** JSON shape, field types, device ID length, payload length, and request size are checked.
- **Baseline browser headers:** responses set `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control` headers.
- **Automated tests:** tests cover accepted requests, unknown/inactive devices, tampering, malformed payloads, endpoint validation, and browser headers.

## Request flow

```text
Browser test form
       |
       v
POST /api/simulate (validate JSON and limits)
       |
       v
Device allowlist check (EAP/NAC-inspired simulation)
       |
       v
Decode payload + recompute HMAC-SHA256
       |
       v
Constant-time integrity comparison
       |
       +---- failed identity/integrity --> Reject and explain why
       |
       +---- checks pass ---------------> Report simulated acceptance
```

The form sends sample input to the Flask endpoint. For this demonstration, the server generates the sample integrity tag so the shared secret does not need to be placed in browser code. Selecting **Simulate Tampering** intentionally corrupts the tag before verification.

## Run locally

Python 3.10+ is recommended.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

The application does not automatically load `.env`; environment variables must be set in the shell or by your chosen local environment manager. The `.env` file is ignored by Git. The `.env.example` file is documentation only.

PowerShell example to set the optional key for the current terminal session:

```powershell
$env:PROXY_SHARED_SECRET = "replace-with-a-long-random-local-demo-secret"
$env:PORT = "5000"
python app.py
```

Then open [http://localhost:5000](http://localhost:5000). Hosting platforms can provide `PORT` and `PROXY_SHARED_SECRET` as environment variables.

## Run the tests

No separate test framework is required; the suite uses Python's standard `unittest` module.

```bash
python -m unittest discover -v
```

## API reference

### `POST /api/simulate`

Example body:

```json
{
  "device_id": "device_node_01",
  "data": "Requesting secure records",
  "tamper_payload": false
}
```

- `device_id`: non-empty string, up to 100 characters.
- `data`: text payload, up to 8,000 characters.
- `tamper_payload`: optional boolean; when `true`, the endpoint deliberately corrupts the generated HMAC tag.

The endpoint returns JSON with `status` (`success` or `error`) and a human-readable `message`. Expected security rejections are represented in the JSON result so the UI can display them as part of the demonstration.

## Security notes and limitations

- The fallback key in `app.py` is a public demonstration value. It is not a secret and must never be used to protect real data. Set `PROXY_SHARED_SECRET` for private experiments and use a proper secret manager in a real deployment.
- HMAC-SHA256 provides message integrity/authentication relative to holders of the shared key; it is not encryption, does not by itself authenticate the browser's identity, and is not a post-quantum implementation.
- The in-memory device registry is a teaching aid, not a real identity provider. EAP/802.1X and RADIUS are not implemented.
- “Forwarding” is simulated. The app does not connect to, authorize against, or forward data to a cloud API or database.
- A real deployment would require a proper identity provider, protected key storage and rotation, authenticated transport, audit logging, deployment hardening, and a separately designed/benchmarked post-quantum evaluation if that remains a project requirement.

## Focused next steps

Keep future development aligned with the same proxy pipeline: replace the simulated device registry with a real EAP/RADIUS-backed verification path, add a controlled upstream cloud target, and measure any future cryptographic alternatives independently before describing them as implemented. These integrations are **not** part of the current demo.

## Authors

- Sahil Rajkumar Jain
- Dhruv Gada

Educational microproject for Cryptography and Network Security.
