"""Integration tests for the signed request and zero-trust policy pipeline."""
import base64
import tempfile
import time
import unittest
from ztproxy import create_app
from ztproxy.security import sign_request

class ProxyWebTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.device_secrets = {
            "device_node_01": "unit-test-device-shared-secret-00001",
            "admin_node": "unit-test-admin-shared-secret-000002",
        }
        self.app = create_app({
            "TESTING": True, "APP_ENV": "test", "SECRET_KEY": "unit-test-flask-secret-key-more-than-32",
            "DATABASE_PATH": f"{self.temp_dir.name}/test.sqlite3", "DEVICE_SECRETS": self.device_secrets,
            "ADMIN_TOKEN": "unit-test-admin-token-long-enough", "REQUEST_TTL_SECONDS": 300, "MAX_PAYLOAD_BYTES": 8192,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def envelope(self, device_id="device_node_01", payload="hello secure cloud", nonce=None, timestamp=None, secret=None):
        timestamp = timestamp if timestamp is not None else int(time.time())
        nonce = nonce or ("nonce" + str(time.time_ns())).ljust(20, "x")
        payload_b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        secret = secret or self.device_secrets.get(device_id, "unknown-device-secret-long-enough")
        return {"device_id": device_id, "timestamp": timestamp, "nonce": nonce, "payload_b64": payload_b64, "signature": sign_request(device_id, timestamp, nonce, payload_b64, secret)}

    def test_dashboard_and_static_assets_load(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Zero-Trust Cloud Access Proxy", response.data)
        self.assertIn(b"static/css/app.css", response.data)
        self.assertEqual(self.client.get("/static/js/app.js").status_code, 200)

    def test_health_and_device_list_do_not_expose_secrets(self):
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "ok")
        result = self.client.get("/api/devices").get_json()
        self.assertIn("device_node_01", str(result))
        self.assertNotIn(self.device_secrets["device_node_01"], str(result))

    def test_valid_signed_request_is_allowed(self):
        response = self.client.post("/api/verify", json=self.envelope())
        result = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual([x["status"] for x in result["checks"]], ["passed"] * 5)

    def test_modified_payload_is_denied(self):
        body = self.envelope()
        body["payload_b64"] = base64.b64encode(b"modified content").decode("ascii")
        response = self.client.post("/api/verify", json=body)
        self.assertEqual(response.status_code, 403)
        self.assertIn("integrity", response.get_json()["message"].lower())

    def test_wrong_device_secret_is_denied(self):
        body = self.envelope(secret="not-the-configured-device-secret-0000")
        response = self.client.post("/api/verify", json=body)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["checks"][-1]["status"], "failed")

    def test_unknown_device_is_denied(self):
        response = self.client.post("/api/verify", json=self.envelope(device_id="rogue_device_01"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["checks"][-1]["name"], "Device authorization")

    def test_disabled_device_is_denied(self):
        self.client.patch("/api/devices/device_node_01", headers={"X-Admin-Token": "unit-test-admin-token-long-enough"}, json={"active": False})
        response = self.client.post("/api/verify", json=self.envelope())
        self.assertEqual(response.status_code, 403)
        self.assertIn("authorization", response.get_json()["message"].lower())

    def test_invalid_admin_token_cannot_change_device(self):
        response = self.client.patch("/api/devices/device_node_01", headers={"X-Admin-Token": "wrong"}, json={"active": False})
        self.assertEqual(response.status_code, 403)
        devices = self.client.get("/api/devices").get_json()["devices"]
        self.assertEqual(next(d for d in devices if d["device_id"] == "device_node_01")["status"], "active")

    def test_valid_admin_can_disable_device_and_audit_change(self):
        response = self.client.patch("/api/devices/device_node_01", headers={"X-Admin-Token": "unit-test-admin-token-long-enough"}, json={"active": False})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(event["decision"] == "ADMIN" for event in self.client.get("/api/audit").get_json()["events"]))

    def test_expired_timestamp_is_denied(self):
        response = self.client.post("/api/verify", json=self.envelope(timestamp=int(time.time()) - 1000))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["checks"][-1]["name"], "Freshness")

    def test_nonce_cannot_be_reused(self):
        body = self.envelope()
        first = self.client.post("/api/verify", json=body)
        second = self.client.post("/api/verify", json=body)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        self.assertIn("Replay", second.get_json()["message"])

    def test_invalid_base64_is_denied(self):
        body = self.envelope(); body["payload_b64"] = "%%%not-base64%%%"
        self.assertEqual(self.client.post("/api/verify", json=body).status_code, 400)

    def test_bad_input_shape_is_denied(self):
        response = self.client.post("/api/verify", json=["bad", "shape"])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["decision"], "DENY")

    def test_payload_over_limit_is_denied(self):
        body = self.envelope(payload="x" * 8200)
        response = self.client.post("/api/verify", json=body)
        self.assertIn(response.status_code, (400, 413))

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_audit_does_not_store_payload_or_secret(self):
        secret_payload = "sensitive-content-should-not-be-logged"
        self.client.post("/api/verify", json=self.envelope(payload=secret_payload))
        audit_text = str(self.client.get("/api/audit").get_json())
        self.assertNotIn(secret_payload, audit_text)
        self.assertNotIn(self.device_secrets["device_node_01"], audit_text)

if __name__ == "__main__":
    unittest.main()
