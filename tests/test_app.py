"""Focused tests for the Zero-Trust Cloud Access Proxy demo."""

import base64
import unittest

import app as proxy_app


class ProxyLogicTests(unittest.TestCase):
    def setUp(self):
        self.original_devices = proxy_app.AUTHORIZED_DEVICES.copy()

    def tearDown(self):
        proxy_app.AUTHORIZED_DEVICES.clear()
        proxy_app.AUTHORIZED_DEVICES.update(self.original_devices)

    def test_authorized_device_with_valid_payload_is_accepted(self):
        request = proxy_app.secure_payload("private test record", proxy_app.SHARED_SECRET)
        result = proxy_app.authenticate_and_forward("device_node_01", request)
        self.assertEqual(result["status"], "success")
        self.assertIn("Simulated cloud proxy accepted payload", result["message"])

    def test_unknown_device_is_denied(self):
        request = proxy_app.secure_payload("private test record", proxy_app.SHARED_SECRET)
        result = proxy_app.authenticate_and_forward("unknown_device", request)
        self.assertEqual(result["status"], "error")
        self.assertIn("authorization failed", result["message"])

    def test_inactive_device_is_denied(self):
        proxy_app.AUTHORIZED_DEVICES["revoked_device"] = "disabled"
        request = proxy_app.secure_payload("private test record", proxy_app.SHARED_SECRET)
        result = proxy_app.authenticate_and_forward("revoked_device", request)
        self.assertEqual(result["status"], "error")

    def test_changed_integrity_tag_is_rejected(self):
        request = proxy_app.secure_payload("original record", proxy_app.SHARED_SECRET)
        request["integrity_hash"] = "0" * 64
        result = proxy_app.authenticate_and_forward("device_node_01", request)
        self.assertEqual(result["status"], "error")
        self.assertIn("integrity mismatch", result["message"])

    def test_malformed_base64_is_rejected(self):
        result = proxy_app.authenticate_and_forward(
            "device_node_01",
            {"payload": "%%%not-base64%%%", "integrity_hash": "0" * 64},
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "Malformed payload.")

    def test_malformed_hash_is_rejected(self):
        request = {"payload": base64.b64encode(b"hello").decode(), "integrity_hash": "bad"}
        result = proxy_app.authenticate_and_forward("device_node_01", request)
        self.assertEqual(result["message"], "Malformed payload.")


class ProxyEndpointTests(unittest.TestCase):
    def setUp(self):
        proxy_app.app.config.update(TESTING=True)
        self.client = proxy_app.app.test_client()

    def test_valid_simulation_succeeds(self):
        response = self.client.post(
            "/api/simulate",
            json={"device_id": "device_node_01", "data": "hello", "tamper_payload": False},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")

    def test_unauthorized_device_is_rejected(self):
        response = self.client.post(
            "/api/simulate",
            json={"device_id": "unknown_device", "data": "hello"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "error")

    def test_tampering_demo_fails_integrity_check(self):
        response = self.client.post(
            "/api/simulate",
            json={"device_id": "device_node_01", "data": "hello", "tamper_payload": True},
        )
        self.assertEqual(response.get_json()["status"], "error")
        self.assertIn("integrity mismatch", response.get_json()["message"])

    def test_rejects_non_object_json(self):
        response = self.client.post("/api/simulate", json=["not", "an", "object"])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    def test_rejects_payload_over_character_limit(self):
        response = self.client.post(
            "/api/simulate",
            json={"device_id": "device_node_01", "data": "x" * 8_001},
        )
        self.assertEqual(response.status_code, 400)

    def test_sets_baseline_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")


if __name__ == "__main__":
    unittest.main()
