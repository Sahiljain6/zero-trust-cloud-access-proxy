"""Production configuration guard tests."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from ztproxy import create_app


class ProductionConfigTests(unittest.TestCase):
    def test_production_rejects_example_placeholders(self):
        placeholder_device_key = "REPLACE_WITH_UNIQUE_DEVICE_KEY_A_32_CHARS"
        env = {
            "DEVICE_SECRETS_JSON": json.dumps({"device_node_01": placeholder_device_key}),
            "APP_ENV": "production",
            "FLASK_SECRET_KEY": "REPLACE_WITH_A_UNIQUE_RANDOM_VALUE_AT_LEAST_32_CHARACTERS",
            "ADMIN_TOKEN": "REPLACE_WITH_A_PRIVATE_RANDOM_ADMIN_TOKEN_AT_LEAST_24_CHARACTERS",
        }
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "TESTING": True,
                "APP_ENV": "production",
                "SECRET_KEY": env["FLASK_SECRET_KEY"],
                "ADMIN_TOKEN": env["ADMIN_TOKEN"],
                "DEVICE_SECRETS": {"device_node_01": placeholder_device_key},
                "DATABASE_PATH": os.path.join(directory, "proxy.sqlite3"),
            }
            with patch.dict(os.environ, env, clear=False):
                with self.assertRaisesRegex(RuntimeError, "placeholder"):
                    create_app(config)


if __name__ == "__main__":
    unittest.main()
