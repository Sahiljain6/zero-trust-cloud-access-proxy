"""Smoke test the Streamlit Community Cloud entry point."""
import os
import tempfile
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


class StreamlitEntryPointTests(unittest.TestCase):
    def test_streamlit_dashboard_renders_without_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("DATABASE_PATH")
            previous_env = os.environ.get("APP_ENV")
            os.environ["DATABASE_PATH"] = str(Path(directory) / "streamlit-test.sqlite3")
            os.environ["APP_ENV"] = "test"
            try:
                app_path = Path(__file__).resolve().parents[1] / "streamlit_app.py"
                result = AppTest.from_file(str(app_path), default_timeout=20).run()
                self.assertEqual(len(result.exception), 0, str(result.exception))
                self.assertTrue(any("Trust is not assumed." in str(item.value) for item in result.markdown))
            finally:
                if previous is None:
                    os.environ.pop("DATABASE_PATH", None)
                else:
                    os.environ["DATABASE_PATH"] = previous
                if previous_env is None:
                    os.environ.pop("APP_ENV", None)
                else:
                    os.environ["APP_ENV"] = previous_env


if __name__ == "__main__":
    unittest.main()
