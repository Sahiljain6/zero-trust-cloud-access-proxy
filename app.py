"""WSGI entry point for the Zero-Trust Cloud Access Proxy."""
import os
from dotenv import load_dotenv
load_dotenv()
from ztproxy import create_app
app = create_app()
if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
