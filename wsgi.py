"""Production WSGI entry point, e.g. gunicorn wsgi:app."""
from app import app
__all__ = ["app"]
