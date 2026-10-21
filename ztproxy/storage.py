"""SQLite persistence for device state, replay protection, and security audit events."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _connect(database_path):
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection

def connect_db():
    from flask import current_app
    return _connect(current_app.config["DATABASE_PATH"])

def init_db(app):
    db = _connect(app.config["DATABASE_PATH"])
    try:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS seen_nonces (
            device_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (device_id, nonce)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            device_id TEXT,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(id DESC);
        """)
        now = utc_now()
        for device_id in app.config["DEVICE_SECRETS"]:
            display_name = device_id.replace("_", " ").replace("-", " ").title()
            db.execute("INSERT OR IGNORE INTO devices (device_id, display_name, active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)", (device_id, display_name, now, now))
    finally:
        db.close()

def get_device(device_id):
    db = connect_db()
    try:
        row = db.execute("SELECT device_id, display_name, active, created_at, updated_at FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()

def list_devices():
    db = connect_db()
    try:
        rows = db.execute("SELECT device_id, display_name, active, created_at, updated_at FROM devices ORDER BY device_id").fetchall()
        return [dict(row) for row in rows]
    finally:
        db.close()

def set_device_active(device_id, active):
    db = connect_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        cursor = db.execute("UPDATE devices SET active = ?, updated_at = ? WHERE device_id = ?", (1 if active else 0, utc_now(), device_id))
        db.execute("COMMIT")
        return cursor.rowcount == 1
    except Exception:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()

def _trim_audit(db):
    db.execute("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT 1000)")

def record_audit(request_id, device_id, decision, reason):
    db = connect_db()
    try:
        db.execute("INSERT INTO audit_events (request_id, created_at, device_id, decision, reason) VALUES (?, ?, ?, ?, ?)", (request_id, utc_now(), device_id, decision, reason))
        _trim_audit(db)
    finally:
        db.close()

def record_nonce_and_audit(device_id, nonce, now_epoch, request_id, reason):
    """Atomically consume a nonce and record an accepted request."""
    db = connect_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM seen_nonces WHERE created_at < ?", (now_epoch - 3600,))
        db.execute("INSERT INTO seen_nonces (device_id, nonce, created_at) VALUES (?, ?, ?)", (device_id, nonce, now_epoch))
        db.execute("INSERT INTO audit_events (request_id, created_at, device_id, decision, reason) VALUES (?, ?, ?, 'ALLOW', ?)", (request_id, utc_now(), device_id, reason))
        _trim_audit(db)
        db.execute("COMMIT")
        return True
    except sqlite3.IntegrityError:
        db.execute("ROLLBACK")
        return False
    except Exception:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()

def list_audit_events(limit=40):
    db = connect_db()
    try:
        rows = db.execute("SELECT request_id, created_at, device_id, decision, reason FROM audit_events ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 100)),)).fetchall()
        return [dict(row) for row in rows]
    finally:
        db.close()
