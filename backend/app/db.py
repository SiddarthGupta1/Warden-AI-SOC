"""
Durable storage for users, triage reports and the remediation audit trail.

Before this module the application kept all three in process memory, so every
restart silently discarded user accounts (including their reset passwords), every
completed investigation, and the record of every containment action taken. That
also made the Kubernetes manifests incorrect at more than one replica, since two
pods would hold two disjoint sets of users.

SQLite is used deliberately: no new dependency, no service to run, and it is the
right size for a single-instance deployment. The repository functions below are
the only place SQL appears, so moving to Postgres for a multi-replica deployment
means reimplementing this file and nothing else.

Concurrency: a connection is opened per operation rather than shared across
threads. SQLite serialises writers internally and FastAPI's threadpool is small
here, so this is simpler and safer than passing a connection around. WAL mode
lets reads proceed during a write.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings

logger = logging.getLogger("warden.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username             TEXT PRIMARY KEY,
    full_name            TEXT NOT NULL DEFAULT '',
    email                TEXT NOT NULL DEFAULT '',
    role                 TEXT NOT NULL DEFAULT 'analyst',
    hashed_password      TEXT NOT NULL,
    disabled             INTEGER NOT NULL DEFAULT 0,
    must_reset_password  INTEGER NOT NULL DEFAULT 1,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage_reports (
    incident_id   TEXT PRIMARY KEY,
    verdict       TEXT,
    model_used    TEXT,
    report_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT,
    incident_id  TEXT,
    status       TEXT NOT NULL,
    verified     INTEGER,
    detail       TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_path() -> Path:
    p = Path(settings.DATABASE_PATH)
    if not p.is_absolute():
        # Resolve relative to backend/ so the working directory does not decide
        # where the database lives.
        p = Path(__file__).resolve().parent.parent / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


@contextmanager
def connect():
    conn = sqlite3.connect(db_path(), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
    logger.info(f"Database ready at {db_path()}")


# --------------------------------------------------------------------- users

def get_user(username: str) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["disabled"] = bool(d["disabled"])
    d["must_reset_password"] = bool(d["must_reset_password"])
    return d


def list_users() -> List[Dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["disabled"] = bool(d["disabled"])
        d["must_reset_password"] = bool(d["must_reset_password"])
        out.append(d)
    return out


def user_exists(username: str) -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is not None


def create_user(username: str, hashed_password: str, role: str = "analyst",
                full_name: str = "", email: str = "", must_reset_password: bool = True) -> None:
    ts = _now()
    with connect() as conn:
        conn.execute(
            """INSERT INTO users (username, full_name, email, role, hashed_password,
                                  disabled, must_reset_password, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)""",
            (username, full_name, email, role, hashed_password, int(must_reset_password), ts, ts),
        )


def set_password(username: str, hashed_password: str, must_reset_password: bool = False) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET hashed_password = ?, must_reset_password = ?, updated_at = ? WHERE username = ?",
            (hashed_password, int(must_reset_password), _now(), username),
        )


def delete_user(username: str) -> bool:
    """
    Remove a user entirely. Returns True if a row was deleted.

    Disabling is usually the right action for a real account, since it preserves
    the audit trail's reference to the name. This exists for removing accounts
    that should never have persisted, such as ones created during testing.
    """
    with connect() as conn:
        cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        return cur.rowcount > 0


def set_user_disabled(username: str, disabled: bool) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET disabled = ?, updated_at = ? WHERE username = ?",
            (int(disabled), _now(), username),
        )


# ------------------------------------------------------------ triage reports

def save_report(incident_id: str, report: Dict[str, Any]) -> None:
    ts = _now()
    payload = json.dumps(report, default=str)
    with connect() as conn:
        conn.execute(
            """INSERT INTO triage_reports (incident_id, verdict, model_used, report_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(incident_id) DO UPDATE SET
                   verdict = excluded.verdict,
                   model_used = excluded.model_used,
                   report_json = excluded.report_json,
                   updated_at = excluded.updated_at""",
            (incident_id, report.get("verdict"), report.get("model_used"), payload, ts, ts),
        )


def get_report(incident_id: str) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(
            "SELECT report_json FROM triage_reports WHERE incident_id = ?", (incident_id,)
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["report_json"])
    except json.JSONDecodeError:
        logger.warning(f"Stored report for {incident_id} is not valid JSON; ignoring.")
        return None


def all_report_summaries() -> Dict[str, Dict[str, Any]]:
    """incident_id -> {verdict, model_used} for dashboard statistics."""
    with connect() as conn:
        rows = conn.execute("SELECT incident_id, verdict, model_used FROM triage_reports").fetchall()
    return {r["incident_id"]: {"verdict": r["verdict"], "model_used": r["model_used"]} for r in rows}


def delete_report(incident_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM triage_reports WHERE incident_id = ?", (incident_id,))


# ---------------------------------------------------------------- audit log

def record_audit(actor: str, action: str, status: str, target: str = None,
                 incident_id: str = None, verified: Optional[bool] = None,
                 detail: str = None) -> None:
    """
    Append-only record of every remediation attempt, including refusals and
    failures. This is the durable counterpart to the Sentinel comment: if the
    workspace is unreachable or the comment write fails, the attempt is still
    recorded locally.
    """
    with connect() as conn:
        conn.execute(
            """INSERT INTO audit_log (ts, actor, action, target, incident_id, status, verified, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (_now(), actor, action, target, incident_id, status,
             None if verified is None else int(verified), detail),
        )


def get_audit_log(incident_id: str = None, limit: int = 100) -> List[Dict[str, Any]]:
    with connect() as conn:
        if incident_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE incident_id = ? ORDER BY id DESC LIMIT ?",
                (incident_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["verified"] = None if d["verified"] is None else bool(d["verified"])
        out.append(d)
    return out
