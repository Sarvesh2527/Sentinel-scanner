"""
database.py -- SQLite persistence layer for scan history.

One table, `scans`, stores every scan: the target URL, a timestamp, the overall
score/grade, quick pass/fail counts, and the full results payload as JSON so a
past report can be reopened and rendered exactly as it first appeared.

Owned by: Ronit (Full-Stack Developer)
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

# Store the DB next to this file so it works no matter where the app is launched.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")

# History retention: keep only the most recent N scans. Older scans are pruned
# automatically after each new scan. Change this one number to adjust the limit.
MAX_HISTORY = 3


def get_connection() -> sqlite3.Connection:
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the scans table if it doesn't exist yet. Safe to call on boot."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                score       INTEGER NOT NULL,
                grade       TEXT    NOT NULL,
                rating      TEXT    NOT NULL,
                passed      INTEGER NOT NULL,
                failed      INTEGER NOT NULL,
                warned      INTEGER NOT NULL,
                total       INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                results     TEXT    NOT NULL   -- full per-check results as JSON
            )
            """
        )


def save_scan(report: dict) -> int:
    """Persist one completed scan report and return its new row id."""
    summary = report["summary"]
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans
                (url, created_at, score, grade, rating,
                 passed, failed, warned, total, duration_ms, results)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["url"],
                created_at,
                summary["score"],
                summary["grade"],
                summary["rating"],
                summary["passed"],
                summary["failed"],
                summary["warned"],
                summary["total"],
                report.get("duration_ms", 0),
                json.dumps(report["results"]),
            ),
        )
        new_id = cur.lastrowid

    # Auto-prune: keep only the most recent MAX_HISTORY scans.
    prune_history()
    return new_id


def prune_history(keep: int = MAX_HISTORY) -> int:
    """Delete all but the newest `keep` scans. Returns how many were removed."""
    if keep < 0:
        return 0
    with get_connection() as conn:
        cur = conn.execute(
            """
            DELETE FROM scans
            WHERE id NOT IN (
                SELECT id FROM scans ORDER BY id DESC LIMIT ?
            )
            """,
            (keep,),
        )
        return cur.rowcount


def list_scans(limit: int = 50) -> list[dict]:
    """Return recent scans (newest first) without the heavy results blob."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, url, created_at, score, grade, rating,
                   passed, failed, warned, total, duration_ms
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    """Return one full scan (with parsed results) so a report can be reopened."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["results"] = json.loads(data["results"])
    return data


def delete_scan(scan_id: int) -> bool:
    """Remove a single scan from history. Returns True if a row was deleted."""
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def clear_history() -> int:
    """Delete all scans. Returns how many rows were removed."""
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM scans")
        return cur.rowcount
