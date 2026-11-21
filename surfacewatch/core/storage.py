"""SQLite kayıt katmanı.

Her tarama bir `scans` satırı, her bulgu bir `findings` satırıdır. Blue
modundaki diff, aynı kapsamın son iki taramasını karşılaştırır.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    modules     TEXT NOT NULL,          -- JSON liste
    targets     TEXT NOT NULL,          -- JSON liste
    status      TEXT NOT NULL DEFAULT 'running'   -- running | done | failed
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target      TEXT NOT NULL,
    module      TEXT NOT NULL,
    key         TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    data        TEXT NOT NULL,          -- JSON
    mitre       TEXT NOT NULL,          -- JSON liste
    remediation TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    UNIQUE (scan_id, target, module, key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_scope ON scans(scope_name, id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanRecord:
    id: int
    scope_name: str
    started_at: str
    finished_at: str | None
    modules: list[str]
    targets: list[str]
    status: str


class Storage:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # ----------------------------------------------------------- yazma
    def start_scan(self, scope_name: str, modules: list[str], targets: list[str]) -> int:
        with self._tx() as c:
            cur = c.execute(
                "INSERT INTO scans (scope_name, started_at, modules, targets) VALUES (?,?,?,?)",
                (scope_name, _now(), json.dumps(modules), json.dumps(targets)),
            )
            return int(cur.lastrowid)

    def add_findings(self, scan_id: int, findings: list[Finding]) -> None:
        rows = [
            (scan_id, f.target, f.module, f.key, f.title, f.severity,
             json.dumps(f.data, sort_keys=True, default=str), json.dumps(f.mitre),
             f.remediation, f.fingerprint)
            for f in findings
        ]
        with self._tx() as c:
            c.executemany(
                "INSERT OR REPLACE INTO findings (scan_id, target, module, key, title, severity, "
                "data, mitre, remediation, fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )

    def finish_scan(self, scan_id: int, status: str = "done") -> None:
        with self._tx() as c:
            c.execute("UPDATE scans SET finished_at=?, status=? WHERE id=?", (_now(), status, scan_id))

    # ----------------------------------------------------------- okuma
    def _scan(self, row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            id=row["id"], scope_name=row["scope_name"], started_at=row["started_at"],
            finished_at=row["finished_at"], modules=json.loads(row["modules"]),
            targets=json.loads(row["targets"]), status=row["status"],
        )

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return self._scan(row) if row else None

    def list_scans(self, scope_name: str | None = None, limit: int = 20) -> list[ScanRecord]:
        if scope_name:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE scope_name=? ORDER BY id DESC LIMIT ?", (scope_name, limit))
        else:
            rows = self.conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return [self._scan(r) for r in rows]

    def last_completed(self, scope_name: str, n: int = 2) -> list[ScanRecord]:
        rows = self.conn.execute(
            "SELECT * FROM scans WHERE scope_name=? AND status='done' ORDER BY id DESC LIMIT ?",
            (scope_name, n),
        )
        return [self._scan(r) for r in rows]

    def findings(self, scan_id: int) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY target, module, key", (scan_id,))
        return [
            Finding(target=r["target"], module=r["module"], key=r["key"], title=r["title"],
                    severity=r["severity"], data=json.loads(r["data"]),
                    mitre=json.loads(r["mitre"]), remediation=r["remediation"])
            for r in rows
        ]
