"""
Net Ward — Storage Layer (sqlite3 backend for the standalone build)

Single-file sqlite database, stdlib-only. Thread-safe via internal lock
(sqlite3 connections are not thread-safe by default). Sync API; async
callers bridge with `asyncio.to_thread(...)`.

Public contract:
    sources_lookup(ip: str) -> Optional[Source]
    sources_upsert(source: Source) -> None
    patterns_active() -> list[Pattern]
    patterns_upsert(pattern: Pattern) -> None
    patterns_purge_expired(now: float) -> int
    probes_log(probe: Probe) -> None
    probes_recent_for_source(source_id: str, window_secs: int, now: float) -> int
    mirror_response_lookup(response_id: str) -> Optional[MirrorResponse]
    mirror_response_upsert(response: MirrorResponse) -> None
    mesh_intel_archive(intel: MeshIntel) -> None
    alerts_recent(now: float, window_secs: int) -> list[OperatorAlert]
    alerts_upsert(alert: OperatorAlert) -> None

Schema migrations: each migration is a (target_version, ddl) pair in
_MIGRATIONS. On init, Storage reads the persisted version from the
_schema_version table and applies any newer migrations in order. v0
ships the entire base schema as migration 0.

Hot-path priorities (per placeholder contract):
- sources_lookup is sub-millisecond — indexed on ip_address
- patterns_active is cacheable — caller refreshes on intel apply, not per-request
- probes_log is fire-and-forget — caller schedules via to_thread

Backend choice is sqlite3 (stdlib) in the standalone build. Postgres / redis
adapters remain a later-release concern; preserve this Storage class's
interface and a swap is mechanical.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .schema import (
    SCHEMA_VERSION,
    MeshIntel,
    MirrorResponse,
    OperatorAlert,
    Pattern,
    Probe,
    RequestMetadata,
    Source,
)


_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS _schema_version (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL UNIQUE,
    asn INTEGER,
    asn_name TEXT,
    geo_country TEXT,
    geo_region TEXT,
    reputation TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    probe_count INTEGER NOT NULL DEFAULT 0,
    legit_count INTEGER NOT NULL DEFAULT 0,
    notes_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sources_ip ON sources(ip_address);
CREATE INDEX IF NOT EXISTS idx_sources_reputation ON sources(reputation);

CREATE TABLE IF NOT EXISTS patterns (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    signature TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    origin TEXT NOT NULL,
    origin_node_id TEXT,
    created_at REAL NOT NULL,
    last_matched REAL,
    match_count INTEGER NOT NULL DEFAULT 0,
    mirror_response_id TEXT,
    confidence REAL NOT NULL DEFAULT 0.5,
    parent_pattern_id TEXT,
    mutation_generation INTEGER NOT NULL DEFAULT 0,
    expires_at REAL
);
CREATE INDEX IF NOT EXISTS idx_patterns_kind ON patterns(kind);
CREATE INDEX IF NOT EXISTS idx_patterns_origin ON patterns(origin);
CREATE INDEX IF NOT EXISTS idx_patterns_expires ON patterns(expires_at);

CREATE TABLE IF NOT EXISTS probes (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    source_id TEXT NOT NULL,
    pattern_id TEXT,
    classification TEXT NOT NULL,
    request_json TEXT NOT NULL,
    response_id TEXT,
    mirror_fired INTEGER NOT NULL DEFAULT 0,
    upstream_passed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_probes_timestamp ON probes(timestamp);
CREATE INDEX IF NOT EXISTS idx_probes_source ON probes(source_id);
CREATE INDEX IF NOT EXISTS idx_probes_pattern ON probes(pattern_id);

CREATE TABLE IF NOT EXISTS mirror_responses (
    id TEXT PRIMARY KEY,
    matches_pattern_id TEXT NOT NULL,
    intensity TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    headers_json TEXT NOT NULL DEFAULT '{}',
    body_template TEXT NOT NULL,
    body_template_vars_json TEXT NOT NULL DEFAULT '{}',
    description TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mirror_pattern ON mirror_responses(matches_pattern_id);

CREATE TABLE IF NOT EXISTS mesh_intel (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    origin_node_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    published_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    propagation_count INTEGER NOT NULL DEFAULT 0,
    received_at REAL,
    verified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mesh_intel_kind ON mesh_intel(kind);
CREATE INDEX IF NOT EXISTS idx_mesh_intel_expires ON mesh_intel(expires_at);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    source_id TEXT,
    pattern_id TEXT,
    triggered_at REAL NOT NULL,
    delivered_to_json TEXT NOT NULL DEFAULT '[]',
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acknowledged_at REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered ON alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_alerts_kind_source ON alerts(kind, source_id);
"""


_MIGRATIONS: list[tuple[int, str]] = [
    (0, _BASE_SCHEMA),
    (1, "ALTER TABLE patterns ADD COLUMN header_name TEXT;"),
]


class StorageError(Exception):
    """Raised on storage layer errors that callers should surface."""


class Storage:
    """Sqlite-backed Net Ward storage. Open once per process."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS _schema_version "
                "(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)"
            )
            row = self._conn.execute(
                "SELECT MAX(version) AS v FROM _schema_version"
            ).fetchone()
            current = row["v"] if row and row["v"] is not None else -1
            # Sort by target version so out-of-order entries in _MIGRATIONS
            # cannot skip or apply migrations in the wrong sequence.
            for target, ddl in sorted(_MIGRATIONS, key=lambda m: m[0]):
                if target > current:
                    self._conn.executescript(ddl)
                    self._conn.execute(
                        "INSERT OR REPLACE INTO _schema_version(version, applied_at) "
                        "VALUES (?, ?)",
                        (target, time.time()),
                    )
                    if target >= SCHEMA_VERSION:
                        break

    # ----- Source -----

    def sources_lookup(self, ip: str) -> Optional[Source]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sources WHERE ip_address = ?", (ip,)
            ).fetchone()
        return _row_to_source(row) if row else None

    def sources_upsert(self, source: Source) -> None:
        cols, vals = _source_columns(source)
        placeholders = ",".join(["?"] * len(cols))
        update_clause = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        sql = (
            f"INSERT INTO sources({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {update_clause}"
        )
        with self._lock:
            self._conn.execute(sql, vals)

    # ----- Pattern -----

    def patterns_active(self) -> list[Pattern]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM patterns "
                "WHERE expires_at IS NULL OR expires_at > strftime('%s','now') "
                "ORDER BY origin, confidence DESC, match_count DESC"
            ).fetchall()
        return [_row_to_pattern(r) for r in rows]

    def patterns_upsert(self, pattern: Pattern) -> None:
        # Regex policy guard runs before commit. Catastrophic-backtracking
        # patterns are rejected here, never reach the live classifier.
        from netward.regex_policy import validate_pattern_signature
        validate_pattern_signature(pattern.get("signature", ""))
        cols, vals = _pattern_columns(pattern)
        placeholders = ",".join(["?"] * len(cols))
        update_clause = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        sql = (
            f"INSERT INTO patterns({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {update_clause}"
        )
        with self._lock:
            self._conn.execute(sql, vals)

    def patterns_purge_expired(self, now: float) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM patterns WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            )
            return cur.rowcount

    # ----- Probe -----

    def probes_log(self, probe: Probe) -> None:
        cols, vals = _probe_columns(probe)
        placeholders = ",".join(["?"] * len(cols))
        sql = f"INSERT OR REPLACE INTO probes({','.join(cols)}) VALUES({placeholders})"
        with self._lock:
            self._conn.execute(sql, vals)

    def probes_recent_for_source(
        self, source_id: str, window_secs: int, now: float
    ) -> int:
        cutoff = now - window_secs
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM probes "
                "WHERE source_id = ? AND timestamp >= ?",
                (source_id, cutoff),
            ).fetchone()
        return int(row["c"]) if row else 0

    # ----- MirrorResponse -----

    def mirror_response_lookup(self, response_id: str) -> Optional[MirrorResponse]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM mirror_responses WHERE id = ?", (response_id,)
            ).fetchone()
        return _row_to_mirror_response(row) if row else None

    def mirror_response_upsert(self, response: MirrorResponse) -> None:
        cols, vals = _mirror_response_columns(response)
        placeholders = ",".join(["?"] * len(cols))
        update_clause = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        sql = (
            f"INSERT INTO mirror_responses({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {update_clause}"
        )
        with self._lock:
            self._conn.execute(sql, vals)

    # ----- MeshIntel -----

    def mesh_intel_archive(self, intel: MeshIntel) -> None:
        cols, vals = _mesh_intel_columns(intel)
        placeholders = ",".join(["?"] * len(cols))
        sql = (
            f"INSERT OR REPLACE INTO mesh_intel({','.join(cols)}) "
            f"VALUES({placeholders})"
        )
        with self._lock:
            self._conn.execute(sql, vals)

    # ----- OperatorAlert -----

    def alerts_recent(self, now: float, window_secs: int) -> list[OperatorAlert]:
        cutoff = now - window_secs
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts WHERE triggered_at >= ? ORDER BY triggered_at DESC",
                (cutoff,),
            ).fetchall()
        return [_row_to_alert(r) for r in rows]

    def alerts_upsert(self, alert: OperatorAlert) -> None:
        cols, vals = _alert_columns(alert)
        placeholders = ",".join(["?"] * len(cols))
        update_clause = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        sql = (
            f"INSERT INTO alerts({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {update_clause}"
        )
        with self._lock:
            self._conn.execute(sql, vals)


# =============================================================================
# Row <-> TypedDict adapters
# =============================================================================

def _source_columns(s: Source) -> tuple[list[str], list[Any]]:
    return (
        [
            "id", "ip_address", "asn", "asn_name", "geo_country", "geo_region",
            "reputation", "first_seen", "last_seen", "probe_count", "legit_count",
            "notes_json",
        ],
        [
            s["id"], s["ip_address"], s.get("asn"), s.get("asn_name"),
            s.get("geo_country"), s.get("geo_region"), s["reputation"],
            s["first_seen"], s["last_seen"],
            int(s.get("probe_count", 0)), int(s.get("legit_count", 0)),
            json.dumps(s.get("notes", [])),
        ],
    )


def _row_to_source(row: sqlite3.Row) -> Source:
    out: Source = {
        "id": row["id"],
        "ip_address": row["ip_address"],
        "asn": row["asn"],
        "asn_name": row["asn_name"],
        "geo_country": row["geo_country"],
        "geo_region": row["geo_region"],
        "reputation": row["reputation"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "probe_count": int(row["probe_count"]),
        "legit_count": int(row["legit_count"]),
        "notes": json.loads(row["notes_json"]),
    }
    return out


def _pattern_columns(p: Pattern) -> tuple[list[str], list[Any]]:
    return (
        [
            "id", "kind", "signature", "description", "severity", "origin",
            "origin_node_id", "created_at", "last_matched", "match_count",
            "mirror_response_id", "confidence", "parent_pattern_id",
            "mutation_generation", "expires_at", "header_name",
        ],
        [
            p["id"], p["kind"], p["signature"], p.get("description"),
            p["severity"], p["origin"], p.get("origin_node_id"),
            p["created_at"], p.get("last_matched"),
            int(p.get("match_count", 0)), p.get("mirror_response_id"),
            float(p.get("confidence", 0.5)), p.get("parent_pattern_id"),
            int(p.get("mutation_generation", 0)),
            p.get("expires_at"), p.get("header_name"),
        ],
    )


def _row_to_pattern(row: sqlite3.Row) -> Pattern:
    out: Pattern = {
        "id": row["id"],
        "kind": row["kind"],
        "signature": row["signature"],
        "description": row["description"] or "",
        "severity": row["severity"],
        "origin": row["origin"],
        "origin_node_id": row["origin_node_id"],
        "created_at": row["created_at"],
        "last_matched": row["last_matched"],
        "match_count": int(row["match_count"]),
        "mirror_response_id": row["mirror_response_id"],
        "confidence": float(row["confidence"]),
        "parent_pattern_id": row["parent_pattern_id"],
        "mutation_generation": int(row["mutation_generation"]),
        "expires_at": row["expires_at"],
        "header_name": row["header_name"] if "header_name" in row.keys() else None,
    }
    return out


def _probe_columns(pr: Probe) -> tuple[list[str], list[Any]]:
    request: RequestMetadata = pr.get("request", {})  # type: ignore[assignment]
    return (
        [
            "id", "timestamp", "source_id", "pattern_id", "classification",
            "request_json", "response_id", "mirror_fired", "upstream_passed",
        ],
        [
            pr["id"], pr["timestamp"], pr["source_id"], pr.get("pattern_id"),
            pr["classification"], json.dumps(request),
            pr.get("response_id"),
            1 if pr.get("mirror_fired") else 0,
            1 if pr.get("upstream_passed") else 0,
        ],
    )


def _mirror_response_columns(m: MirrorResponse) -> tuple[list[str], list[Any]]:
    return (
        [
            "id", "matches_pattern_id", "intensity", "http_status",
            "headers_json", "body_template", "body_template_vars_json",
            "description", "created_at",
        ],
        [
            m["id"], m["matches_pattern_id"], m["intensity"],
            int(m["http_status"]),
            json.dumps(m.get("headers", {})),
            m["body_template"],
            json.dumps(m.get("body_template_vars", {})),
            m.get("description"), m["created_at"],
        ],
    )


def _row_to_mirror_response(row: sqlite3.Row) -> MirrorResponse:
    out: MirrorResponse = {
        "id": row["id"],
        "matches_pattern_id": row["matches_pattern_id"],
        "intensity": row["intensity"],
        "http_status": int(row["http_status"]),
        "headers": json.loads(row["headers_json"]),
        "body_template": row["body_template"],
        "body_template_vars": json.loads(row["body_template_vars_json"]),
        "description": row["description"] or "",
        "created_at": row["created_at"],
    }
    return out


def _mesh_intel_columns(mi: MeshIntel) -> tuple[list[str], list[Any]]:
    return (
        [
            "id", "kind", "origin_node_id", "payload_json", "signature",
            "published_at", "expires_at", "propagation_count", "received_at",
            "verified",
        ],
        [
            mi["id"], mi["kind"], mi["origin_node_id"],
            json.dumps(mi.get("payload", {})), mi["signature"],
            mi["published_at"], mi["expires_at"],
            int(mi.get("propagation_count", 0)),
            mi.get("received_at"),
            1 if mi.get("verified") else 0,
        ],
    )


def _alert_columns(a: OperatorAlert) -> tuple[list[str], list[Any]]:
    return (
        [
            "id", "severity", "kind", "title", "body", "source_id",
            "pattern_id", "triggered_at", "delivered_to_json",
            "acknowledged", "acknowledged_at",
        ],
        [
            a["id"], a["severity"], a["kind"], a["title"], a.get("body"),
            a.get("source_id"), a.get("pattern_id"), a["triggered_at"],
            json.dumps(a.get("delivered_to", [])),
            1 if a.get("acknowledged") else 0,
            a.get("acknowledged_at"),
        ],
    )


def _row_to_alert(row: sqlite3.Row) -> OperatorAlert:
    out: OperatorAlert = {
        "id": row["id"],
        "severity": row["severity"],
        "kind": row["kind"],
        "title": row["title"],
        "body": row["body"] or "",
        "source_id": row["source_id"],
        "pattern_id": row["pattern_id"],
        "triggered_at": row["triggered_at"],
        "delivered_to": json.loads(row["delivered_to_json"]),
        "acknowledged": bool(row["acknowledged"]),
        "acknowledged_at": row["acknowledged_at"],
    }
    return out
