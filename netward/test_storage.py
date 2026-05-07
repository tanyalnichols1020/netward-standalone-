"""
Tests for netward.storage — sqlite3 backend for the standalone build.

Coverage:
- Schema migration creates tables and records version
- Source upsert + lookup round-trip
- Source upsert is idempotent (same id, second call updates)
- Pattern upsert + active list filters expired
- Pattern purge removes expired
- Probe log + recent_for_source counts within window
- MirrorResponse upsert + lookup round-trip
- MeshIntel archive round-trip
- Alert upsert + recent within window
"""
from __future__ import annotations

import time
import uuid

import pytest

from netward.schema import (
    MeshIntel,
    MirrorResponse,
    OperatorAlert,
    Pattern,
    Probe,
    RequestMetadata,
    Source,
)
from netward.storage import Storage


@pytest.fixture
def storage(tmp_path):
    db = tmp_path / "netward_test.db"
    s = Storage(db)
    yield s
    s.close()


# ----- schema migration -----

def test_storage_creates_tables(storage):
    cur = storage._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    names = {r["name"] for r in cur.fetchall()}
    assert {"sources", "patterns", "probes", "mirror_responses",
            "mesh_intel", "alerts", "_schema_version"} <= names


def test_storage_records_schema_version(storage):
    row = storage._conn.execute(
        "SELECT MAX(version) AS v FROM _schema_version"
    ).fetchone()
    assert row["v"] is not None
    assert row["v"] >= 0


# ----- Source -----

def _make_source(ip: str = "203.0.113.7", reputation: str = "neutral") -> Source:
    now = time.time()
    return {
        "id": str(uuid.uuid4()),
        "ip_address": ip,
        "asn": 64512,
        "asn_name": "TEST-AS",
        "geo_country": "US",
        "geo_region": "MN",
        "reputation": reputation,
        "first_seen": now,
        "last_seen": now,
        "probe_count": 0,
        "legit_count": 0,
        "notes": [],
    }


def test_source_upsert_then_lookup_roundtrip(storage):
    source = _make_source(ip="198.51.100.42")
    storage.sources_upsert(source)

    found = storage.sources_lookup("198.51.100.42")
    assert found is not None
    assert found["id"] == source["id"]
    assert found["asn"] == 64512
    assert found["reputation"] == "neutral"
    assert found["notes"] == []


def test_source_lookup_missing_returns_none(storage):
    assert storage.sources_lookup("192.0.2.1") is None


def test_source_upsert_is_idempotent(storage):
    source = _make_source(ip="198.51.100.99")
    storage.sources_upsert(source)
    source["probe_count"] = 7
    source["reputation"] = "suspicious"
    source["notes"] = ["flooded /wp-admin"]
    storage.sources_upsert(source)

    found = storage.sources_lookup("198.51.100.99")
    assert found["probe_count"] == 7
    assert found["reputation"] == "suspicious"
    assert found["notes"] == ["flooded /wp-admin"]


# ----- Pattern -----

def _make_pattern(
    *, signature: str = r"^/wp-admin", expires_at: float | None = None
) -> Pattern:
    return {
        "id": str(uuid.uuid4()),
        "kind": "path",
        "signature": signature,
        "description": "WordPress admin probe",
        "severity": "warn",
        "origin": "vendor",
        "origin_node_id": None,
        "created_at": time.time(),
        "last_matched": None,
        "match_count": 0,
        "mirror_response_id": None,
        "confidence": 0.8,
        "parent_pattern_id": None,
        "mutation_generation": 0,
        "expires_at": expires_at,
    }


def test_pattern_upsert_then_active(storage):
    p1 = _make_pattern(signature=r"^/wp-admin")
    p2 = _make_pattern(signature=r"^/.env")
    storage.patterns_upsert(p1)
    storage.patterns_upsert(p2)

    active = storage.patterns_active()
    sigs = {p["signature"] for p in active}
    assert sigs == {r"^/wp-admin", r"^/.env"}


def test_pattern_active_filters_expired(storage):
    fresh = _make_pattern(signature=r"^/api/login")
    expired = _make_pattern(
        signature=r"^/old-thing", expires_at=time.time() - 100
    )
    storage.patterns_upsert(fresh)
    storage.patterns_upsert(expired)

    active = storage.patterns_active()
    sigs = {p["signature"] for p in active}
    assert r"^/api/login" in sigs
    assert r"^/old-thing" not in sigs


def test_pattern_expires_at_round_trips(storage):
    """Round-trip: storage writes expires_at; adapter must read it back."""
    expiry = time.time() + 86400
    p = _make_pattern(signature=r"^/with-expiry", expires_at=expiry)
    storage.patterns_upsert(p)

    active = storage.patterns_active()
    matches = [x for x in active if x["signature"] == r"^/with-expiry"]
    assert len(matches) == 1
    assert matches[0]["expires_at"] == pytest.approx(expiry)


def test_pattern_purge_expired(storage):
    fresh = _make_pattern(signature=r"^/keep")
    stale = _make_pattern(signature=r"^/drop", expires_at=time.time() - 10)
    storage.patterns_upsert(fresh)
    storage.patterns_upsert(stale)

    removed = storage.patterns_purge_expired(time.time())
    assert removed == 1

    active = storage.patterns_active()
    sigs = {p["signature"] for p in active}
    assert sigs == {r"^/keep"}


# ----- Probe -----

def _make_probe(*, source_id: str, ts: float | None = None) -> Probe:
    request: RequestMetadata = {
        "method": "GET",
        "path": "/wp-admin",
        "headers": {"User-Agent": "evil-scanner/1.0"},
        "query_string": None,
        "body_snippet": None,
        "body_size": 0,
        "tls_fingerprint": None,
        "user_agent": "evil-scanner/1.0",
    }
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts if ts is not None else time.time(),
        "source_id": source_id,
        "pattern_id": None,
        "classification": "probe",
        "request": request,
        "response_id": None,
        "mirror_fired": True,
        "upstream_passed": False,
    }


def test_probe_log_then_recent_window_counts(storage):
    src_id = str(uuid.uuid4())
    now = time.time()
    storage.probes_log(_make_probe(source_id=src_id, ts=now))
    storage.probes_log(_make_probe(source_id=src_id, ts=now - 30))
    storage.probes_log(_make_probe(source_id=src_id, ts=now - 600))

    in_60s = storage.probes_recent_for_source(src_id, window_secs=60, now=now)
    in_300s = storage.probes_recent_for_source(src_id, window_secs=300, now=now)
    in_1h = storage.probes_recent_for_source(src_id, window_secs=3600, now=now)

    assert in_60s == 2
    assert in_300s == 2
    assert in_1h == 3


def test_probe_recent_isolates_by_source(storage):
    src_a = str(uuid.uuid4())
    src_b = str(uuid.uuid4())
    now = time.time()
    storage.probes_log(_make_probe(source_id=src_a, ts=now))
    storage.probes_log(_make_probe(source_id=src_b, ts=now))

    assert storage.probes_recent_for_source(src_a, 60, now) == 1
    assert storage.probes_recent_for_source(src_b, 60, now) == 1


# ----- MirrorResponse -----

def test_mirror_response_upsert_then_lookup_roundtrip(storage):
    mr: MirrorResponse = {
        "id": str(uuid.uuid4()),
        "matches_pattern_id": str(uuid.uuid4()),
        "intensity": "moderate",
        "http_status": 200,
        "headers": {"Content-Type": "text/html"},
        "body_template": "<html>Hello {{user_id}}</html>",
        "body_template_vars": {"user_id": "fake_id"},
        "description": "WordPress fake admin login",
        "created_at": time.time(),
    }
    storage.mirror_response_upsert(mr)
    found = storage.mirror_response_lookup(mr["id"])
    assert found is not None
    assert found["body_template"] == "<html>Hello {{user_id}}</html>"
    assert found["body_template_vars"] == {"user_id": "fake_id"}
    assert found["headers"] == {"Content-Type": "text/html"}


def test_mirror_response_lookup_missing_returns_none(storage):
    assert storage.mirror_response_lookup(str(uuid.uuid4())) is None


# ----- MeshIntel -----

def test_mesh_intel_archive_persists(storage):
    intel: MeshIntel = {
        "id": str(uuid.uuid4()),
        "kind": "new_pattern",
        "origin_node_id": str(uuid.uuid4()),
        "payload": {"pattern_signature": r"^/.env"},
        "signature": "ed25519:placeholder",
        "published_at": time.time(),
        "expires_at": time.time() + 86400,
        "propagation_count": 0,
        "received_at": None,
        "verified": False,
    }
    storage.mesh_intel_archive(intel)
    row = storage._conn.execute(
        "SELECT id, kind, payload_json, verified FROM mesh_intel WHERE id = ?",
        (intel["id"],),
    ).fetchone()
    assert row is not None
    assert row["kind"] == "new_pattern"
    assert "pattern_signature" in row["payload_json"]
    assert row["verified"] == 0


# ----- OperatorAlert -----

def _make_alert(*, kind: str = "new_pattern", source_id: str | None = None) -> OperatorAlert:
    return {
        "id": str(uuid.uuid4()),
        "severity": "warn",
        "kind": kind,
        "title": "Probe pattern fired",
        "body": "Source X hit /wp-admin",
        "source_id": source_id,
        "pattern_id": None,
        "triggered_at": time.time(),
        "delivered_to": [],
        "acknowledged": False,
        "acknowledged_at": None,
    }


def test_alert_upsert_then_recent(storage):
    a1 = _make_alert(kind="new_pattern")
    a2 = _make_alert(kind="flood_active")
    storage.alerts_upsert(a1)
    storage.alerts_upsert(a2)

    recent = storage.alerts_recent(now=time.time(), window_secs=60)
    kinds = {a["kind"] for a in recent}
    assert kinds == {"new_pattern", "flood_active"}


def test_alert_recent_excludes_outside_window(storage):
    old: OperatorAlert = {
        "id": str(uuid.uuid4()),
        "severity": "info",
        "kind": "old_alert",
        "title": "old",
        "body": "",
        "source_id": None,
        "pattern_id": None,
        "triggered_at": time.time() - 7200,
        "delivered_to": [],
        "acknowledged": True,
        "acknowledged_at": time.time() - 7000,
    }
    storage.alerts_upsert(old)
    storage.alerts_upsert(_make_alert(kind="fresh_alert"))

    recent = storage.alerts_recent(now=time.time(), window_secs=60)
    kinds = {a["kind"] for a in recent}
    assert "fresh_alert" in kinds
    assert "old_alert" not in kinds


def test_alert_upsert_idempotent(storage):
    a = _make_alert(kind="dedupe_test")
    storage.alerts_upsert(a)
    a["acknowledged"] = True
    a["acknowledged_at"] = time.time()
    storage.alerts_upsert(a)

    recent = storage.alerts_recent(now=time.time(), window_secs=60)
    matches = [r for r in recent if r["id"] == a["id"]]
    assert len(matches) == 1
    assert matches[0]["acknowledged"] is True
