"""
Net Ward -- bootstrap layer tests.
Covers install_vendor_patterns idempotency, error handling, and the
disable/enable cycle that the CLI delegates to direct SQL.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from netward import bootstrap as mod
from netward.storage import Storage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def storage(tmp_path):
    s = Storage(tmp_path / "bootstrap_test.db")
    yield s
    s.close()


def _write_vendor_json(path: Path, n_patterns: int = 3, n_mirrors: int = 2) -> Path:
    mirrors = [
        {
            "id": f"mirror_{i}",
            "matches_pattern_id": f"vendor_test_{i}",
            "intensity": "minimal",
            "http_status": 200,
            "headers": {"Content-Type": "application/json"},
            "body_template": '{"id":"{{uuid}}"}',
            "body_template_vars": {"uuid": "uuid"},
            "description": f"test mirror {i}",
            "created_at": 0,
        }
        for i in range(n_mirrors)
    ]
    patterns = [
        {
            "id": f"vendor_test_{i}",
            "kind": "path",
            "signature": f"^/test-{i}\\b",
            "description": f"test pattern {i}",
            "severity": "warn",
            "origin": "vendor",
            "mirror_response_id": f"mirror_{i % n_mirrors}",
            "confidence": 0.9,
            "match_count": 0,
            "mutation_generation": 0,
            "created_at": 0,
        }
        for i in range(n_patterns)
    ]
    path.write_text(json.dumps({"version": 1, "mirror_responses": mirrors, "patterns": patterns}))
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_empty_db_seeds_patterns_and_mirrors(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json", n_patterns=3, n_mirrors=2)
    pats, mirrors = mod.install_vendor_patterns(storage, _data_path=data_path)
    assert pats == 3
    assert mirrors == 2
    active = storage.patterns_active()
    assert len(active) == 3
    assert all(p["origin"] == "vendor" for p in active)


def test_second_call_is_idempotent(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json")
    mod.install_vendor_patterns(storage, _data_path=data_path)
    pats2, mirrors2 = mod.install_vendor_patterns(storage, _data_path=data_path)
    assert pats2 == 0 and mirrors2 == 0


def test_force_reinstalls_and_returns_full_counts(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json", n_patterns=2, n_mirrors=1)
    mod.install_vendor_patterns(storage, _data_path=data_path)
    pats, mirrors = mod.install_vendor_patterns(storage, force=True, _data_path=data_path)
    assert pats == 2
    assert mirrors == 1


def test_malformed_json_raises_clear_error_storage_untouched(storage, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not {{ valid json }")
    with pytest.raises(mod.BootstrapError, match="invalid JSON"):
        mod.install_vendor_patterns(storage, _data_path=bad)
    assert len(storage.patterns_active()) == 0


def test_disable_pattern_then_list_filters_it_out(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json", n_patterns=2, n_mirrors=1)
    mod.install_vendor_patterns(storage, _data_path=data_path)

    # Disable pattern 0 via direct SQL (same logic as cli.py disable-pattern)
    target_id = "vendor_test_0"
    storage._conn.execute(
        "UPDATE patterns SET expires_at = ? WHERE id = ?",
        (time.time() - 1, target_id),
    )

    active = storage.patterns_active()
    active_ids = {p["id"] for p in active}
    assert target_id not in active_ids
    assert "vendor_test_1" in active_ids


def test_real_vendor_json_installs_cleanly(storage):
    """Smoke test: the real vendor_patterns.json ships without errors."""
    pats, mirrors = mod.install_vendor_patterns(storage)
    assert pats > 0
    assert mirrors > 0
    active = storage.patterns_active()
    assert len(active) > 0
    # basic_auth_probe ships with expires_at=1 (disabled by default); active < pats is expected
    assert len(active) <= pats


def test_basic_auth_probe_is_seeded_but_disabled_by_default(storage):
    """basic_auth_probe ships disabled to avoid trapping legitimate Basic Auth users.
    It must be in the DB (so enable-pattern works) but absent from patterns_active()."""
    mod.install_vendor_patterns(storage)
    active_ids = {p["id"] for p in storage.patterns_active()}
    assert "basic_auth_probe" not in active_ids

    row = storage._conn.execute(
        "SELECT expires_at FROM patterns WHERE id = ?", ("basic_auth_probe",)
    ).fetchone()
    assert row is not None, "basic_auth_probe must be seeded into storage"
    assert row["expires_at"] == pytest.approx(1.0)
