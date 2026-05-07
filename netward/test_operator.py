from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path

import pytest

from netward.operator_layer import (
    ValidationError,
    dedupe_alert,
    deliver_alert,
    load_config,
    validate_storage_permissions,
)
from netward.schema import OperatorAlert, OperatorConfig


_WORKSPACE_TMP_ROOT = Path(__file__).resolve().parent.parent / ".codex-test-operator"


def _config(**overrides) -> OperatorConfig:
    cfg: OperatorConfig = {
        "node_id": "node-1",
        "upstream_target": "http://127.0.0.1:8080",
        "listen_address": "127.0.0.1:9000",
        "mirror_intensity_default": "moderate",
        "mesh_enabled": False,
        "mesh_endpoint": None,
        "trust_manifest_url": None,
        "alert_channels": [],
        "alert_email": None,
        "alert_slack_webhook": None,
        "alert_ntfy_topic": None,
    }
    cfg.update(overrides)
    return cfg


def _alert(**overrides) -> OperatorAlert:
    alert: OperatorAlert = {
        "id": "alert-1",
        "severity": "warn",
        "kind": "flood_active",
        "title": "Flood active",
        "body": "source is sending probes",
        "source_id": "source-1",
        "pattern_id": None,
        "triggered_at": time.time(),
        "delivered_to": [],
        "acknowledged": False,
        "acknowledged_at": None,
    }
    alert.update(overrides)
    return alert


def _workspace_tempdir() -> Path:
    path = _WORKSPACE_TMP_ROOT / str(uuid.uuid4())
    path.mkdir(parents=True, exist_ok=False)
    return path


def test_load_config_reads_valid_json(tmp_path):
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(_config()), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["node_id"] == "node-1"
    assert loaded["upstream_target"] == "http://127.0.0.1:8080"


@pytest.mark.parametrize("raw_channels", [None, []])
def test_load_config_normalizes_empty_alert_channels(tmp_path, raw_channels):
    cfg = _config(alert_channels=raw_channels)
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["alert_channels"] == []


def test_load_config_normalizes_missing_alert_channels(tmp_path):
    cfg = _config()
    cfg.pop("alert_channels")
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["alert_channels"] == []


def test_load_config_missing_required_field_is_clear(tmp_path):
    bad = _config()
    bad.pop("upstream_target")
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(bad), encoding="utf-8")

    with pytest.raises(ValidationError, match="upstream_target"):
        load_config(str(path))


def test_load_config_rejects_unknown_alert_channel(tmp_path):
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(_config(alert_channels=["pagerduty"])), encoding="utf-8")

    with pytest.raises(ValidationError, match="unknown alert channels"):
        load_config(str(path))


def test_validate_storage_permissions_rejects_world_writable_db(monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")
        monkeypatch.setattr("netward.operator_layer._is_world_writable", lambda path: True)

        with pytest.raises(ValidationError, match="world-writable"):
            validate_storage_permissions(
                _config(storage_path=str(db_path)),
                platform_name="linux",
            )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_allows_override_for_world_writable_db(
    capsys,
    monkeypatch,
):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")
        monkeypatch.setattr("netward.operator_layer._is_world_writable", lambda path: True)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            allow_permissive_db=True,
            platform_name="linux",
        )

        captured = capsys.readouterr()
        assert "ERROR:" in captured.err
        assert "--allow-permissive-db" in captured.err
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_missing_db_checks_parent_dir(monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "state" / "netward.db"
        db_path.parent.mkdir()
        seen: list[str] = []

        def fake_is_world_writable(path):
            seen.append(str(path))
            return False

        monkeypatch.setattr("netward.operator_layer._is_world_writable", fake_is_world_writable)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            platform_name="linux",
        )

        assert seen == [str(db_path.parent)]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_clean_posix_path_passes(capsys, monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")
        monkeypatch.setattr("netward.operator_layer._is_world_writable", lambda path: False)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            platform_name="darwin",
        )

        captured = capsys.readouterr()
        assert captured.err == ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_windows_logs_skip(capsys, monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")

        def should_not_run(path):
            raise AssertionError("world-writable check should be skipped on Windows")

        monkeypatch.setattr("netward.operator_layer._is_world_writable", should_not_run)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            platform_name="win32",
        )

        captured = capsys.readouterr()
        assert "INFO:" in captured.err
        assert "avoid shared-write locations" in captured.err
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_deliver_alert_logs_to_stdout(capsys):
    delivered = deliver_alert(_alert(), _config())

    captured = capsys.readouterr()
    assert delivered == ["stdout"]
    assert "[NETWARD] WARN flood_active" in captured.out


@pytest.mark.parametrize("raw_channels", [None, []])
def test_deliver_alert_treats_empty_channels_as_stdout(raw_channels, capsys):
    delivered = deliver_alert(_alert(), _config(alert_channels=raw_channels))

    captured = capsys.readouterr()
    assert delivered == ["stdout"]
    assert "Flood active" in captured.out


def test_configured_external_alert_channel_is_deferred():
    with pytest.raises(NotImplementedError, match="deferred to a later release"):
        deliver_alert(_alert(), _config(alert_channels=["slack"]))


def test_dedupe_alert_within_window_rolls_up_count():
    base = _alert(id="alert-1", triggered_at=1000.0)
    new = _alert(id="alert-2", triggered_at=1100.0, body="new detail")

    merged = dedupe_alert(new, [base])

    assert merged is not None
    assert merged["id"] == "alert-1"
    assert merged["count"] == 2
    assert merged["body"] == "new detail"


def test_dedupe_alert_outside_window_passes_new_alert():
    base = _alert(id="alert-1", triggered_at=1000.0)
    new = _alert(id="alert-2", triggered_at=2000.0)

    passed = dedupe_alert(new, [base])

    assert passed == new
