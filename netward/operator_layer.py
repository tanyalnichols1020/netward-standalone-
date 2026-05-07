"""
Net Ward — Operator Layer (placeholder, not yet implemented)

Responsibility: surface what the human running the node needs to know,
when, and how. Config validation, alert delivery, dashboard hooks.

Public contract this module exposes:
    load_config(path: str) -> OperatorConfig
        Read + validate config file. Reject on missing required fields.
        Never auto-write — operator changes are deliberate.

    deliver_alert(alert: OperatorAlert, config: OperatorConfig) -> list[str]
        Fan out the alert to configured channels (email, slack, ntfy,
        webhook, sms). Returns list of channel names that delivered
        successfully — the rest become retry candidates.

    dedupe_alert(alert: OperatorAlert, recent: list[OperatorAlert]) -> Optional[OperatorAlert]
        Roll up alerts in the same dedup window (per ALERT_DEDUP_WINDOW_SECS).
        Returns merged alert OR None if suppressed.

Alert escalation philosophy:
- info: log only (operator browses on demand, never paged)
- warn: low-friction channel (slack, ntfy) — operator notices, not woken
- critical: high-friction (email + sms if configured) — operator paged

Dashboard requirements (separate module / future build, but contract here):
- Live counters from NodeStatus
- Last 24h probe timeline
- Top 10 Sources by probe_count
- Top 10 Patterns by match_count
- Mesh peer health
- Recent OperatorAlerts (last 7 days)
- Trust manifest viewer + audit log of changes

Buyer-distributable note:
Operator tools must work for the small-shop case (one Linux box, no
managed cloud). Slack/ntfy/email are the priority channels; sms
requires Twilio/etc. and stays optional. Webhook is the escape hatch
for operators with their own incident management.
"""
from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from typing import Optional

from .schema import (
    ALERT_DEDUP_WINDOW_SECS,
    OperatorAlert,
    OperatorConfig,
)


_REQUIRED_CONFIG_FIELDS = frozenset({"node_id", "upstream_target", "listen_address"})
_SUPPORTED_ALERT_CHANNELS = frozenset({"email", "slack", "webhook", "ntfy", "sms"})


class ValidationError(ValueError):
    """Raised when an operator-editable config file is invalid."""


def load_config(path: str) -> OperatorConfig:
    """Read and validate an operator config file.

    The standalone build intentionally supports JSON only so the package stays
    stdlib-only. YAML gets a precise deferred error instead of a surprise
    dependency.
    """
    config_path = Path(path)
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        raise NotImplementedError("YAML config loading deferred to a later release; use JSON")
    if config_path.suffix.lower() != ".json":
        raise ValidationError("config file must be JSON for the standalone release")

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON config: {exc.msg}") from exc

    if not isinstance(raw, dict):
        raise ValidationError("config root must be an object")

    _validate_required_fields(raw)
    _validate_alert_channels(raw)
    raw["alert_channels"] = _normalized_alert_channels(raw)
    return raw


def validate_storage_permissions(
    config: OperatorConfig,
    *,
    allow_permissive_db: bool = False,
    platform_name: Optional[str] = None,
) -> None:
    """Validate storage_path permissions before the listener binds.

    POSIX builds refuse to start on world-writable DB paths unless the operator
    explicitly overrides the check. Windows emits an informational skip because
    POSIX mode bits are not a reliable permission signal there.
    """
    platform_name = (platform_name or sys.platform).lower()
    if platform_name.startswith("win"):
        print(
            "INFO: storage permission check skipped on Windows; avoid shared-write "
            "locations for the Net Ward database.",
            file=sys.stderr,
        )
        return

    target = _storage_permission_target(config.get("storage_path"))
    if not _is_world_writable(target):
        return

    message = (
        "ERROR: storage path permissions are too permissive: "
        f"{target} is world-writable. Fix the path or start with "
        "--allow-permissive-db."
    )
    if allow_permissive_db:
        print(f"{message} Proceeding because --allow-permissive-db was set.", file=sys.stderr)
        return
    raise ValidationError(message)


def deliver_alert(alert: OperatorAlert, config: OperatorConfig) -> list[str]:
    """Deliver an alert through the current standalone alert surface.

    Logging to stdout is the only implemented channel. Explicit external
    channels are rejected so operators do not assume paging is active.
    """
    channels = _normalized_alert_channels(config)
    if channels:
        deferred = ", ".join(channels)
        raise NotImplementedError(f"alert channels deferred to a later release: {deferred}")

    print(_format_alert(alert), file=sys.stdout)
    return ["stdout"]


def dedupe_alert(
    alert: OperatorAlert,
    recent: list[OperatorAlert],
) -> Optional[OperatorAlert]:
    """Roll up same-kind/source alerts inside the dedup window.

    Returns the merged alert when a recent match exists, otherwise returns
    the new alert for normal delivery.
    """
    alert_time = float(alert.get("triggered_at", 0))
    for candidate in recent:
        same_kind = candidate.get("kind") == alert.get("kind")
        same_source = candidate.get("source_id") == alert.get("source_id")
        candidate_time = float(candidate.get("triggered_at", 0))
        within_window = 0 <= alert_time - candidate_time <= ALERT_DEDUP_WINDOW_SECS
        if same_kind and same_source and within_window:
            merged = dict(candidate)
            merged["triggered_at"] = max(alert_time, candidate_time)
            merged["count"] = int(candidate.get("count", 1)) + 1
            merged["body"] = alert.get("body", candidate.get("body", ""))
            return merged
    return alert


def _validate_required_fields(config: dict) -> None:
    missing = sorted(
        field
        for field in _REQUIRED_CONFIG_FIELDS
        if not str(config.get(field, "")).strip()
    )
    if missing:
        raise ValidationError(f"missing required config fields: {', '.join(missing)}")


def _validate_alert_channels(config: dict) -> None:
    channels = _normalized_alert_channels(config)
    unknown = sorted(set(channels) - _SUPPORTED_ALERT_CHANNELS)
    if unknown:
        raise ValidationError(f"unknown alert channels: {', '.join(unknown)}")


def _normalized_alert_channels(config: dict) -> list[str]:
    channels = config.get("alert_channels")
    if channels is None:
        return []
    if not isinstance(channels, list):
        raise ValidationError("alert_channels must be a list")
    return channels


def _storage_permission_target(storage_path: Optional[str]) -> Path:
    path = Path(storage_path or "netward.db")
    if path.exists():
        return path
    return path.parent if str(path.parent) else Path(".")


def _is_world_writable(path: Path) -> bool:
    return bool(path.stat().st_mode & stat.S_IWOTH)


def _format_alert(alert: OperatorAlert) -> str:
    severity = str(alert.get("severity", "info")).upper()
    kind = alert.get("kind", "alert")
    title = alert.get("title", "Net Ward alert")
    body = alert.get("body", "")
    return f"[NETWARD] {severity} {kind}: {title}\n{body}"
