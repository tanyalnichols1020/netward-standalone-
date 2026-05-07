"""
Net Ward — Mirror Layer (placeholder, not yet implemented)

Responsibility: when classify says "fire mirror", build and return a
plausible-looking response so the bot believes its probe succeeded and
moves on. The "confetti" lesson: random structured-looking responses
that send the bot's logic into harmless loops.

Public contract this module exposes:
    fire_mirror(probe: Probe, response: MirrorResponse) -> dict
        Returns the HTTP response (status, headers, body) to send back.
        Performs template variable substitution per body_template_vars.

Variable generators (kinds the substitution engine supports):
    "uuid"           — fresh uuid4 per response (so two probes never see same)
    "timestamp"      — current epoch as an ISO-8601 or numeric string
    "fake_id"        — plausible alphanumeric ID (8-12 chars, mixed case)
    "fake_token"     — JWT-like or session-token-like string
    "fake_redirect"  — a redirect URL that sends the bot to a honeypot path
    "random_int"     — bounded random number for plausible counts/IDs
    "user_agent_echo"— echo back the bot's claimed UA (signals "we see you")

Anti-pattern guards (per the moral architecture from product memory):
- Never deliver actual malware / hostile payload
- Never echo back PII even if the bot included it
- Always return within HTTP norms (no protocol abuse)
- Mirror responses must be DETECTABLE by future bot operators if they
  audit; we're not pretending forever, just long enough for the bot's
  current dedup logic to deprioritize the target

Mirror intensity scaling:
- minimal: 200 + small JSON body, single uuid var
- moderate: 200 + plausible HTML/JSON page with 2-3 substitution vars
- elaborate: full fake login flow / fake admin panel / fake redirect
  chain — used only for known_bad sources, severity=critical patterns
"""
from __future__ import annotations

import re
import secrets
import string
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from html import escape as html_escape
from html import unescape as html_unescape
from typing import Callable
from urllib.parse import unquote

from .schema import MirrorResponse, Probe


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PII_VAR_RE = re.compile(
    r"(email|e_mail|mail|password|passwd|pwd|secret|token_echo|auth|"
    r"authorization|cookie|session_cookie|ssn|credit|card|phone|body)",
    re.IGNORECASE,
)
_HOSTILE_PAYLOAD_MARKERS = (
    "<script",
    "javascript:",
    "data:text/html",
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "rm -rf",
    "curl ",
    "wget ",
)
_HONEYPOT_REDIRECTS = (
    "/wp-admin/",
    "/admin/login",
    "/account/verify",
    "/session/continue",
    "/portal/status",
)
_SUPPORTED_GENERATORS = frozenset(
    {
        "uuid",
        "timestamp",
        "fake_id",
        "fake_token",
        "fake_redirect",
        "random_int",
        "user_agent_echo",
    }
)


class MirrorSafetyError(ValueError):
    """Raised when a mirror response violates Net Ward safety rules."""


def fire_mirror(probe: Probe, response: MirrorResponse) -> dict:
    """Render a safe, plausible mirror response for a matched probe."""
    _assert_safe_response(response)

    rendered_vars = {
        name: _generate_value(kind, probe)
        for name, kind in response.get("body_template_vars", {}).items()
    }

    def _render(template: str) -> str:
        return _PLACEHOLDER_RE.sub(
            lambda m: rendered_vars.get(m.group(1), m.group(0)),
            template,
        )

    # X1: apply substitution to both body and header values
    body = _render(response.get("body_template", ""))
    _assert_safe_body(body)

    rendered_headers = {k: _render(v) for k, v in response.get("headers", {}).items()}

    # X2: inject a plausible Server header if the mirror doesn't supply one
    if not any(k.lower() == "server" for k in rendered_headers):
        rendered_headers["Server"] = "nginx"

    return {
        "status": int(response.get("http_status", 200)),
        "headers": rendered_headers,
        "body": body,
    }


def _assert_safe_response(response: MirrorResponse) -> None:
    _assert_safe_body(response.get("body_template", ""))
    for header_name, header_value in response.get("headers", {}).items():
        _assert_safe_body(str(header_name))
        _assert_safe_body(str(header_value))

    for var_name, generator_spec in response.get("body_template_vars", {}).items():
        if _PII_VAR_RE.search(var_name):
            raise MirrorSafetyError(f"refusing PII-like template variable: {var_name}")
        generator = _generator_name(generator_spec)
        if generator not in _SUPPORTED_GENERATORS:
            raise ValueError(f"unsupported mirror generator: {generator_spec!r}")


def _assert_safe_body(value: str) -> None:
    lowered = _normalized_for_detection(value)
    for marker in _HOSTILE_PAYLOAD_MARKERS:
        if marker in lowered:
            raise MirrorSafetyError(f"refusing hostile mirror payload marker: {marker}")


def _generate_value(generator_spec: str, probe: Probe) -> str:
    generator = _generator_name(generator_spec)
    generators: dict[str, Callable[[str, Probe], str]] = {
        "uuid": lambda _spec, _probe: str(uuid.uuid4()),
        "timestamp": lambda _spec, _probe: _utc_timestamp(),
        "fake_id": lambda _spec, _probe: _fake_id(),
        "fake_token": lambda _spec, _probe: _fake_token(),
        "fake_redirect": lambda _spec, _probe: secrets.choice(_HONEYPOT_REDIRECTS),
        "random_int": _random_int,
        "user_agent_echo": _user_agent_echo,
    }
    return generators[generator](generator_spec, probe)


def _generator_name(generator_spec: str) -> str:
    return generator_spec.split(":", 1)[0].strip()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fake_id() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


def _fake_token() -> str:
    # JWT-shaped only. These segments are random bait, not a signed token.
    return ".".join(secrets.token_urlsafe(size) for size in (9, 18, 24))


def _random_int(generator_spec: str, _probe: Probe) -> str:
    low, high = _random_int_bounds(generator_spec)
    return str(secrets.randbelow(high - low + 1) + low)


@lru_cache(maxsize=256)
def _random_int_bounds(generator_spec: str) -> tuple[int, int]:
    bounds = generator_spec.split(":", 1)[1:] or ["1:9999"]
    raw = bounds[0].replace(",", ":")
    parts = [part.strip() for part in raw.split(":") if part.strip()]
    if len(parts) == 1:
        low, high = 1, int(parts[0])
    elif len(parts) == 2:
        low, high = int(parts[0]), int(parts[1])
    else:
        raise ValueError(f"invalid random_int generator spec: {generator_spec!r}")
    if low > high:
        raise ValueError(f"invalid random_int bounds: {low}>{high}")
    return low, high


def _user_agent_echo(_generator_spec: str, probe: Probe) -> str:
    request = probe.get("request", {})
    extracted = request.get("user_agent")
    if extracted:
        return _safe_echo(extracted)
    headers = request.get("headers", {})
    value = headers.get("User-Agent") or headers.get("user-agent") or ""
    return _safe_echo(value)


def _safe_echo(value: str) -> str:
    lowered = _normalized_for_detection(value)
    if (
        _EMAIL_RE.search(value)
        or _PII_VAR_RE.search(value)
        or any(marker in lowered for marker in _HOSTILE_PAYLOAD_MARKERS)
    ):
        return ""
    return html_escape(value[:256], quote=True)


def _normalized_for_detection(value: str) -> str:
    normalized = value
    for _ in range(2):
        normalized = html_unescape(unquote(normalized))
    return normalized.lower()
