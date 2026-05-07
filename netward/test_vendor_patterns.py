"""
Tests for the vendor pattern set shipped at netward/data/vendor_patterns.json.

Every default pattern Net Ward installs on first run goes through this
gate. A bad regex, hostile body template, or PII-named template var
would otherwise reach an operator's deployment and fire on legitimate
traffic — exactly what the fail-safe rules in __init__.py forbid.

Coverage:
- File loads as JSON, has required top-level keys
- Every pattern's `signature` regex compiles
- Every pattern's `mirror_response_id` resolves to a real mirror
- Every mirror is referenced by at least one pattern (dead mirrors fail)
- No pattern or mirror contains hostile markers (re-uses mirror.py's guard)
- No mirror body_template_vars name matches the PII rejection regex
- Every pattern has all required Pattern TypedDict keys
- Every mirror has all required MirrorResponse keys
- Pattern and mirror IDs are unique within their pools
- Sanity threshold: at least 8 patterns + 5 mirrors total (vendor set
  is composed of two category groups; both must be present)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from netward.mirror import (
    _HOSTILE_PAYLOAD_MARKERS,
    _PII_VAR_RE,
    _SUPPORTED_GENERATORS,
)


VENDOR_JSON = Path(__file__).parent / "data" / "vendor_patterns.json"


_REQUIRED_PATTERN_KEYS = {
    "id", "kind", "signature", "description", "severity", "origin",
    "mirror_response_id", "confidence",
}
_REQUIRED_MIRROR_KEYS = {
    "id", "intensity", "http_status", "headers", "body_template",
    "body_template_vars", "description",
}


@pytest.fixture(scope="module")
def vendor_data():
    with VENDOR_JSON.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def patterns(vendor_data):
    return vendor_data["patterns"]


@pytest.fixture(scope="module")
def mirrors(vendor_data):
    return vendor_data["mirror_responses"]


# ----- file shape -----

def test_vendor_file_exists():
    assert VENDOR_JSON.exists(), f"missing {VENDOR_JSON}"


def test_vendor_top_level_shape(vendor_data):
    assert vendor_data.get("version") == 1
    assert isinstance(vendor_data.get("patterns"), list)
    assert isinstance(vendor_data.get("mirror_responses"), list)


def test_vendor_minimum_count(patterns, mirrors):
    """Both category groups must be present in the shipped vendor set."""
    assert len(patterns) >= 8, (
        f"vendor pattern count {len(patterns)} below minimum 8 — "
        "is the second category group merged?"
    )
    assert len(mirrors) >= 5


# ----- pattern integrity -----

def test_every_pattern_has_required_keys(patterns):
    for p in patterns:
        missing = _REQUIRED_PATTERN_KEYS - set(p.keys())
        assert not missing, f"pattern {p.get('id')!r} missing keys: {missing}"


def test_every_pattern_id_unique(patterns):
    ids = [p["id"] for p in patterns]
    assert len(ids) == len(set(ids)), f"duplicate pattern ids in vendor set: {ids}"


def test_every_pattern_signature_compiles(patterns):
    for p in patterns:
        try:
            re.compile(p["signature"])
        except re.error as exc:
            pytest.fail(f"pattern {p['id']!r} signature does not compile: {exc}")


def test_every_pattern_kind_supported(patterns):
    """The standalone classifier supports path + header patterns."""
    supported = {"path", "header"}
    for p in patterns:
        assert p["kind"] in supported, (
            f"pattern {p['id']!r} kind={p['kind']!r} not yet supported by classify.py"
        )


def test_every_pattern_origin_is_vendor(patterns):
    """Vendor JSON must declare origin='vendor' so trust ranking is honest."""
    for p in patterns:
        assert p["origin"] == "vendor", (
            f"pattern {p['id']!r} origin={p['origin']!r}, must be 'vendor' in this file"
        )


def test_every_pattern_severity_valid(patterns):
    for p in patterns:
        assert p["severity"] in {"info", "warn", "critical"}


def test_every_pattern_confidence_in_range(patterns):
    for p in patterns:
        c = p["confidence"]
        assert 0.0 <= c <= 1.0, f"pattern {p['id']!r} confidence={c} out of range"


def test_header_patterns_declare_target_header(patterns):
    for p in patterns:
        if p["kind"] != "header":
            continue
        assert p.get("header_name"), (
            f"header pattern {p['id']!r} must declare header_name for scoped matching"
        )


# ----- mirror integrity -----

def test_every_mirror_has_required_keys(mirrors):
    for m in mirrors:
        missing = _REQUIRED_MIRROR_KEYS - set(m.keys())
        assert not missing, f"mirror {m.get('id')!r} missing keys: {missing}"


def test_every_mirror_id_unique(mirrors):
    ids = [m["id"] for m in mirrors]
    assert len(ids) == len(set(ids)), f"duplicate mirror ids: {ids}"


def test_every_mirror_intensity_valid(mirrors):
    for m in mirrors:
        assert m["intensity"] in {"minimal", "moderate", "elaborate"}


def test_every_mirror_http_status_sane(mirrors):
    for m in mirrors:
        assert 100 <= m["http_status"] < 600


def test_every_mirror_template_var_uses_supported_generator(mirrors):
    for m in mirrors:
        for var_name, gen_spec in m.get("body_template_vars", {}).items():
            gen_name = gen_spec.split(":", 1)[0].strip()
            assert gen_name in _SUPPORTED_GENERATORS, (
                f"mirror {m['id']!r} var {var_name!r} uses unsupported generator: {gen_spec!r}"
            )


def test_every_mirror_template_var_name_not_pii(mirrors):
    """mirror.py rejects PII-shaped var names at runtime; reject here too so
    we never ship a vendor mirror that the runtime would refuse."""
    for m in mirrors:
        for var_name in m.get("body_template_vars", {}):
            assert not _PII_VAR_RE.search(var_name), (
                f"mirror {m['id']!r} var {var_name!r} matches PII rejection regex — "
                "runtime would refuse this mirror"
            )


def test_every_mirror_body_template_safe(mirrors):
    """No hostile-marker leakage in the canned body templates we ship."""
    for m in mirrors:
        body_lower = m["body_template"].lower()
        for marker in _HOSTILE_PAYLOAD_MARKERS:
            assert marker not in body_lower, (
                f"mirror {m['id']!r} body_template contains hostile marker: {marker!r}"
            )


def test_every_mirror_headers_safe(mirrors):
    for m in mirrors:
        for hk, hv in m.get("headers", {}).items():
            for marker in _HOSTILE_PAYLOAD_MARKERS:
                assert marker not in (str(hk) + str(hv)).lower(), (
                    f"mirror {m['id']!r} header {hk!r} contains hostile marker: {marker!r}"
                )


# ----- cross-references -----

def test_every_pattern_mirror_resolves(patterns, mirrors):
    mirror_ids = {m["id"] for m in mirrors}
    for p in patterns:
        mr_id = p.get("mirror_response_id")
        if mr_id is None:
            continue  # patterns may legitimately omit a mirror (rare in vendor set)
        assert mr_id in mirror_ids, (
            f"pattern {p['id']!r} references mirror_response_id={mr_id!r} which doesn't exist"
        )


def test_every_mirror_referenced_by_at_least_one_pattern(patterns, mirrors):
    """Dead mirrors are dead code — fail the build."""
    referenced = {p.get("mirror_response_id") for p in patterns}
    referenced.discard(None)
    for m in mirrors:
        assert m["id"] in referenced, (
            f"mirror {m['id']!r} is not referenced by any pattern — dead code"
        )


# ----- false-positive sanity (vendor patterns must not match legit traffic) -----

@pytest.mark.parametrize("legit_path", [
    "/",
    "/index.html",
    "/api/users",
    "/admin-console",
    "/login",  # generic login MUST NOT match scanner UA pattern (which is header-kind)
    "/static/js/app.js",
    "/healthz",
    "/favicon.ico",
    "/robots.txt",
    "/api/v1/widgets/123",
    "/account",
])
def test_path_patterns_do_not_match_legit_traffic(patterns, legit_path):
    """Vendor path patterns must not fire on common legit URLs.
    A false-positive in the default set ships malware-shaped breakage
    to every operator on first install."""
    for p in patterns:
        if p["kind"] != "path":
            continue
        regex = re.compile(p["signature"])
        if regex.search(legit_path):
            pytest.fail(
                f"pattern {p['id']!r} (signature={p['signature']!r}) "
                f"falsely matches legit path {legit_path!r}"
            )


@pytest.mark.parametrize(("pattern_id", "probe_path"), [
    ("generic_admin_login_probe", "/admin"),
    ("generic_admin_login_probe", "/admin/"),
    ("wordpress_admin_probe", "/WP-ADMIN/"),
    ("phpmyadmin_probe", "/PHPMYADMIN/"),
    ("shell_uploader_probe", "/by.php"),
    ("env_file_probe", "/.envrc"),
    ("env_file_probe", "/config/settings/.env_backup"),
    ("env_file_probe", "/app/releases/current/.env_local"),
])
def test_vendor_path_patterns_cover_expected_probe_variants(patterns, pattern_id, probe_path):
    pattern = next(p for p in patterns if p["id"] == pattern_id)
    normalized = probe_path.lower().rstrip("/") or "/"
    regex = re.compile(pattern["signature"])
    assert regex.search(normalized), (
        f"pattern {pattern_id!r} did not match expected probe path {probe_path!r}"
    )


@pytest.mark.parametrize("legit_ua", [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
    "curl/8.4.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "python-requests/2.31.0",
    "okhttp/4.12.0",
])
def test_header_patterns_do_not_match_legit_user_agents(patterns, legit_ua):
    for p in patterns:
        if p["kind"] != "header":
            continue
        regex = re.compile(p["signature"])
        if regex.search(legit_ua):
            pytest.fail(
                f"pattern {p['id']!r} (signature={p['signature']!r}) "
                f"falsely matches legit UA {legit_ua!r}"
            )


@pytest.mark.parametrize("probe_ua", [
    "feroxbuster/2.11",
    "ffuf/2.1.0",
    "dirb/2.22",
    "BurpSuite Professional",
    "metasploit/6.4",
    "ZAP/2.15.0",
])
def test_scanner_ua_pattern_matches_expanded_tooling(patterns, probe_ua):
    pattern = next(p for p in patterns if p["id"] == "scanner_ua_probe")
    regex = re.compile(pattern["signature"])
    assert regex.search(probe_ua), f"scanner_ua_probe missed {probe_ua!r}"


def test_basic_auth_probe_does_not_match_unrelated_header_value(patterns):
    pattern = next(p for p in patterns if p["id"] == "basic_auth_probe")
    regex = re.compile(pattern["signature"])
    unrelated_header_value = "https://example.test/?token=Basic+dXNlcjpwYXNzd29yZA=="
    assert not regex.search(unrelated_header_value)
