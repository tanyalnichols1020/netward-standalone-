"""
Net Ward -- regex policy guard unit tests.
Pure logic: no I/O, no storage. Validates static-analysis insertion guard
and the safe_search runtime wrapper.
"""
from __future__ import annotations

import logging
import re

import pytest

from netward.regex_policy import (
    PATTERN_LENGTH_CAP,
    PatternPolicyError,
    _DANGEROUS_SHAPES,
    safe_search,
    validate_pattern_signature,
)


# ---------------------------------------------------------------------------
# validate_pattern_signature -- accept clean
# ---------------------------------------------------------------------------

CLEAN_PATTERNS = [
    r"^/\.env$",
    r"^/\.env(\.[\w.]+)?$",
    r"^/\.git/(config|HEAD|index)$",
    r"^/(wp-admin|wp-login\.php)/?$",
    r"(?i)^Basic\s+[A-Za-z0-9+/=]{8,}$",
    r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster)",
    r"^/admin/?$",
    r"(foo|bar|baz)+",  # disjoint alternation -- safe; documented coverage caveat
]


@pytest.mark.parametrize("sig", CLEAN_PATTERNS)
def test_validate_accepts_clean_patterns(sig):
    validate_pattern_signature(sig)


# ---------------------------------------------------------------------------
# validate_pattern_signature -- reject catastrophic
# ---------------------------------------------------------------------------

CATASTROPHIC_PATTERNS = [
    r"^/(a+)+$",      # canonical nested-quantifier
    r"^/(.+)+$",      # greedy variant
    r"^([a-z]+)+$",   # character-class variant
    r"^/(a?)+$",      # repeated optional family
    r"^([a-z]*)*$",   # nested star-on-star
    r"^(\w+)*\!$",    # canonical anchor-fail family
    r"^([a-z]{1,5})+$",  # bounded inner with outer +
]


@pytest.mark.parametrize("sig", CATASTROPHIC_PATTERNS)
def test_validate_rejects_catastrophic_shapes(sig):
    with pytest.raises(PatternPolicyError, match="catastrophic-backtracking"):
        validate_pattern_signature(sig)


# ---------------------------------------------------------------------------
# validate_pattern_signature -- other reject paths
# ---------------------------------------------------------------------------

def test_validate_rejects_oversize():
    sig = "^/" + "a" * (PATTERN_LENGTH_CAP + 1)
    with pytest.raises(PatternPolicyError, match="exceeds cap"):
        validate_pattern_signature(sig)


def test_validate_rejects_noncompiling():
    with pytest.raises(PatternPolicyError, match="does not compile"):
        validate_pattern_signature(r"[unclosed")


def test_validate_rejects_non_string():
    with pytest.raises(PatternPolicyError, match="must be a string"):
        validate_pattern_signature(123)  # type: ignore[arg-type]


def test_validate_error_message_does_not_leak_signature():
    """Per design Section 5 #3: signatures never appear in error messages."""
    sig = r"^/(SECRET_PROBE_PATH_a+)+$"
    try:
        validate_pattern_signature(sig)
    except PatternPolicyError as e:
        assert "SECRET_PROBE_PATH" not in str(e)
    else:
        pytest.fail("expected PatternPolicyError")


# ---------------------------------------------------------------------------
# Vendor pattern regression -- the validator must accept every shipping pattern
# ---------------------------------------------------------------------------

def test_vendor_patterns_all_pass_validation():
    """Regression guard: any shipping vendor pattern that fails validation is
    a vendor-pattern bug to fix, not a reason to weaken the validator."""
    import json
    from importlib import resources

    with resources.files("netward.data").joinpath("vendor_patterns.json").open("r") as f:
        bundle = json.load(f)

    patterns = bundle.get("patterns", [])
    assert patterns, "vendor pattern bundle is empty -- did the file move?"
    for p in patterns:
        sig = p.get("signature", "")
        try:
            validate_pattern_signature(sig)
        except PatternPolicyError as e:
            pytest.fail(f"vendor pattern {p.get('id')!r} failed validation: {e}")


# ---------------------------------------------------------------------------
# safe_search -- behavior parity with re.search on clean input
# ---------------------------------------------------------------------------

def test_safe_search_match_returns_match_object():
    m = safe_search(r"\.env", "/.env")
    assert m is not None
    assert m.group(0) == ".env"


def test_safe_search_no_match_returns_none():
    assert safe_search(r"\.env", "/foo") is None


def test_safe_search_respects_flags():
    # IGNORECASE mirrors re.search(flags=re.IGNORECASE)
    assert safe_search(r"basic", "Basic XYZ", flags=re.IGNORECASE) is not None
    assert safe_search(r"basic", "Basic XYZ") is None


def test_safe_search_returns_none_on_compile_error_and_logs(caplog):
    """Silent compile failures must surface a pattern_id-keyed log line so
    operators can see why a pattern never fires. The signature itself does
    NOT appear in the log."""
    with caplog.at_level(logging.WARNING, logger="netward.regex_policy"):
        result = safe_search(r"[unclosed", "anything", pattern_id="bad-pattern-id")
    assert result is None
    matched = [r for r in caplog.records if "regex_compile_error" in r.getMessage()]
    assert matched, "expected regex_compile_error log line"
    # pattern_id surfaced via extra= attached to the LogRecord
    record = matched[0]
    assert getattr(record, "pattern_id", None) == "bad-pattern-id"
    # signature does not leak through
    assert "[unclosed" not in record.getMessage()


# ---------------------------------------------------------------------------
# Documented coverage gap (will not be caught in v0.4.1 -- v0.5 with re2)
# ---------------------------------------------------------------------------

def test_documented_gap_overlapping_alternation_passes_for_now():
    """v0.4.1 coverage gap: substring analysis cannot distinguish overlapping
    alternation like (a|aa)+ from legitimate disjoint alternation like
    (foo|bar)+. v0.5's re2 migration closes this. Test pins the current
    behavior so any future change is intentional."""
    # These overlap and ARE catastrophic, but pass v0.4.1 validation
    validate_pattern_signature(r"^(a|aa)+$")
    validate_pattern_signature(r"^(a|ab)+$")


# ---------------------------------------------------------------------------
# _DANGEROUS_SHAPES sanity -- guard list is non-empty and distinct
# ---------------------------------------------------------------------------

def test_dangerous_shapes_list_is_distinct():
    assert len(_DANGEROUS_SHAPES) == len(set(_DANGEROUS_SHAPES))


def test_dangerous_shapes_list_is_non_empty():
    assert len(_DANGEROUS_SHAPES) >= 8
