"""
Buyer hygiene gate for Net Ward source.

Net Ward ships under Apache 2.0 to paying operators. Every line in the
package must be OK to read on day one. This test scans production source
and operator-facing files for content that has no business in a
buyer-distributable artifact: personal paths, internal team narrative
references, sister-product leakage, debug residue.

Production source: every .py file in netward/ that is not a test_*.py
Operator-facing: README.md, NOTICE, LICENSE, example_config.json
Allowed exceptions: data/vendor_patterns.json (deception content; the
"AKIA" prefix in the AWS fake mirror is intentional bait, not a leak).

Each check fails loudly with the offending file + matched string so
cleanup is mechanical. Add to the denylist as patterns of leakage are
discovered in review.
"""
from __future__ import annotations

from pathlib import Path

import pytest


NETWARD_DIR = Path(__file__).parent
PROJECT_ROOT = NETWARD_DIR.parent

# All .py files under netward/ except __pycache__
_ALL_PY = [p for p in NETWARD_DIR.rglob("*.py") if "__pycache__" not in p.parts]
PRODUCTION_PY = [p for p in _ALL_PY if not p.name.startswith("test_")]

# Tests ship with Apache 2.0 source distribution — buyers see them too.
# This file is the legitimate exception: it contains the denylist itself.
_HYGIENE_FILE_NAME = "test_buyer_hygiene.py"
TEST_PY = [p for p in _ALL_PY if p.name.startswith("test_") and p.name != _HYGIENE_FILE_NAME]


# -----------------------------------------------------------------------------
# Denylists — substring matches (case-insensitive where noted)
# -----------------------------------------------------------------------------

# Paths that pin to a developer's local machine
PERSONAL_PATH_FRAGMENTS = (
    r"c:\users\tanya",
    r"\users\tanya",
    r"/users/tanya",
    r"/home/tanya",
)

# Sister-product references that should not appear in Net Ward source
SISTER_PRODUCT_REFS = (
    "dragon eye",
    "dragoneye",
    "adsbx",
    "adsbexchange",
    "adsb.lol",
)

# Specific intel hex codes from DE that must never leak into Net Ward source.
# These are public ICAO addresses but their presence here would signal that
# DE-internal context bled across product boundaries.
DE_INTEL_HEXES = (
    "000001",
    "249249",
    "F11AA3",
    "053977",
    "B6DB6D",
)

# Team / persona names that belong in NOTICE attribution (if anywhere),
# not in narrative comments or docstrings throughout production source.
TEAM_NAMES = (
    "Tanya",
    "Rocky",
    "Goldwing",
    "Fidget",
    "Mythos",
)
# Note: "Oracle" is excluded from this list because it has legitimate
# database-context meaning ("Oracle DB", "the oracle pattern"). "James"
# is excluded because it's too common a first name to mass-grep safely.
# Both rely on manual review.


def _read_lower(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").lower()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# -----------------------------------------------------------------------------
# Production source checks
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_personal_paths_in_production(py_file):
    text = _read_lower(py_file)
    found = [frag for frag in PERSONAL_PATH_FRAGMENTS if frag in text]
    assert not found, (
        f"{py_file.name} contains personal path fragments: {found}. "
        "Buyers see this; remove or replace with relative/configurable paths."
    )


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_sister_product_references_in_production(py_file):
    text = _read_lower(py_file)
    found = [ref for ref in SISTER_PRODUCT_REFS if ref in text]
    assert not found, (
        f"{py_file.name} contains sister-product references: {found}. "
        "Net Ward ships standalone; remove cross-product narrative."
    )


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_de_intel_hexes_in_production(py_file):
    text = _read(py_file)
    found = [h for h in DE_INTEL_HEXES if h in text]
    assert not found, (
        f"{py_file.name} contains intel hex codes that belong to a different "
        f"product: {found}."
    )


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_team_names_in_production(py_file):
    """Apache 2.0 attribution lives in NOTICE. Production code comments
    should not name individual contributors — that's narrative residue."""
    text = _read(py_file)
    found = [name for name in TEAM_NAMES if name in text]
    assert not found, (
        f"{py_file.name} contains team names: {found}. "
        "Move attribution to NOTICE or remove."
    )


_PRINT_OK_FILES = frozenset({
    "operator_layer.py",  # standalone alert delivery to stdout (documented)
    "cli.py",             # CLI tool: stdout is the user interface contract
    "__main__.py",        # entrypoint: print() before logger is configured for fatal errors
})


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_top_level_print_statements(py_file):
    """Production library code uses logging or return values; print() is
    debug residue. CLI / entrypoint / alert-delivery files where stdout
    IS the user interface are explicitly exempted."""
    if py_file.name in _PRINT_OK_FILES:
        return
    lines = _read(py_file).splitlines()
    offenders = []
    for i, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("print(") and not stripped.startswith("print()"):
            offenders.append(f"line {i}: {stripped[:60]}")
    assert not offenders, (
        f"{py_file.name} has print() calls in production code:\n  "
        + "\n  ".join(offenders)
    )


# -----------------------------------------------------------------------------
# Top-level package files (LICENSE / NOTICE presence)
# -----------------------------------------------------------------------------

def test_license_file_exists():
    assert (PROJECT_ROOT / "LICENSE").exists(), (
        "Apache 2.0 LICENSE file missing from project root"
    )


def test_notice_file_exists():
    assert (PROJECT_ROOT / "NOTICE").exists(), (
        "NOTICE file missing — Apache 2.0 attribution lives here"
    )


def test_license_is_apache_2_0():
    text = _read(PROJECT_ROOT / "LICENSE")
    assert "Apache License" in text
    assert "Version 2.0" in text


# -----------------------------------------------------------------------------
# Test files — also ship under Apache 2.0 source distribution.
# Buyers running `pip install -e .` or browsing the repo see them.
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_personal_paths_in_tests(py_file):
    text = _read_lower(py_file)
    found = [frag for frag in PERSONAL_PATH_FRAGMENTS if frag in text]
    assert not found, f"{py_file.name} contains personal path: {found}"


@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_sister_product_references_in_tests(py_file):
    text = _read_lower(py_file)
    found = [ref for ref in SISTER_PRODUCT_REFS if ref in text]
    assert not found, f"{py_file.name} references sister product: {found}"


@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_de_intel_hexes_in_tests(py_file):
    text = _read(py_file)
    found = [h for h in DE_INTEL_HEXES if h in text]
    assert not found, f"{py_file.name} contains intel hex codes: {found}"


@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_team_names_in_tests(py_file):
    text = _read(py_file)
    found = [name for name in TEAM_NAMES if name in text]
    assert not found, (
        f"{py_file.name} contains team names: {found}. "
        "Test docstrings ship under source distribution; scrub narrative."
    )


# -----------------------------------------------------------------------------
# Operator-facing artifacts (README, example_config, NOTICE) — these reach
# buyers directly and must not contain the same leaks production source can't.
# -----------------------------------------------------------------------------

OPERATOR_FACING = [
    p for p in [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "example_config.json",
        PROJECT_ROOT / "CHANGELOG.md",
        PROJECT_ROOT / "SECURITY.md",
    ]
    if p.exists()
]


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_personal_paths(doc):
    text = _read_lower(doc)
    found = [frag for frag in PERSONAL_PATH_FRAGMENTS if frag in text]
    assert not found, f"{doc.name} contains personal path: {found}"


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_sister_product_references(doc):
    text = _read_lower(doc)
    found = [ref for ref in SISTER_PRODUCT_REFS if ref in text]
    assert not found, (
        f"{doc.name} references a sister product: {found}. "
        "Net Ward ships standalone."
    )


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_de_intel_hexes(doc):
    text = _read(doc)
    found = [h for h in DE_INTEL_HEXES if h in text]
    assert not found, f"{doc.name} contains intel hex codes: {found}"


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_team_names(doc):
    text = _read(doc)
    found = [name for name in TEAM_NAMES if name in text]
    assert not found, (
        f"{doc.name} contains team names: {found}. "
        "Move attribution to NOTICE if needed."
    )
