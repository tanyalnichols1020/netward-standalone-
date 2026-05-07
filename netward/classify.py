"""
Net Ward -- Classify Layer

Given a Probe and context (installed Patterns, Source state, rate window),
return a ClassifyResult with the routing decision.

classify(probe, ctx) -> ClassifyResult
    Core pipeline. No I/O -- all state arrives via ctx. Fail-safe: any
    NotImplementedError from unsupported Pattern kinds is swallowed so
    one bad pattern can never crash classification of legitimate traffic.

update_source_reputation(source) -> Source
    Recalculate reputation from cumulative probe_count.
    Returns updated copy; caller is responsible for persisting.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Optional, TypedDict

_log = logging.getLogger(__name__)
_warned_pattern_ids: set[str] = set()  # emit one warning per pattern id, not per request

from netward.schema import (
    Pattern,
    Probe,
    Source,
    PROBES_TO_SUSPICIOUS,
    PROBES_TO_KNOWN_BAD,
)
from netward.regex_policy import safe_search


class ClassifyContext(TypedDict, total=False):
    patterns: list[Pattern]
    source: Optional[Source]
    rate_window: list[float]  # recent request timestamps from this source


class ClassifyResult(TypedDict):
    probe: Probe
    fire_mirror: bool
    mirror_response_id: Optional[str]


# Flood gate defaults (v0.4.1 redesign).
# Previous: 30 hits in 1.0 s — tripped on normal bursty legitimate traffic.
# New: 1000 hits in 10.0 s — only trips on genuine flood volumes (100+ RPS
# sustained for 10 s), with natural sliding-window decay when traffic subsides.
FLOOD_WINDOW_SECS: float = 10.0
FLOOD_THRESHOLD: int = 1000

_ORIGIN_RANK: dict[str, int] = {"operator": 0, "vendor": 1, "mesh": 2, "local": 3}
_DEFAULT_HEADER_NAMES: dict[str, str] = {
    "basic_auth_probe": "Authorization",
    "scanner_ua_probe": "User-Agent",
}


def _pattern_sort_key(p: Pattern) -> tuple:
    origin = p.get("origin", "local")
    rank = _ORIGIN_RANK.get(origin, 3)
    # mesh: highest confidence first; local: highest match_count first
    secondary = -(p.get("confidence", 0.0)) if origin == "mesh" else 0
    tertiary = -(p.get("match_count", 0)) if origin == "local" else 0
    return (rank, secondary, tertiary)


def _normalize_path_for_match(path: str) -> str:
    path_part, sep, query = path.partition("?")
    normalized = path_part.lower()
    if len(normalized) > 1:
        normalized = normalized.rstrip("/") or "/"
    if sep:
        return f"{normalized}?{query.lower()}"
    return normalized


def _header_value(headers: dict[str, str], header_name: str) -> Optional[str]:
    target = header_name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def _match_pattern(probe: Probe, pattern: Pattern) -> bool:
    """
    Returns True if probe matches pattern.
    Raises NotImplementedError for kinds not yet implemented (body, timing,
    method, tls_fingerprint, asn_burst, composite -- deferred to a later
    release).
    Callers must catch NotImplementedError and skip the pattern.
    """
    kind = pattern.get("kind")
    sig = pattern.get("signature", "")
    req = probe.get("request", {})

    pattern_id = pattern.get("id", "")
    if kind == "path":
        path = _normalize_path_for_match(req.get("path", ""))
        return safe_search(sig, path, pattern_id=pattern_id) is not None
    if kind == "header":
        headers = req.get("headers", {})
        header_name = pattern.get("header_name") or _DEFAULT_HEADER_NAMES.get(pattern_id)
        if not header_name:
            return False
        header_value = _header_value(headers, header_name)
        if header_value is None:
            return False
        return safe_search(sig, header_value, re.IGNORECASE, pattern_id=pattern_id) is not None
    raise NotImplementedError(f"kind={kind!r} deferred to a later release")


def classify(probe: Probe, ctx: ClassifyContext) -> ClassifyResult:
    """
    Classification pipeline (v0.4.1 semantics):

    1. Detect flood state (sliding window — informational only, does not block).
    2. Pattern match always runs — for every source, regardless of flood state
       or reputation. This is the core B1 fix: previously, known_bad and flood
       sources were short-circuited to a mirror before pattern matching, denying
       legitimate traffic at the upstream.
    3. Pattern match → fire mirror (probe or flood classification).
    4. No match → pass through to upstream, regardless of source state.
       A flood source sending legitimate-shaped traffic still reaches upstream.
    """
    source: Optional[Source] = ctx.get("source")
    patterns: list[Pattern] = ctx.get("patterns") or []
    rate_window: list[float] = ctx.get("rate_window") or []
    now = time.time()

    updated: Probe = dict(probe)  # type: ignore[assignment]

    # 1. Flood detection (sliding window, does not route — informs classification label)
    recent = sum(1 for t in rate_window if now - t <= FLOOD_WINDOW_SECS)
    is_flood = recent >= FLOOD_THRESHOLD

    # 2+3. Pattern match — always runs
    for pattern in sorted(patterns, key=_pattern_sort_key):
        try:
            matched = _match_pattern(probe, pattern)
        except NotImplementedError as exc:
            pat_id = pattern.get("id", "?")
            if pat_id not in _warned_pattern_ids:
                _log.warning("pattern %s skipped: %s", pat_id, exc)
                _warned_pattern_ids.add(pat_id)
            continue
        if matched:
            updated["classification"] = "flood" if is_flood else "probe"
            updated["pattern_id"] = pattern["id"]
            updated["mirror_fired"] = True
            mr_id = pattern.get("mirror_response_id")
            if mr_id:
                updated["response_id"] = mr_id
            return {"probe": updated, "fire_mirror": True, "mirror_response_id": mr_id}

    # 4. No pattern match — upstream regardless of flood or reputation state
    updated["classification"] = "flood" if is_flood else "unknown"
    updated["upstream_passed"] = True
    return {"probe": updated, "fire_mirror": False, "mirror_response_id": None}


def update_source_reputation(source: Source) -> Source:
    """Flip reputation at thresholds. Returns updated copy; does not persist."""
    updated: Source = dict(source)  # type: ignore[assignment]
    count = updated.get("probe_count", 0)
    rep = updated.get("reputation", "neutral")
    if rep in ("clean", "neutral") and count >= PROBES_TO_SUSPICIOUS:
        updated["reputation"] = "suspicious"
    elif rep == "suspicious" and count >= PROBES_TO_KNOWN_BAD:
        updated["reputation"] = "known_bad"
    return updated
