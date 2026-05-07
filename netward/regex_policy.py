"""
Net Ward -- Regex Policy Guard (v0.4.1)

Insertion-time static analysis of regex signatures to reject patterns whose
shape is known to cause catastrophic backtracking ("ReDoS") in the live
classifier. v0.4.1 is best-effort using static shape detection plus a
length cap; full ReDoS protection requires v0.5's google-re2 migration.

WHY NOT RUNTIME TIMEOUT
   Python's `re` module does not release the GIL during catastrophic
   backtracking, so any threading-based timeout (concurrent.futures or
   threading.Thread.join) returns to the caller after the timeout, but
   the orphan worker thread continues holding the GIL until the regex
   completes. Under sustained adversarial load this jams the worker pool
   and prevents clean interpreter shutdown. Runtime timeout via threading
   is therefore unreliable. v0.4.1 ships without a runtime wrapper and
   relies on insertion validation to keep catastrophic patterns out of
   the live classifier in the first place.

WHY STATIC ANALYSIS, NOT SYNTHETIC INPUT TESTING
   Synthetic-input testing has the same orphan-thread limitation as
   runtime timeout. If a synthetic triggers catastrophic backtracking,
   the test thread is stuck. Static analysis on the signature itself
   (substring detection of known-bad shapes) is fast, reliable, and
   does not run the regex against any input.

WHAT V0.5 ADDS
   google-re2 (or equivalent linear-time regex engine) gives us a
   guaranteed linear-time match with no catastrophic backtracking,
   eliminating both the insertion validation gap (re2 either compiles
   the pattern in linear-mode or rejects it for unsupported features)
   and the runtime exposure (matches always return promptly).

KNOWN COVERAGE GAP IN V0.4.1
   Substring-based static analysis cannot detect ambiguous/overlapping
   alternation patterns like (a|aa)+ or (a+|b)+ -- alternatives that can
   match the same input via different splits, triggering exponential
   backtracking. Detecting these requires regex AST parsing to determine
   alternative overlap, which is out of scope for v0.4.1. v0.5's re2
   migration closes this gap by construction. Do not extend the
   _DANGEROUS_SHAPES list to try to catch alternation; substring checks
   produce false positives on legitimate disjoint alternations like
   (foo|bar)+.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

_log = logging.getLogger(__name__)

# v0.4.1 hardcoded limits per design ratification (V0_4_1_B3_REGEX_POLICY_DESIGN.md Section 5).
# Not config-tunable in v0.4.1; revisit in v0.5 with telemetry.
PATTERN_LENGTH_CAP = 512

# Known catastrophic regex shapes from public ReDoS literature.
# A signature containing any of these substrings is rejected at insertion.
# These are LITERAL substrings of regex source -- not regex patterns themselves
# (so the validator cannot itself ReDoS).
#
# Coverage gap (v0.5 with re2 closes): overlapping alternation like (a|aa)+
# requires regex AST parsing and is not detectable via substring search.
# Static analysis here catches nested-quantifier and repeated-optional-atom
# families; ambiguous-alternation families pass through.
_DANGEROUS_SHAPES: tuple[str, ...] = (
    "+)+",    # nested + on group with + (canonical (a+)+ family)
    "+)*",    # nested * on group with +
    "*)+",    # nested + on group with *
    "*)*",    # nested * on group with *
    "+)?+",   # nested + on optional group with +
    "*)?+",   # nested + on optional group with *
    "+)?*",   # nested * on optional group with +
    "*)?*",   # nested * on optional group with *
    "?)+",    # repeated optional atom: (a?)+ family
    "?)*",    # repeated optional atom with outer star
    "?)?+",   # repeated optional atom with non-greedy outer +
    "?)?*",   # repeated optional atom with non-greedy outer *
    "}+",     # bounded quantifier with outer + (e.g. {N,M}+)
    "}*",     # bounded quantifier with outer *
    "})+",    # group with bounded quantifier, outer +
    "})*",    # group with bounded quantifier, outer *
    "})?+",   # group with bounded quantifier, optional, outer +
    "})?*",   # group with bounded quantifier, optional, outer *
)


class PatternPolicyError(ValueError):
    """Raised when a pattern signature fails the regex policy guard."""


def _has_dangerous_shape(signature: str) -> Optional[str]:
    """Return the first dangerous shape found in `signature`, or None."""
    for shape in _DANGEROUS_SHAPES:
        if shape in signature:
            return shape
    return None


def validate_pattern_signature(signature: str) -> None:
    """Raise PatternPolicyError if `signature` is unsafe for the live classifier.

    Static analysis only -- no synthetic input runs. Cheap, reliable, no
    risk of the validator itself getting stuck in backtracking.

    Per the logger policy ratified in design, error messages do NOT include
    the signature itself -- signatures do not leak through observable channels.
    """
    if not isinstance(signature, str):
        raise PatternPolicyError("signature must be a string")
    if len(signature) > PATTERN_LENGTH_CAP:
        raise PatternPolicyError(
            f"signature length {len(signature)} exceeds cap {PATTERN_LENGTH_CAP}"
        )
    try:
        re.compile(signature)
    except re.error as e:
        raise PatternPolicyError(f"signature does not compile: {e}")
    bad_shape = _has_dangerous_shape(signature)
    if bad_shape is not None:
        raise PatternPolicyError(
            f"signature contains catastrophic-backtracking shape "
            f"(nested-quantifier pattern detected)"
        )


def safe_search(
    pattern: str,
    target: str,
    flags: int = 0,
    pattern_id: Optional[str] = None,
) -> Optional[re.Match]:
    """Drop-in replacement for re.search.

    v0.4.1: thin wrapper around re.search with no runtime timeout. Insertion
    validation is the primary defense; this wrapper exists as a single point
    of upgrade for v0.5's re2 migration. External callers should use this
    instead of re.search to keep the upgrade surface small.

    Returns a Match object on success, None on no-match. Treats compilation
    failures as no-match (a non-compiling pattern reaching runtime means
    insertion validation was bypassed; raising would crash the request) but
    emits a one-time warning per pattern_id so operators can see why the
    pattern is silently no-firing.
    """
    try:
        return re.search(pattern, target, flags)
    except re.error:
        # pattern_id-keyed log so operators can locate the bad pattern; the
        # signature itself is not logged (per the no-signature-in-logs rule).
        _log.warning(
            "regex_compile_error",
            extra={"pattern_id": pattern_id or "unknown"},
        )
        return None
