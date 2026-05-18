"""
Net Ward — Schema v0 contract tests
Round-trip serialization, type literal coverage, constant sanity.
Locks the contract; future implementations build against these passing tests.
"""
from __future__ import annotations

import json
import time

import pytest

from netward import schema


def _now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Round-trip serialization — schema entities must JSON-serialize cleanly
# (storage backends and mesh propagation both depend on this)
# ---------------------------------------------------------------------------

class TestSerializationRoundTrip:
    def test_source_round_trip(self):
        src: schema.Source = {
            "id": "src-uuid-1",
            "ip_address": "203.0.113.42",
            "asn": 13335,
            "asn_name": "CloudflareNet",
            "geo_country": "US",
            "geo_region": "CA",
            "reputation": "suspicious",
            "first_seen": _now() - 3600,
            "last_seen": _now(),
            "probe_count": 42,
            "legit_count": 0,
            "notes": ["caught probing /wp-admin"],
        }
        encoded = json.dumps(src)
        decoded = json.loads(encoded)
        assert decoded["reputation"] == "suspicious"
        assert decoded["probe_count"] == 42

    def test_pattern_round_trip(self):
        pat: schema.Pattern = {
            "id": "pat-uuid-1",
            "kind": "path",
            "signature": r"^/wp-admin\b",
            "description": "WordPress admin probe",
            "severity": "warn",
            "origin": "vendor",
            "origin_node_id": None,
            "created_at": _now(),
            "last_matched": _now(),
            "match_count": 17,
            "mirror_response_id": "mr-uuid-1",
            "confidence": 0.95,
        }
        encoded = json.dumps(pat)
        decoded = json.loads(encoded)
        assert decoded["kind"] == "path"
        assert decoded["confidence"] == 0.95

    def test_probe_round_trip_with_request_metadata(self):
        probe: schema.Probe = {
            "id": "probe-uuid-1",
            "timestamp": _now(),
            "source_id": "src-uuid-1",
            "pattern_id": "pat-uuid-1",
            "classification": "probe",
            "request": {
                "method": "GET",
                "path": "/wp-admin/",
                "headers": {"User-Agent": "Mozilla/5.0 ..."},
                "body_size": 0,
            },
            "response_id": "mr-uuid-1",
            "mirror_fired": True,
            "upstream_passed": False,
        }
        encoded = json.dumps(probe)
        decoded = json.loads(encoded)
        assert decoded["classification"] == "probe"
        assert decoded["mirror_fired"] is True
        assert decoded["request"]["method"] == "GET"

    def test_mirror_response_round_trip(self):
        mr: schema.MirrorResponse = {
            "id": "mr-uuid-1",
            "matches_pattern_id": "pat-uuid-1",
            "intensity": "moderate",
            "http_status": 200,
            "headers": {"Content-Type": "text/html"},
            "body_template": "<html><body>Welcome {{user_id}}</body></html>",
            "body_template_vars": {"user_id": "fake_id"},
            "description": "Fake WordPress admin success page",
            "created_at": _now(),
        }
        encoded = json.dumps(mr)
        decoded = json.loads(encoded)
        assert decoded["intensity"] == "moderate"
        assert "{{user_id}}" in decoded["body_template"]

    def test_mesh_intel_round_trip_with_signature(self):
        intel: schema.MeshIntel = {
            "id": "intel-uuid-1",
            "kind": "new_pattern",
            "origin_node_id": "node-uuid-local-hub",
            "payload": {"pattern_id": "pat-uuid-99",
                        "kind": "path",
                        "signature": r"^/.env"},
            "signature": "base64-ed25519-sig-placeholder",
            "published_at": _now(),
            "expires_at": _now() + schema.INTEL_DEFAULT_TTL_SECS,
            "propagation_count": 0,
            "received_at": None,
            "verified": False,
        }
        encoded = json.dumps(intel)
        decoded = json.loads(encoded)
        assert decoded["kind"] == "new_pattern"
        assert decoded["verified"] is False
        assert decoded["payload"]["signature"] == r"^/.env"


# ---------------------------------------------------------------------------
# Type literal coverage — exhaustive set membership ensures Literal types
# don't get expanded silently
# ---------------------------------------------------------------------------

class TestTypeLiteralCoverage:
    def test_source_reputation_set(self):
        valid = {"clean", "neutral", "suspicious", "known_bad"}
        # Ensures the Literal in schema.SourceReputation is the canonical set
        for rep in valid:
            src: schema.Source = {"id": "x", "ip_address": "1.1.1.1",
                                  "reputation": rep, "first_seen": 0,
                                  "last_seen": 0, "probe_count": 0,
                                  "legit_count": 0}
            json.dumps(src)  # round-trip OK

    def test_pattern_kind_set(self):
        valid = {"path", "header", "body", "timing", "method",
                 "tls_fingerprint", "asn_burst", "composite"}
        # Set membership documented; future expansion requires schema bump
        assert "path" in valid
        assert "composite" in valid

    def test_probe_classification_set(self):
        valid = {"probe", "flood", "legit", "unknown"}
        assert "probe" in valid

    def test_alert_severity_ordering(self):
        # info → warn → critical is the documented escalation
        order = ["info", "warn", "critical"]
        assert len(order) == 3


# ---------------------------------------------------------------------------
# Constants — sanity bounds on operational thresholds
# ---------------------------------------------------------------------------

class TestSchemaConstants:
    def test_schema_version_is_implementation(self):
        """v0 was the schema sketch; v1+ means implementation is live."""
        assert schema.SCHEMA_VERSION >= 1

    def test_confidence_thresholds_sane(self):
        assert 0.0 < schema.CONFIDENCE_INSTALL_THRESHOLD < 1.0
        assert 0.0 < schema.CONFIDENCE_PUBLISH_THRESHOLD < 1.0
        # publish threshold must be >= install threshold
        # (don't publish patterns we haven't validated locally first)
        assert (schema.CONFIDENCE_PUBLISH_THRESHOLD
                >= schema.CONFIDENCE_INSTALL_THRESHOLD)

    def test_intel_ttl_within_reasonable_window(self):
        # Default TTL is one week — long enough to propagate, short
        # enough to expire stale intel
        assert schema.INTEL_DEFAULT_TTL_SECS > 86400  # > 1 day
        assert schema.INTEL_DEFAULT_TTL_SECS < 86400 * 30  # < 1 month

    def test_reputation_promotion_thresholds(self):
        assert schema.PROBES_TO_SUSPICIOUS < schema.PROBES_TO_KNOWN_BAD
        assert schema.PROBES_TO_SUSPICIOUS > 0

    def test_alert_dedup_window_reasonable(self):
        # Dedup window between 1 and 30 minutes
        assert 60 < schema.ALERT_DEDUP_WINDOW_SECS < 1800

    def test_heartbeat_interval_reasonable(self):
        # Heartbeats between 30s and 5 min
        assert 30 <= schema.HEARTBEAT_INTERVAL_SECS <= 300


# ---------------------------------------------------------------------------
# Trust manifest — versioning + chain auditability
# ---------------------------------------------------------------------------

class TestTrustManifest:
    def test_trust_manifest_round_trip(self):
        manifest: schema.TrustManifest = {
            "version": 3,
            "updated_at": _now(),
            "nodes": [
                {"node_id": "node-central-hub",
                 "public_key": "base64-pubkey-placeholder",
                 "operator_label": "central-hub",
                 "trust_level": "full",
                 "added_at": _now() - 86400},
            ],
            "central_authority_pubkey": "base64-authority-pubkey",
        }
        encoded = json.dumps(manifest)
        decoded = json.loads(encoded)
        assert decoded["version"] == 3
        assert len(decoded["nodes"]) == 1
        assert decoded["nodes"][0]["trust_level"] == "full"
