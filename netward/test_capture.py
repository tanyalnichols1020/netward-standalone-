"""
Net Ward -- capture layer tests.
Tests the routing pipeline end-to-end using aiohttp.test_utils.TestClient.
Mirror and storage layers are stubbed.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque

import pytest
import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import netward.capture as cap_mod
from netward.capture import _make_handler
from netward.schema import OperatorConfig


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class _MockStorage:
    def __init__(self):
        self.sources: dict = {}
        self.patterns: list = []
        self.probes: list = []
        self.mirror_responses: dict = {}

    def sources_lookup(self, ip: str):
        return self.sources.get(ip)

    def sources_upsert(self, source):
        self.sources[source["ip_address"]] = source

    def patterns_active(self):
        return list(self.patterns)

    def probes_log(self, probe):
        self.probes.append(probe)

    def mirror_response_lookup(self, mr_id: str):
        return self.mirror_responses.get(mr_id)

    def alerts_recent(self, window_secs: int):
        return []

    def alerts_upsert(self, alert):
        pass


def _config(upstream: str = "http://127.0.0.1:59999") -> OperatorConfig:
    return {
        "node_id": "test-node",
        "upstream_target": upstream,
        "listen_address": "0.0.0.0:8080",
        "mirror_intensity_default": "minimal",
        "mesh_enabled": False,
        "alert_channels": [],
    }


def _wp_admin_pattern() -> dict:
    return {
        "id": "pat-wp-admin",
        "kind": "path",
        "signature": r"^/wp-admin\b",
        "description": "WordPress admin probe",
        "severity": "warn",
        "origin": "vendor",
        "created_at": time.time(),
        "match_count": 0,
        "confidence": 0.95,
        "mirror_response_id": None,
        "mutation_generation": 0,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_module_state():
    """Reset module-level rate windows between tests."""
    cap_mod._rate_windows.clear()
    yield
    cap_mod._rate_windows.clear()


@pytest.fixture
def mock_storage():
    return _MockStorage()


@pytest.fixture
def stub_mirror(monkeypatch):
    """Replace fire_mirror with a fixed detectable response."""
    def _fire(probe, mr):
        return {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"netward":"mirrored"}',
        }
    monkeypatch.setattr("netward.capture._mirror_mod.fire_mirror", _fire)


async def _make_client(config: OperatorConfig, storage) -> tuple[TestClient, aiohttp.ClientSession]:
    connector = aiohttp.TCPConnector()
    session = aiohttp.ClientSession(connector=connector)
    handler_func = _make_handler(config, storage, session)

    @web.middleware
    async def catch_all(request: web.Request, handler) -> web.Response:
        return await handler_func(request)

    app = web.Application(middlewares=[catch_all])
    client = TestClient(TestServer(app))
    await client.start_server()
    return client, session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_legit_request_forwarded_upstream(mock_storage):
    """
    No patterns, no flood -> classification=unknown -> forwards to upstream.
    If the upstream is unreachable, Net Ward falls back to the default mirror
    (one of five response-shape variants) rather than a raw 502.
    """
    client, session = await _make_client(_config(upstream="http://127.0.0.1:59997"), mock_storage)
    try:
        resp = await client.get("/api/v1/status")
        # Default mirror variants: 200 (json ok), 429 (rate limited), 503 (html),
        # 200 (empty json), 200 (plain). Any is valid; 502 is the failure mode.
        assert resp.status in {200, 429, 503}
        await asyncio.sleep(0.05)  # let fire-and-forget probe log flush
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "unknown"
        assert logged["upstream_passed"] is False
        assert logged["mirror_fired"] is True
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_probe_match_fires_mirror(mock_storage, stub_mirror):
    """
    Request matching a path pattern returns mirror response, not upstream 502.
    """
    mock_storage.patterns = [_wp_admin_pattern()]
    client, session = await _make_client(_config(), mock_storage)
    try:
        resp = await client.get("/wp-admin/login.php")
        assert resp.status == 200
        body = await resp.text()
        assert "mirrored" in body
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "probe"
        assert logged["mirror_fired"] is True
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_flood_with_probe_path_fires_mirror(mock_storage, stub_mirror):
    """
    Source in flood state (1000 hits in window) hitting a probe-shaped path
    still receives a mirror response (B1 semantics: pattern match drives mirror,
    flood state labels classification but does not change routing).
    """
    now = time.time()
    source_id = "flood-test-source"
    mock_storage.sources["127.0.0.1"] = {
        "id": source_id,
        "ip_address": "127.0.0.1",
        "reputation": "neutral",
        "first_seen": now,
        "last_seen": now,
        "probe_count": 0,
        "legit_count": 0,
        "notes": [],
    }
    mock_storage.patterns = [_wp_admin_pattern()]
    # 1000 timestamps within the last 0.5 s -> just at FLOOD_THRESHOLD (1000/10s)
    cap_mod._rate_windows[source_id] = deque([now - 0.1] * 1000, maxlen=2000)

    client, session = await _make_client(_config(), mock_storage)
    try:
        resp = await client.get("/wp-admin/")   # probe-shaped path → pattern match
        assert resp.status == 200               # stub_mirror always returns 200
        body = await resp.text()
        assert "mirrored" in body
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "flood"
        assert logged["mirror_fired"] is True
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_flood_without_probe_path_passes_through(mock_storage):
    """
    Source in flood state hitting a non-probe path still reaches upstream (B1).
    Upstream unavailable here → default mirror fallback, but classification is
    still 'flood' and the probe log shows the pass-through attempt.
    """
    now = time.time()
    source_id = "flood-test-source"
    mock_storage.sources["127.0.0.1"] = {
        "id": source_id,
        "ip_address": "127.0.0.1",
        "reputation": "neutral",
        "first_seen": now,
        "last_seen": now,
        "probe_count": 0,
        "legit_count": 0,
        "notes": [],
    }
    # No patterns installed — any path will pass through (or fall to mirror if upstream down)
    cap_mod._rate_windows[source_id] = deque([now - 0.1] * 1000, maxlen=2000)

    client, session = await _make_client(_config(upstream="http://127.0.0.1:59995"), mock_storage)
    try:
        resp = await client.get("/api/health")
        assert resp.status in {200, 429, 503}  # upstream down → default mirror variant
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "flood"
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_no_match_routes_upstream(mock_storage):
    """
    Pattern installed but path doesn't match -> unknown -> upstream.
    If upstream is unavailable, Net Ward falls back to one of the default mirror
    variants rather than a raw 502.
    """
    mock_storage.patterns = [_wp_admin_pattern()]
    client, session = await _make_client(_config(upstream="http://127.0.0.1:59996"), mock_storage)
    try:
        resp = await client.get("/totally/legitimate/endpoint")
        assert resp.status in {200, 429, 503}  # default mirror variant (not a raw 502)
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "unknown"
        assert logged["mirror_fired"] is True
        assert logged["upstream_passed"] is False
    finally:
        await client.close()
        await session.close()
