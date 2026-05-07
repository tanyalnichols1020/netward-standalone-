"""
End-to-end integration test for the Net Ward standalone proxy.

Spins up:
1. A mock upstream service (aiohttp web.Application returning "from upstream")
2. A Net Ward reverse proxy (the real `_make_handler` from capture.py)
   pointing at the mock upstream, backed by a real Storage on tmp_path

Then fires real HTTP requests through the Net Ward proxy and verifies
the full data flow works end-to-end:
    capture -> classify -> (mirror | upstream) -> storage

Coverage:
- Legit request → upstream sees it, returns "from upstream"
- Probe-matching request → mirror fires, upstream is NOT hit
- Flood (1000+ rapid requests from same source in 10s) → flood state; probe-shaped paths mirror, non-probe paths pass through
- Storage records probes with the right classifications
- Source reputation flips after enough probes accumulate

aiohttp's fire-and-forget probe logging is given a brief settle window
(asyncio.sleep) before assertions read the storage.
"""
from __future__ import annotations

import asyncio
import time
import uuid

import aiohttp
import pytest
from aiohttp import web

from netward.bootstrap import install_vendor_patterns
from netward.capture import _make_handler
from netward.classify import FLOOD_THRESHOLD
from netward.schema import Pattern
from netward.storage import Storage


def _make_pattern(signature: str) -> Pattern:
    return {
        "id": str(uuid.uuid4()),
        "kind": "path",
        "signature": signature,
        "description": "integration-test pattern",
        "severity": "warn",
        "origin": "operator",
        "origin_node_id": None,
        "created_at": time.time(),
        "last_matched": None,
        "match_count": 0,
        "mirror_response_id": None,
        "confidence": 0.9,
        "parent_pattern_id": None,
        "mutation_generation": 0,
    }


@pytest.fixture
def storage(tmp_path):
    s = Storage(tmp_path / "integration.db")
    yield s
    s.close()


async def _spin_up_upstream() -> tuple[web.AppRunner, int, list[str]]:
    """Mock upstream that records every path it served."""
    served: list[str] = []

    async def handle(request: web.Request) -> web.Response:
        served.append(request.path)
        return web.Response(text="from upstream")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port, served


async def _spin_up_proxy(
    storage: Storage, upstream_port: int
) -> tuple[web.AppRunner, int, aiohttp.ClientSession]:
    """Bind Net Ward proxy via _make_handler — the real handler used in production."""
    config = {
        "node_id": "integration-test",
        "upstream_target": f"http://127.0.0.1:{upstream_port}",
        "listen_address": "127.0.0.1:0",
    }
    session = aiohttp.ClientSession()
    proxy_handler = _make_handler(config, storage, session)

    @web.middleware
    async def catch_all(request: web.Request, handler) -> web.Response:
        return await proxy_handler(request)

    app = web.Application(middlewares=[catch_all])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port, session


async def _fire(
    client: aiohttp.ClientSession,
    url: str,
    headers: dict | None = None,
    allow_redirects: bool = True,
) -> tuple[int, str]:
    async with client.get(
        url, headers=headers or {}, allow_redirects=allow_redirects
    ) as resp:
        return resp.status, await resp.text()


async def _drain_probe_log_tasks(baseline: set, timeout: float = 0.5) -> None:
    """Wait for fire-and-forget `storage.probes_log` tasks to finish.

    capture._fire_and_forget schedules `to_thread(storage.probes_log, ...)`
    on the running loop; we filter `asyncio.all_tasks()` for those specific
    coroutines (by name) so aiohttp's connection-pool keepalives — which
    look "new" but never finish — don't block us.
    """
    def is_probe_log(task: asyncio.Task) -> bool:
        coro = task.get_coro()
        # to_thread() wraps the call; the inner coro repr includes the func name
        return "probes_log" in repr(coro)

    new_tasks = [
        t for t in asyncio.all_tasks()
        if t not in baseline
        and t is not asyncio.current_task()
        and not t.done()
        and is_probe_log(t)
    ]
    if not new_tasks:
        return
    try:
        await asyncio.wait_for(
            asyncio.gather(*new_tasks, return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        pass


async def _run_scenario(storage: Storage, paths: list[str]) -> dict:
    upstream_runner, upstream_port, served = await _spin_up_upstream()
    proxy_runner, proxy_port, proxy_session = await _spin_up_proxy(
        storage, upstream_port
    )
    try:
        baseline_tasks = set(asyncio.all_tasks())
        async with aiohttp.ClientSession() as client:
            results = []
            for path in paths:
                results.append(
                    await _fire(client, f"http://127.0.0.1:{proxy_port}{path}")
                )
        await _drain_probe_log_tasks(baseline_tasks)
    finally:
        await proxy_session.close()
        await proxy_runner.cleanup()
        await upstream_runner.cleanup()
    return {"results": results, "upstream_served": served}


# ----- Scenarios -----

def test_legit_request_reaches_upstream(storage):
    out = asyncio.run(_run_scenario(storage, ["/healthz"]))
    status, body = out["results"][0]
    assert status == 200
    assert body == "from upstream"
    assert out["upstream_served"] == ["/healthz"]


def test_probe_pattern_fires_mirror_and_blocks_upstream(storage):
    storage.patterns_upsert(_make_pattern(r"^/wp-admin"))
    out = asyncio.run(_run_scenario(storage, ["/wp-admin"]))
    status, body = out["results"][0]
    # Default mirror variant — status is one of {200, 429, 503} depending on
    # (source_id, path) hash. Any is correct; "from upstream" must not appear.
    assert status in {200, 429, 503}
    assert "from upstream" not in body
    assert out["upstream_served"] == [], "upstream must NOT see probe traffic"


def test_unmatched_request_passes_through_to_upstream(storage):
    storage.patterns_upsert(_make_pattern(r"^/wp-admin"))
    out = asyncio.run(_run_scenario(storage, ["/api/users"]))
    status, body = out["results"][0]
    assert status == 200
    assert body == "from upstream"
    assert out["upstream_served"] == ["/api/users"]


def test_probes_are_persisted_to_storage(storage):
    storage.patterns_upsert(_make_pattern(r"^/wp-admin"))
    asyncio.run(
        _run_scenario(storage, ["/healthz", "/wp-admin", "/api/users"])
    )
    rows = storage._conn.execute(
        "SELECT classification, COUNT(*) AS c FROM probes GROUP BY classification"
    ).fetchall()
    counts = {r["classification"]: r["c"] for r in rows}
    # 1 probe (wp-admin), 2 unknown (legit paths classify as 'unknown' since
    # there's no specific 'legit' detector — they pass to upstream)
    assert counts.get("probe", 0) == 1
    assert counts.get("unknown", 0) == 2


def test_flood_burst_classifies_as_flood(storage):
    # Send FLOOD_THRESHOLD + 1 requests so the window crosses the threshold
    # regardless of future threshold changes.
    paths = ["/api/random"] * (FLOOD_THRESHOLD + 1)
    asyncio.run(_run_scenario(storage, paths))
    rows = storage._conn.execute(
        "SELECT classification, COUNT(*) AS c FROM probes GROUP BY classification"
    ).fetchall()
    counts = {r["classification"]: r["c"] for r in rows}
    assert counts.get("flood", 0) >= 1, (
        f"expected at least one flood classification, got {counts}"
    )


def test_source_reputation_advances_with_probes(storage):
    storage.patterns_upsert(_make_pattern(r"^/probe-target"))
    # Fire 6 probes — should cross PROBES_TO_SUSPICIOUS (5)
    asyncio.run(_run_scenario(storage, ["/probe-target"] * 6))

    sources = storage._conn.execute("SELECT * FROM sources").fetchall()
    assert len(sources) == 1
    src = sources[0]
    assert src["probe_count"] >= 5
    assert src["reputation"] in ("suspicious", "known_bad")


# =============================================================================
# Vendor seed-and-fire — proves the default pattern set actually defends.
# bootstrap.install_vendor_patterns(storage) is what start_capture_loop calls
# on first run; we exercise it directly so the assertions can target specific
# vendor mirrors (env, scanner UA, basic auth header value match).
# =============================================================================


async def _run_vendor_scenario(
    storage: Storage,
    requests: list[dict],
) -> dict:
    """Like _run_scenario but each request is {path, headers?, follow?} and
    vendor patterns are pre-installed. `requests` shape:
        [{"path": "/.env"},
         {"path": "/", "headers": {"User-Agent": "sqlmap/1.0"}, "follow": False}]
    """
    install_vendor_patterns(storage)

    upstream_runner, upstream_port, served = await _spin_up_upstream()
    proxy_runner, proxy_port, proxy_session = await _spin_up_proxy(
        storage, upstream_port
    )
    try:
        baseline_tasks = set(asyncio.all_tasks())
        async with aiohttp.ClientSession() as client:
            results = []
            for req in requests:
                results.append(
                    await _fire(
                        client,
                        f"http://127.0.0.1:{proxy_port}{req['path']}",
                        headers=req.get("headers"),
                        allow_redirects=req.get("follow", True),
                    )
                )
        await _drain_probe_log_tasks(baseline_tasks)
    finally:
        await proxy_session.close()
        await proxy_runner.cleanup()
        await upstream_runner.cleanup()
    return {"results": results, "upstream_served": served}


def test_vendor_seed_env_probe_fires_fake_env_mirror(storage):
    """GET /.env after vendor seed → env_fake_blank mirror, upstream untouched."""
    out = asyncio.run(_run_vendor_scenario(storage, [{"path": "/.env"}]))
    status, body = out["results"][0]
    assert status == 200
    assert "APP_ENV=production" in body, (
        f"expected fake env body content, got: {body!r}"
    )
    assert out["upstream_served"] == [], (
        ".env probe must not reach upstream"
    )


def test_vendor_seed_aws_credentials_probe_fires_fake_aws_mirror(storage):
    """GET /.aws/credentials after vendor seed → aws_credentials_fake mirror."""
    out = asyncio.run(
        _run_vendor_scenario(storage, [{"path": "/.aws/credentials"}])
    )
    status, body = out["results"][0]
    assert status == 200
    # Fake AWS mirror substitutes {{fake_key}} into "AKIA<id>" — the AKIA
    # prefix is the literal in the template
    assert "AKIA" in body
    assert "aws_secret_access_key" in body
    assert out["upstream_served"] == []


def test_vendor_seed_shell_uploader_returns_fake_404(storage):
    """GET /shell.php → 404 nginx-lookalike (the deception is 'no shell here')."""
    out = asyncio.run(_run_vendor_scenario(storage, [{"path": "/shell.php"}]))
    status, body = out["results"][0]
    assert status == 404
    assert "404 Not Found" in body
    assert out["upstream_served"] == []


@pytest.mark.parametrize(("probe_path", "expected_status"), [
    ("/admin", 200),
    ("/WP-ADMIN/", 200),
    ("/PHPMYADMIN/", 200),
])
def test_vendor_seed_path_variants_fire_expected_mirrors(storage, probe_path, expected_status):
    out = asyncio.run(_run_vendor_scenario(storage, [{"path": probe_path}]))
    status, body = out["results"][0]
    assert status == expected_status
    assert "from upstream" not in body
    assert out["upstream_served"] == []


def test_vendor_seed_scanner_ua_redirects_to_honeypot(storage):
    """GET / with sqlmap UA → 302 redirect to a honeypot path.
    follow=False because the UA header travels with redirects, retriggering
    the same pattern → infinite redirect loop. We just want to verify the
    302 fired and upstream never saw the original probe."""
    out = asyncio.run(_run_vendor_scenario(storage, [
        {"path": "/", "headers": {"User-Agent": "sqlmap/1.7.2"}, "follow": False},
    ]))
    status, _body = out["results"][0]
    assert status == 302, (
        f"expected 302 redirect from scanner_ua_redirect mirror, got {status}"
    )
    assert out["upstream_served"] == [], (
        f"sqlmap UA leaked to upstream: {out['upstream_served']}"
    )


def test_vendor_seed_scanner_ua_ignores_non_user_agent_headers(storage):
    out = asyncio.run(_run_vendor_scenario(storage, [{
        "path": "/",
        "headers": {
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://scanner.test/?tool=sqlmap",
        },
    }]))
    status, body = out["results"][0]
    assert status == 200
    assert body == "from upstream"
    assert out["upstream_served"] == ["/"]


def test_vendor_seed_basic_auth_probe_fires_fake_realm(storage):
    """basic_auth_probe ships disabled by default. This test explicitly enables it
    (simulating an operator opt-in) then verifies the regex + mirror fire correctly
    end-to-end: Authorization header matched, 401 returned, upstream not hit."""
    # Seed vendor patterns then enable basic_auth_probe; _run_vendor_scenario's
    # internal install_vendor_patterns call is idempotent and preserves this state.
    install_vendor_patterns(storage)
    storage._conn.execute(
        "UPDATE patterns SET expires_at = NULL WHERE id = ?", ("basic_auth_probe",)
    )
    out = asyncio.run(_run_vendor_scenario(storage, [{
        "path": "/api/admin",
        "headers": {"Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
        "follow": False,  # don't follow Authenticate challenge
    }]))
    status, body = out["results"][0]
    assert status == 401, (
        f"expected 401 from basic_auth_fake_realm mirror, got {status} — "
        "either the regex match against header values broke or the mirror status changed"
    )
    assert "Authentication required" in body, (
        f"expected basic_auth body template, got: {body!r}"
    )
    assert out["upstream_served"] == [], (
        "basic auth probe leaked to upstream"
    )


def test_vendor_seed_basic_auth_probe_ignores_unusual_header_names(storage):
    out = asyncio.run(_run_vendor_scenario(storage, [{
        "path": "/api/admin",
        "headers": {
            "User-Agent": "Mozilla/5.0",
            "X-Debug-Authorization": "Basic dXNlcjpwYXNzd29yZA==",
        },
    }]))
    status, body = out["results"][0]
    assert status == 200
    assert body == "from upstream"
    assert out["upstream_served"] == ["/api/admin"]


def test_vendor_seed_legit_request_still_passes_through(storage):
    """Real browser UA + non-suspicious path → upstream sees it normally."""
    out = asyncio.run(_run_vendor_scenario(storage, [{
        "path": "/api/users/me",
        "headers": {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)"},
    }]))
    status, body = out["results"][0]
    assert status == 200
    assert body == "from upstream", (
        f"vendor seed broke a legit path — false positive in default set: {body!r}"
    )
    assert out["upstream_served"] == ["/api/users/me"]


def test_vendor_seed_persists_patterns_in_storage(storage):
    """Sanity: bootstrap actually wrote rows. Without this, every other vendor
    test would be passing because of fallthrough behavior.
    basic_auth_probe ships with expires_at=1 (disabled by default), so the
    active count is one less than the total seeded count."""
    pats, _mirrors = install_vendor_patterns(storage)
    assert pats >= 11, f"expected 11+ vendor patterns seeded, got {pats}"
    active = storage.patterns_active()
    vendor_count = sum(1 for p in active if p["origin"] == "vendor")
    assert vendor_count >= 10, (
        f"expected 10+ active vendor patterns after seed, got {vendor_count}"
    )


# =============================================================================
# B1 flood gate redesign — pass-through bypass
# =============================================================================


def test_flood_source_on_pass_through_path_reaches_upstream(storage):
    """Core B1 test: a source that has hit the flood threshold must still reach
    the upstream when it requests a non-probe-shaped path.

    This is the scenario that failed in Oracle's loadgen run (v0.4): 5,999 of
    6,000 requests to / returned the default mirror instead of upstream content.
    """
    storage.patterns_upsert(_make_pattern(r"^/probe-target"))

    # Fire 1001 probe-target requests to trip the flood gate, then one clean path
    paths = ["/probe-target"] * 1001 + ["/api/health"]
    out = asyncio.run(_run_scenario(storage, paths))

    # The probe-target hits should be mirrored
    for status, body in out["results"][:1001]:
        assert "from upstream" not in body

    # The clean path request after flood state must still reach upstream
    final_status, final_body = out["results"][-1]
    assert final_status == 200
    assert final_body == "from upstream", (
        "flood gate blocked a non-probe path — B1 pass-through bypass failed"
    )
    assert "/api/health" in out["upstream_served"], (
        "flood gate suppressed upstream delivery for a non-probe path"
    )


def test_flood_source_on_probe_path_still_gets_mirrored(storage):
    """Flood sources hitting probe-shaped paths still receive mirror responses."""
    storage.patterns_upsert(_make_pattern(r"^/probe-target"))
    paths = ["/probe-target"] * 1002
    out = asyncio.run(_run_scenario(storage, paths))

    # After flood state trips, probe-target hits still get mirrored
    for status, body in out["results"]:
        assert "from upstream" not in body, (
            "probe-shaped path from flood source leaked to upstream"
        )
