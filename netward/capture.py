"""
Net Ward -- Capture Layer

aiohttp reverse-proxy entry point. All inbound HTTP traffic passes through
here: build a Probe, classify it, then route -- mirror response (probe/flood)
or pass-through to upstream (unknown/legit).

Design rule (from __init__.py): FAIL SAFE, FAIL OPEN.
If classification or mirroring raises, the request is forwarded to upstream
rather than dropped. Net Ward must never take the host application down.

Public interface:
    start_capture_loop(config, storage=None) -> None
        Bind to config["listen_address"], proxy to config["upstream_target"].
        Runs until cancelled (asyncio.CancelledError).
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from typing import Optional

import aiohttp
from aiohttp import web

from netward.schema import OperatorConfig, Probe, RequestMetadata, Source
from netward import classify as _classify_mod
from netward import mirror as _mirror_mod

# Body capture cap per schema (RequestMetadata.body_snippet)
_BODY_SNIPPET_MAX = 4096

# Must stay in sync with classify.FLOOD_WINDOW_SECS (both are 10.0 s, v0.4.1)
_RATE_WINDOW_SECS: float = 10.0

# Per-source rate windows (source_id -> bounded deque of request timestamps).
# maxlen=2000: headroom above the 1000-hit flood threshold to avoid evicting
# in-window timestamps before they age out naturally.
# Dict is capped at _RATE_WINDOW_MAX_SOURCES; oldest quarter evicted when full.
_RATE_WINDOW_MAX_SOURCES = 10_000
_rate_windows: dict[str, deque] = {}


def _get_rate_window(source_id: str) -> deque:
    if source_id not in _rate_windows:
        if len(_rate_windows) >= _RATE_WINDOW_MAX_SOURCES:
            evict_n = _RATE_WINDOW_MAX_SOURCES // 4
            for k in list(_rate_windows.keys())[:evict_n]:
                del _rate_windows[k]
        _rate_windows[source_id] = deque(maxlen=2000)
    return _rate_windows[source_id]

# Hop-by-hop headers stripped before forwarding upstream
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})

_PATTERN_CACHE_TTL = 30.0

# Default mirror variant set (v0.4.1 fingerprint hardening).
# A single fixed JSON shape was detectable under load (stress-state signature).
# Variant selection is deterministic per (source_id, path) so a given source
# sees a consistent shape per path — prevents second-probe shape divergence.
_DEFAULT_MIRROR: dict = {
    "id": "_netward_default",
    "matches_pattern_id": "",
    "intensity": "minimal",
    "http_status": 200,
    "headers": {"Content-Type": "application/json"},
    "body_template": '{"status":"ok","id":"{{uuid}}","timestamp":"{{timestamp}}"}',
    "body_template_vars": {"uuid": "uuid", "timestamp": "timestamp"},
    "description": "Default minimal mirror (fallback; prefer _select_default_mirror)",
    "created_at": 0.0,
}

_DEFAULT_MIRROR_VARIANTS: list[dict] = [
    {
        "id": "_netward_default_0",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 200,
        "headers": {"Content-Type": "application/json"},
        "body_template": '{"status":"ok","id":"{{uuid}}","timestamp":"{{timestamp}}"}',
        "body_template_vars": {"uuid": "uuid", "timestamp": "timestamp"},
        "description": "Default variant 0 — JSON ok",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_1",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 429,
        "headers": {"Content-Type": "application/json", "Retry-After": "30"},
        "body_template": '{"error":"rate limited","retry_after":30}',
        "body_template_vars": {},
        "description": "Default variant 1 — rate limited JSON",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_2",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 503,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body_template": "<html><body><h1>Service Unavailable</h1><p>Try again later.</p></body></html>",
        "body_template_vars": {},
        "description": "Default variant 2 — HTML 503",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_3",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 200,
        "headers": {"Content-Type": "application/json"},
        "body_template": '{"data":null,"next":null}',
        "body_template_vars": {},
        "description": "Default variant 3 — empty result JSON",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_4",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 200,
        "headers": {"Content-Type": "text/plain; charset=utf-8"},
        "body_template": "OK",
        "body_template_vars": {},
        "description": "Default variant 4 — plain OK",
        "created_at": 0.0,
    },
]


def _select_default_mirror(source_id: str, path: str) -> dict:
    """Deterministic variant per (source_id, path) to prevent shape divergence."""
    idx = abs(hash(source_id + path)) % len(_DEFAULT_MIRROR_VARIANTS)
    return _DEFAULT_MIRROR_VARIANTS[idx]


async def _read_body_snippet(request: web.Request) -> Optional[str]:
    try:
        raw = await request.read()
        if not raw:
            return None
        return raw[:_BODY_SNIPPET_MAX].decode("utf-8", errors="replace")
    except Exception:
        return None


async def _build_probe(request: web.Request, source_id: str) -> Probe:
    body = await _read_body_snippet(request)
    req_meta: RequestMetadata = {
        "method": request.method,
        "path": request.path,
        "headers": dict(request.headers),
        "query_string": request.query_string or None,
        "body_snippet": body,
        "body_size": len(body.encode("utf-8", errors="replace")) if body else 0,
        "user_agent": request.headers.get("User-Agent"),
    }
    return {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "source_id": source_id,
        "pattern_id": None,
        "classification": "unknown",
        "request": req_meta,
        "response_id": None,
        "mirror_fired": False,
        "upstream_passed": False,
    }


async def _forward_upstream(
    request: web.Request,
    upstream: str,
    session: aiohttp.ClientSession,
) -> Optional[web.Response]:
    """Forward to upstream. Return None when upstream is unavailable."""
    url = upstream.rstrip("/") + request.path
    if request.query_string:
        url += "?" + request.query_string
    body = await request.read()
    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }
    try:
        async with session.request(
            method=request.method,
            url=url,
            headers=fwd_headers,
            data=body,
            allow_redirects=False,
        ) as resp:
            content = await resp.read()
            resp_headers = {
                k: v for k, v in resp.headers.items()
                if k.lower() not in _HOP_BY_HOP | {"content-encoding"}
            }
            return web.Response(status=resp.status, headers=resp_headers, body=content)
    except Exception:
        return None


def _mirror_response_from_probe(probe: Probe, mirror: dict) -> web.Response:
    http_resp = _mirror_mod.fire_mirror(probe, mirror)
    return web.Response(
        status=http_resp["status"],
        headers=http_resp["headers"],
        text=http_resp["body"],
    )


def _fire_and_forget(storage, probe: Probe) -> None:
    """Schedule probe logging without blocking the response path."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(asyncio.to_thread(storage.probes_log, probe))
    except RuntimeError:
        pass  # no running loop (e.g., during sync tests)
    except Exception:
        pass


def _make_handler(config: OperatorConfig, storage, session: aiohttp.ClientSession):
    upstream = config["upstream_target"]

    # Per-handler pattern cache (closure) so each handler instance starts fresh
    # and tests don't bleed stale cached patterns into each other.
    _pcache: list = []
    _pcache_at: float = 0.0

    def _get_patterns() -> list:
        nonlocal _pcache, _pcache_at
        if time.time() - _pcache_at > _PATTERN_CACHE_TTL:
            try:
                _pcache = storage.patterns_active()
                _pcache_at = time.time()
            except Exception:
                pass  # fail-open: return stale cache rather than crashing request path
        return _pcache

    async def handle(request: web.Request) -> web.Response:
        ip = request.remote or "0.0.0.0"
        now = time.time()

        # Source lookup or create
        source: Source = storage.sources_lookup(ip) or {
            "id": str(uuid.uuid4()),
            "ip_address": ip,
            "reputation": "neutral",
            "first_seen": now,
            "last_seen": now,
            "probe_count": 0,
            "legit_count": 0,
            "notes": [],
        }
        source_id: str = source["id"]

        # Rate window update (in-memory, bounded + evicting)
        window = _get_rate_window(source_id)
        window.append(now)
        rate_window = list(window)

        probe = await _build_probe(request, source_id)

        # Classify -- fail-open on any unhandled exception
        patterns = _get_patterns()
        try:
            result = _classify_mod.classify(
                probe, {"patterns": patterns, "source": source, "rate_window": rate_window}
            )
        except Exception:
            probe["classification"] = "unknown"
            upstream_response = await _forward_upstream(request, upstream, session)
            if upstream_response is None:
                probe["mirror_fired"] = True
                probe["upstream_passed"] = False
                response = _mirror_response_from_probe(
                    probe, _select_default_mirror(source_id, request.path)
                )
            else:
                probe["upstream_passed"] = True
                response = upstream_response
            _fire_and_forget(storage, probe)
            return response

        updated = result["probe"]
        classification = updated.get("classification", "unknown")

        # Source counters + reputation.
        # Key on fire_mirror, not classification: a "flood"-classified request
        # that didn't match a pattern still passes to upstream — that's legit
        # traffic, not a probe. Only mirror-firing events are probe_count.
        if result["fire_mirror"]:
            source["probe_count"] = source.get("probe_count", 0) + 1
        else:
            source["legit_count"] = source.get("legit_count", 0) + 1
        source["last_seen"] = now
        source = _classify_mod.update_source_reputation(source)
        try:
            storage.sources_upsert(source)
        except Exception:
            pass  # fail-open: stale source state is acceptable

        # Route
        _default_mr = _select_default_mirror(source_id, request.path)
        if result["fire_mirror"]:
            mr_id = result.get("mirror_response_id")
            mr = (storage.mirror_response_lookup(mr_id) if mr_id else None) or _default_mr
            try:
                response = _mirror_response_from_probe(updated, mr)
            except Exception:
                # Mirror failed -- fail-open, pass upstream
                upstream_response = await _forward_upstream(request, upstream, session)
                if upstream_response is None:
                    updated["mirror_fired"] = True
                    updated["upstream_passed"] = False
                    response = _mirror_response_from_probe(updated, _default_mr)
                else:
                    updated["mirror_fired"] = False
                    updated["upstream_passed"] = True
                    response = upstream_response
        else:
            upstream_response = await _forward_upstream(request, upstream, session)
            if upstream_response is None:
                updated["mirror_fired"] = True
                updated["upstream_passed"] = False
                response = _mirror_response_from_probe(updated, _default_mr)
            else:
                updated["upstream_passed"] = True
                response = upstream_response

        _fire_and_forget(storage, updated)
        return response

    return handle


async def start_capture_loop(config: OperatorConfig, storage=None) -> None:
    """
    Bind to config["listen_address"] and begin proxying to
    config["upstream_target"]. Runs until cancelled.
    Fail-open: crashing this process does not harm the upstream service.
    """
    if storage is None:
        from netward.storage import Storage
        storage = Storage(config.get("storage_path", "netward.db"))

    try:
        from netward import bootstrap as _bootstrap
        _bootstrap.install_vendor_patterns(storage)
    except Exception:
        pass  # fail-open: never block startup on seed failure

    connector = aiohttp.TCPConnector()
    session = aiohttp.ClientSession(connector=connector)
    _proxy_handler = _make_handler(config, storage, session)

    @web.middleware
    async def catch_all(request: web.Request, handler) -> web.Response:
        return await _proxy_handler(request)

    app = web.Application(middlewares=[catch_all])

    runner = web.AppRunner(app)
    await runner.setup()

    listen = config.get("listen_address", "0.0.0.0:8080")
    host, _, port_str = listen.rpartition(":")
    if not host:
        host = "0.0.0.0"
    site = web.TCPSite(runner, host, int(port_str))
    await site.start()

    try:
        await asyncio.Event().wait()
    finally:
        await session.close()
        await runner.cleanup()
