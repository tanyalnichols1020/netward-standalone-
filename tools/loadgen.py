"""Net Ward operator sustained-rate load generator.

A defensive capacity-planning and stress-test tool for Net Ward operators.
Drives steady-rate HTTP traffic against a Net Ward instance you control and
reports latency percentiles (success and error tracked separately), error
breakdown, and (optionally) target-process metrics sampled via psutil. Use
this to characterize your single-box capacity, validate post-deployment
behavior, and confirm sustained-load resource bounds before going live.
Only run this against systems you own or are explicitly authorized to test.

Pacing is open-loop: the tool keeps firing at the configured RPS even if
the target is saturated. Use --duration to bound the run and watch target
metrics for backpressure indicators.

Example:
    python tools/loadgen.py \\
        --target http://127.0.0.1:8080/ \\
        --rps 1000 --duration 60 --target-pid 12345

JSON summary -> stdout. Rolling progress -> stderr.
"""

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from typing import List

try:
    import aiohttp
except ImportError:
    sys.stderr.write("ERROR: aiohttp not installed. pip install aiohttp\n")
    sys.exit(2)

try:
    import psutil
except ImportError:
    psutil = None


@dataclass
class Metrics:
    request_count: int = 0
    success_count: int = 0
    error_count: int = 0
    success_latencies_ms: List[float] = field(default_factory=list)
    error_latencies_ms: List[float] = field(default_factory=list)
    status_codes: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)
    response_body_bytes: List[int] = field(default_factory=list)
    response_body_bytes_by_status: dict = field(default_factory=dict)
    abandoned_count: int = 0
    started_at: float = 0.0
    ended_at: float = 0.0
    target_samples: List[dict] = field(default_factory=list)


async def fire_one(session, url, method, metrics):
    t0 = time.perf_counter()
    try:
        async with session.request(method, url) as resp:
            body = await resp.read()
            latency_ms = (time.perf_counter() - t0) * 1000
            metrics.request_count += 1
            metrics.success_count += 1
            metrics.success_latencies_ms.append(latency_ms)
            metrics.status_codes[resp.status] = metrics.status_codes.get(resp.status, 0) + 1
            metrics.response_body_bytes.append(len(body))
            metrics.response_body_bytes_by_status.setdefault(resp.status, []).append(len(body))
    except Exception as e:
        latency_ms = (time.perf_counter() - t0) * 1000
        metrics.request_count += 1
        metrics.error_count += 1
        metrics.error_latencies_ms.append(latency_ms)
        err_key = type(e).__name__
        metrics.errors[err_key] = metrics.errors.get(err_key, 0) + 1


async def rate_pump(session, url, method, rps, duration, metrics):
    interval = 1.0 / rps
    started = time.monotonic()
    end_at = started + duration
    pending = []
    next_fire = started

    while time.monotonic() < end_at:
        now = time.monotonic()
        if now >= next_fire:
            task = asyncio.create_task(fire_one(session, url, method, metrics))
            pending.append(task)
            next_fire += interval
            if len(pending) > 1024:
                pending = [t for t in pending if not t.done()]
        else:
            await asyncio.sleep(min(interval / 4, max(next_fire - now, 0.0001)))

    if pending:
        done, not_done = await asyncio.wait(pending, timeout=30)
        metrics.abandoned_count = len(not_done)


async def progress_reporter(metrics, interval, end_at):
    while time.monotonic() < end_at:
        await asyncio.sleep(interval)
        top_err = dict(sorted(metrics.errors.items(), key=lambda kv: -kv[1])[:3])
        sys.stderr.write(
            f"[loadgen] reqs={metrics.request_count} "
            f"ok={metrics.success_count} err={metrics.error_count} "
            f"top_err={top_err if top_err else '{}'}\n"
        )
        sys.stderr.flush()


async def target_metrics_sampler(metrics, pid, interval, end_at):
    if not psutil:
        sys.stderr.write("[loadgen] psutil not installed; skipping target sampling\n")
        return
    try:
        proc = psutil.Process(pid)
        proc.cpu_percent(interval=None)
    except Exception as e:
        sys.stderr.write(f"[loadgen] cannot attach to PID {pid}: {e}\n")
        return
    while time.monotonic() < end_at:
        try:
            fd_count = proc.num_fds() if hasattr(proc, "num_fds") else proc.num_handles()
            metrics.target_samples.append({
                "t": time.time(),
                "cpu_pct": proc.cpu_percent(interval=None),
                "rss_mb": proc.memory_info().rss / 1024 / 1024,
                "num_fds": fd_count,
                "num_threads": proc.num_threads(),
            })
        except psutil.NoSuchProcess:
            sys.stderr.write("[loadgen] target process exited mid-run\n")
            break
        except Exception as e:
            sys.stderr.write(f"[loadgen] sampler error: {e}\n")
            break
        await asyncio.sleep(interval)


def percentile(values, pct):
    if not values:
        return None
    sv = sorted(values)
    k = (len(sv) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(sv) - 1)
    return sv[f] + (sv[c] - sv[f]) * (k - f)


def _latency_summary(latencies):
    if not latencies:
        return None
    return {
        "p50": round(percentile(latencies, 50), 2),
        "p95": round(percentile(latencies, 95), 2),
        "p99": round(percentile(latencies, 99), 2),
        "max": round(max(latencies), 2),
        "count": len(latencies),
    }


def summarize(metrics, request_size_bytes):
    duration = max(metrics.ended_at - metrics.started_at, 1e-9)
    out = {
        "duration_s": round(duration, 3),
        "achieved_rps": round(metrics.request_count / duration, 1),
        "request_count": metrics.request_count,
        "success_count": metrics.success_count,
        "error_count": metrics.error_count,
        "abandoned_count": metrics.abandoned_count,
        "status_codes": metrics.status_codes,
        "errors": metrics.errors,
        "latency_ms_success": _latency_summary(metrics.success_latencies_ms),
        "latency_ms_error": _latency_summary(metrics.error_latencies_ms),
    }
    if metrics.response_body_bytes:
        # Note: request_size_bytes is an estimate (URL + 150 byte aiohttp header overhead).
        # Real keep-alive headers land ~150-200 bytes, so ratios are accurate to ~20%.
        # The AMPLIFIER flag (>1.0) is robust to that error band.
        avg_resp = sum(metrics.response_body_bytes) / len(metrics.response_body_bytes)
        max_resp = max(metrics.response_body_bytes)
        per_status = {}
        for status, sizes in metrics.response_body_bytes_by_status.items():
            avg = sum(sizes) / len(sizes)
            per_status[str(status)] = {
                "count": len(sizes),
                "avg_bytes": round(avg, 1),
                "max_bytes": max(sizes),
                "ratio_avg": round(avg / request_size_bytes, 2),
                "flag": "AMPLIFIER" if avg / request_size_bytes > 1.0 else "ok",
            }
        out["amplification"] = {
            "request_size_bytes_est": request_size_bytes,
            "response_body_avg_bytes": round(avg_resp, 1),
            "response_body_max_bytes": max_resp,
            "amplification_ratio_avg": round(avg_resp / request_size_bytes, 2),
            "amplification_ratio_max": round(max_resp / request_size_bytes, 2),
            "flag_aggregate": "AMPLIFIER" if avg_resp / request_size_bytes > 1.0 else "ok",
            "by_status": per_status,
        }
    if metrics.target_samples:
        out["target"] = {
            "samples": len(metrics.target_samples),
            "cpu_max_pct": round(max(s["cpu_pct"] for s in metrics.target_samples), 1),
            "rss_max_mb": round(max(s["rss_mb"] for s in metrics.target_samples), 1),
            "rss_growth_mb": round(
                metrics.target_samples[-1]["rss_mb"] - metrics.target_samples[0]["rss_mb"], 1
            ),
            "fds_max": max(s["num_fds"] for s in metrics.target_samples),
            "fds_growth": (
                metrics.target_samples[-1]["num_fds"] - metrics.target_samples[0]["num_fds"]
            ),
            "threads_max": max(s["num_threads"] for s in metrics.target_samples),
        }
    return out


async def main_async(args):
    metrics = Metrics()
    timeout = aiohttp.ClientTimeout(total=args.request_timeout)
    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=args.concurrency)
    metrics.started_at = time.monotonic()
    end_at = metrics.started_at + args.duration

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [
            asyncio.create_task(rate_pump(session, args.target, args.method, args.rps, args.duration, metrics)),
            asyncio.create_task(progress_reporter(metrics, args.progress_interval, end_at)),
        ]
        if args.target_pid:
            tasks.append(asyncio.create_task(
                target_metrics_sampler(metrics, args.target_pid, args.sample_interval, end_at)
            ))
        await asyncio.gather(*tasks, return_exceptions=True)

    metrics.ended_at = time.monotonic()
    request_size_bytes = len(args.target.encode("utf-8")) + 150  # URL + estimated aiohttp header overhead
    summary = summarize(metrics, request_size_bytes)
    print(json.dumps(summary, indent=2))


def main():
    p = argparse.ArgumentParser(description="Net Ward operator load generator")
    p.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:8080/)")
    p.add_argument("--rps", type=int, default=100, help="Requests per second (default: 100)")
    p.add_argument("--duration", type=int, default=60, help="Duration in seconds (default: 60)")
    p.add_argument("--concurrency", type=int, default=100, help="Max concurrent connections (default: 100)")
    p.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument("--request-timeout", type=float, default=30.0)
    p.add_argument("--progress-interval", type=float, default=5.0)
    p.add_argument("--sample-interval", type=float, default=1.0)
    p.add_argument("--target-pid", type=int, help="PID of target process for resource sampling")
    args = p.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        sys.stderr.write("\n[loadgen] interrupted\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
