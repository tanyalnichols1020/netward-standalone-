# Net Ward
**User-space DDoS and bot deflection for small teams.**

Net Ward runs in front of an HTTP service as a reverse proxy. Normal traffic passes through. Known probe and abuse patterns receive harmless mirror responses that waste bot effort without damaging the client, the protected application, or the host system.

---

## Quick Start

From the repo root:

```bash
pip install -e .
python -m netward --config example_config.json
```

Net Ward listens on `listen_address` and forwards clean traffic to `upstream_target`.

---

## Configuration

Copy the example config and edit the upstream target:

```bash
cp example_config.json config.json
```

Point `upstream_target` at a real HTTP service before you start Net Ward. If
the upstream is unreachable, unmatched requests return a default mirror response
instead of exposing a raw proxy error.

Required fields:

| Field | Meaning |
|-------|---------|
| `node_id` | Stable name for this Net Ward instance |
| `upstream_target` | HTTP service being protected |
| `listen_address` | Host and port Net Ward binds |

Optional fields control mirror intensity, local storage, mesh placeholders, and alert channels. v0.4.1 logs alerts to stdout; external alert delivery is reserved for a later release.

---

## Run

```bash
python -m netward --config config.json
```

Example topology:

| Component | Address |
|-----------|---------|
| Net Ward | `127.0.0.1:8080` |
| Upstream app | `http://127.0.0.1:9000` |
| Storage | `netward.db` |

Point your load balancer or web server at Net Ward. Keep the upstream app reachable only from the host or trusted network when possible.
Set `listen_address` to `0.0.0.0:<port>` only when you intentionally want Net Ward reachable beyond localhost.
On Linux/macOS, keep `storage_path` non-world-writable. Example: `chmod 600 netward.db`, or `chmod 644 netward.db` only if you intentionally need read access for monitoring.

### Resource Monitoring

Net Ward sustains its documented per-box capacity continuously, but Python runtime memory pools may retain working-set state after sustained heavy load. Operators running Net Ward under continuous heavy traffic should monitor process resource usage and restart the daemon periodically, for example weekly or when RSS exceeds 2x baseline. v0.5 will refine this guidance based on production telemetry.

---

## Verify

Clean request should reach upstream:

```bash
curl -i http://127.0.0.1:8080/
```

Known probe should be mirrored:

```bash
curl -i http://127.0.0.1:8080/wp-admin/
```

The WordPress probe returns a fake login page. The upstream service does not receive the request.

---

## Operator Commands

Install or refresh the bundled vendor pattern set:

```bash
python -m netward.cli --db netward.db install-patterns
python -m netward.cli --db netward.db install-patterns --force
```

List active patterns:

```bash
python -m netward.cli --db netward.db list-patterns
```

Disable or re-enable a pattern:

```bash
python -m netward.cli --db netward.db disable-pattern wordpress_admin_probe
python -m netward.cli --db netward.db enable-pattern wordpress_admin_probe
```

If your upstream exposes a real admin panel at `/admin`, disable
`generic_admin_login_probe` or replace it with a tighter operator pattern before
putting Net Ward in front of that service:

```bash
python -m netward.cli --db netward.db disable-pattern generic_admin_login_probe
```

---

## Optional Patterns

Some vendor patterns are shipped but **disabled by default** because they can
break legitimate traffic if your upstream uses the same protocol feature the
pattern targets.

### `basic_auth_probe`

Catches brute-force credential stuffing via `Authorization: Basic <base64>`.

**Safe to enable only when:** your upstream does not use HTTP Basic Auth at all.
If your upstream accepts Basic Auth credentials from real users, enabling this
pattern traps those users in an infinite 401 loop — Net Ward returns a fake
challenge, the browser re-prompts, the cycle repeats.

Enable:

```bash
netward --db netward.db enable-pattern basic_auth_probe
```

Disable again:

```bash
netward --db netward.db disable-pattern basic_auth_probe
```

To verify it is working once enabled:

```bash
curl -i -H "Authorization: Basic dXNlcjpwYXNz" http://127.0.0.1:8080/api/admin
```

Should return `401` with `WWW-Authenticate: Basic realm="Restricted"`. The
upstream should not receive the request.

---

## Safety Model

Net Ward is fail-open and user-space only:

- No kernel hooks
- No packet tampering outside normal HTTP responses
- No hostile payloads
- No collection of submitted login values
- No retaliation
- If classification, storage, or mirror rendering fails, traffic passes to upstream

The mirror layer is meant to deflect automated abuse, not attack it back.

---

## Files

| File | Purpose |
|------|---------|
| `capture.py` | Reverse proxy and request capture |
| `classify.py` | Pattern matching and flood classification |
| `mirror.py` | Safe mirror response rendering |
| `storage.py` | SQLite persistence |
| `bootstrap.py` | Vendor pattern seeding |
| `cli.py` | Operator management commands |
| `data/vendor_patterns.json` | Bundled default probe patterns |
| `operator_layer.py` | Config validation and alert surface |

---

*Net Ward v0.4.1*
