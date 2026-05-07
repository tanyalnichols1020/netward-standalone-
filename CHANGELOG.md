# Changelog

All notable changes to Net Ward are documented here.
Format follows Keep a Changelog. Versioning is semver.

## [Unreleased]

## [0.4.1] - 2026-05-07

### Security

- **`basic_auth_probe` disabled by default** — the pattern fires on any well-formed
  `Authorization: Basic <base64>` header, including legitimate users authenticating
  to a Basic Auth-protected upstream. Seeded in storage with `expires_at=1` so it
  never fires on a fresh install. Enable explicitly only when your upstream does not
  use HTTP Basic Auth (see README — Optional Patterns).

- **`WWW-Authenticate` realm de-branded** — the `basic_auth_fake_realm` mirror
  response previously emitted `realm="Net Ward Maintenance ..."`, a product-name
  fingerprint detectable in one probe. Changed to the generic `realm="Restricted"`.

- **Header matchers scoped to intended header field** — `scanner_ua_probe` now
  inspects `User-Agent` only; `basic_auth_probe` inspects `Authorization` only.
  Previously all header values were scanned, causing false positives when non-auth
  headers contained scanner tool names or Base64 blobs.

- **Path matching case-normalized** — probe paths are lowercased before pattern
  matching; trailing slashes are stripped. Patterns that required exact case
  (`/PHPMYADMIN/`, `/WP-ADMIN/`) now fire correctly.

- **Header template placeholders rendered** — `mirror.fire_mirror()` previously
  left `{{...}}` placeholders unrendered in response headers, exposing a
  deception-layer fingerprint (e.g., `X-Request-Id: {{request_id}}`,
  `Location: {{honeypot_path}}`). Substitution now applies to both body and
  header values using the same rendered-vars dict, so scanner redirect targets
  are real paths and request-ID headers are real fake IDs.

- **Mirror responses default to `Server: nginx`** — mirrors without an explicit
  `Server` header previously inherited aiohttp's default
  (`Server: Python/3.X aiohttp/3.X.X`), disclosing the deception layer's
  runtime to any scanner that compared mirror responses with pass-through
  responses. Default is now `nginx`; mirrors with an explicit `Server` value
  (such as the shell-uploader 404 lookalike) keep their value unchanged.

- **Regex policy guard at pattern insertion** — pattern signatures are now
  validated against a 512-character length cap, Python's regex compiler, and
  a substring blacklist of known catastrophic-backtracking shapes
  (nested-quantifier, repeated-optional, and bounded-then-quantified
  families). Rejected patterns surface a clear `PatternPolicyError`; the
  signature itself is never echoed in logs or error messages. Closes the
  operator/mesh-supplied ReDoS vector at the insertion boundary. See
  *Known limitations* below for the v0.4.1 coverage envelope.

- **502-oracle eliminated** — when the upstream is unreachable (connection
  refused, timeout, DNS failure), the reverse-proxy layer now returns the
  default mirror response instead of bubbling a raw 502. Previously a
  misconfigured deployment let an attacker map the complete deception
  surface in one path scan: `502 = no deception handler, non-502 = handler
  exists`. Real upstream 4xx/5xx status codes are still passed through
  (those are real signals operators want to see); only connection-level
  failures collapse to the mirror.

- **DB integrity check at startup** — on POSIX systems, Net Ward now refuses
  to start if the storage path (or its parent directory, when the DB does
  not yet exist) is world-writable. The `--allow-permissive-db` flag
  overrides for unusual deployments where the operator accepts the risk.
  Windows logs an INFO-level skip message; ACL enforcement on Windows is
  out of scope for v0.4.1 and operator docs document the required
  permissions. Closes the local-pattern-injection vector in the storage
  layer.

- **Flood gate pass-through bypass** — the flood gate previously denied ALL
  traffic from a source once it tripped (30 hits/s, no decay), including
  paths that should reach the real upstream. This permanently locked out
  legitimate bursty clients (CI health checks, mobile-app refresh loops,
  NATed office IPs). Redesigned semantics: pattern matching always runs
  regardless of flood or reputation state; only requests that match a
  deception pattern receive a mirror response; non-matching requests reach
  the real upstream even from flagged sources. Closes the CRITICAL
  self-denial-of-service finding.

- **Flood gate threshold raised** — default threshold changed from 30 hits
  in 1 second to 1,000 hits in 10 seconds. The old threshold tripped on
  normal burst patterns; the new threshold requires sustained volume
  (100+ RPS for 10 seconds) before triggering.

- **Flood gate natural decay via sliding window** — the 10-second window
  automatically clears when traffic subsides. Sources that go quiet are
  unflagged within 10 seconds without any explicit timer.

- **Default mirror shape rotation** — the default mirror (used when upstream
  is unavailable or a pattern fires with no specific mirror installed)
  previously emitted a fixed `{"status":"ok",...}` JSON shape that was
  detectable under load as a fingerprint. Replaced with five variant shapes
  (JSON ok, JSON rate-limited 429, HTML 503, empty-result JSON, plain text)
  selected deterministically per `(source_id, path)` so a given source sees
  a consistent shape per path.

- **Probe count keyed on mirror-fired, not flood classification** — previously,
  any request classified as "flood" incremented `probe_count`, accelerating
  reputation escalation for legitimate bursty clients. Now only requests that
  actually fire a mirror response (matched a pattern) increment `probe_count`.

### Fixed

- `shell_uploader_probe`: `by\.php` alternation member corrected to `by`; the old
  regex matched `/by.php.php` and missed `/by.php`.

### Changed

- `scanner_ua_probe` adds `feroxbuster`, `ffuf`, `dirb`, `burpsuite`, `burp`,
  `metasploit`, and `zap` to the User-Agent alternation.
- `env_file_probe` signature expanded to catch `.envrc`, underscore-separated
  variants (`.env_local`, `.env_backup`), and nested paths beyond `app/` and `config/`.
- Storage schema migration 1: adds `header_name` column to the `patterns` table.

### Migration notes — v0.4.0 → v0.4.1

Bootstrap is idempotent: if vendor patterns already exist in your DB, the seeder
skips. This means upgrading from v0.4.0 does **not** auto-expire `basic_auth_probe`
if it was previously active. To opt out:

```bash
netward --db <path-to-netward.db> disable-pattern basic_auth_probe
```

To keep `basic_auth_probe` active (only safe when your upstream uses no Basic Auth):
no action needed — your existing enabled state is preserved.

If you upgrade and your storage path turns out to be world-writable, Net Ward
will refuse to start with a clear error message. Tighten the permissions with
`chmod 600 netward.db` (or equivalent) and restart, or pass `--allow-permissive-db`
if the permissive state is intentional for your environment.

### Known limitations

These are documented intentional gaps in v0.4.1's security coverage. v0.5
addresses each. Operators deploying Net Ward should understand them.

- **Regex policy guard is best-effort static analysis.** Substring-based
  shape detection at pattern insertion catches the most common ReDoS
  patterns (nested-quantifier and repeated-optional families) but cannot
  detect overlapping-alternation patterns like `(a|aa)+` or `(a|ab|abc)+`.
  There is no runtime ReDoS protection in v0.4.1; a pattern that bypasses
  the static guard can still cause catastrophic backtracking in production.
  Treat any untrusted regex source — operator-supplied custom patterns,
  third-party pattern bundles, future mesh-distributed patterns — as
  adversarial. v0.5 introduces a linear-time regex engine that closes both
  gaps by construction.

- **Reverse-proxy / NAT awareness deferred.** The flood gate keys on
  `request.remote`. If you deploy Net Ward behind a reverse proxy
  (nginx, Caddy, Cloudflare, ALB) without configuring `X-Forwarded-For`
  parsing manually, the flood gate sees the proxy IP for your entire user
  base and can escalate the proxy IP to a flagged source. v0.5 adds
  proxy awareness. For v0.4.1: do not deploy behind a reverse proxy
  without manual `X-Forwarded-For` handling, or accept the risk that
  shared egress IPs may be flagged.

- **Windows DB permission enforcement deferred.** The startup DB-permission
  check enforces on POSIX (`os.stat()` mode bits); on Windows it logs an
  informational skip message. Operators on Windows should ensure the
  `netward.db` path is in a directory not writable by other users. v0.5
  adds ACL-based enforcement for Windows.

- **Single-source flood-gate semantics.** Multi-source coordinated low-rate
  attacks (10 IPs each at 25 RPS) are not detected by the per-source flood
  gate. Aggregate detection is a v0.5 work item.

- **Runtime memory working set after sustained load.** Net Ward bounds its
  in-process flood windows and pattern caches, and current testing did not
  attribute sustained post-load memory growth to a confirmed Net Ward data
  leak. However, the Python runtime and native dependency stack may retain
  allocator arenas, connection-pool state, and other working-set memory
  after heavy traffic. This is normal for the Python ecosystem, but it can
  still matter on small hosts with tight memory budgets. Operators running
  continuous heavy traffic should monitor process RSS and restart the daemon
  periodically, such as weekly or when RSS exceeds 2x the post-start
  baseline. v0.5 will refine this recommendation with production telemetry
  and longer-duration soak data.

## [0.4.0] - 2026-04-30
### Added
- `pyproject.toml` enabling `pip install netward` from wheel or source
- `CHANGELOG.md` (this file) following Keep a Changelog convention
- `SECURITY.md` with vulnerability disclosure policy, supported versions,
  response SLA, and coordinated disclosure window
- `requirements.txt` annotated to document that `pynacl` is reserved for
  the v0.5 mesh layer and not exercised in v0.4

### Changed
- **BREAKING:** `netward.operator` renamed to `netward.operator_layer` to
  avoid shadowing Python's stdlib `operator` module. The shadow caused
  circular imports when builds or tools ran from inside the package
  directory. Update imports:
  `from netward.operator import X` → `from netward.operator_layer import X`

## [0.3.0] - 2026-04-30
### Added
- Apache 2.0 license and notice files.
- Docker image with multi-stage build, non-root runtime user, and config mount support at `/etc/netward/`.
- Operator README with quickstart, configuration, verification, and command reference.
- `example_config.json` with annotated operator fields.
- Buyer hygiene test gate for source cleanliness.
- `OperatorConfig.storage_path` field for configurable SQLite storage.

### Changed
- `mirror.user_agent_echo` now prefers the already-extracted `probe.request.user_agent` field.
- `random_int` mirror generator now caches parsed bounds.

### Fixed
- Pattern storage adapter now round-trips `expires_at`.
- Schema migrations now sort by target version before application.

## [0.2.0] - 2026-04-30
### Added
- Eleven-pattern vendor deception set that installs automatically on first run.
- `bootstrap.install_vendor_patterns`, with idempotent install behavior.
- Pattern management CLI commands: `install-patterns`, `list-patterns`, `disable-pattern`, and `enable-pattern`.
- Vendor pattern validation gate covering regex compilation, mirror cross-references, PII guard compatibility, hostile-marker checks, and false-positive sanity.

## [0.1.0] - 2026-04-30
### Added
- `capture` aiohttp reverse proxy with fail-open routing.
- `classify` path/header pattern matching, flood detection, and source reputation updates.
- `mirror` template substitution with XSS-safe user-agent echo and PII guard.
- `operator` config validation and alert deduplication.
- `storage` SQLite backend with schema migrations and idempotent CRUD operations.
- Seventy-nine tests across seven modules.

## [0.0.0] - 2026-04-30
### Added
- Schema contract using `TypedDict` definitions for source, pattern, probe, mirror response, mesh intel, trust, node, and operator entities.
- Module placeholders for capture, classify, mirror, operator, and mesh.
- Sixteen contract round-trip tests.
