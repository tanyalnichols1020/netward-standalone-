"""
Net Ward — Schema v0
The contract that capture / classify / mirror / mesh / operator lanes
build against. Provider-agnostic — Anthropic Claude, OpenAI Codex, and
any future implementer can read this and ship.

All entities are TypedDicts (JSON-serializable, no required runtime
class binding). Fields use frozenset/list/dict primitives so storage
backends (sqlite, redis, postgres, in-memory) can persist them with
minimal adapter code.

Schema philosophy:
- Each entity has a stable `id` field (uuid4 string) for cross-node
  reference even when payloads diverge
- Timestamps are unix epoch seconds (float) — no timezone ambiguity
- All "kind" / "category" / "severity" fields use Literal types so
  enums are self-documenting and type-checkable
- No required runtime dependencies beyond stdlib (TypedDict + Literal
  from typing); buyer-distributable as pure-python module
"""
from __future__ import annotations

from typing import Literal, Optional, TypedDict


SCHEMA_VERSION = 1  # base standalone schema version


# =============================================================================
# Source — origin of an inbound request (IP + ASN + geo + reputation)
# =============================================================================

# Reputation tracks our local + mesh-derived assessment. Starts neutral.
# Promotes to suspicious on N probe hits, known_bad after mesh confirmation.
SourceReputation = Literal["clean", "neutral", "suspicious", "known_bad"]


class Source(TypedDict, total=False):
    """An origin endpoint that has sent us at least one request.

    Per-source state is kept in storage and updated on every probe match.
    Operators see Source-level alerts ("ASN 13335 firing 200 probes/min")
    rather than per-probe spam."""

    id: str                              # uuid4
    ip_address: str                      # canonical (IPv4 or IPv6) string
    asn: Optional[int]                   # BGP autonomous system number
    asn_name: Optional[str]              # human-readable ("CloudflareNet")
    geo_country: Optional[str]           # ISO-3166-1 alpha-2
    geo_region: Optional[str]            # state/province where resolvable
    reputation: SourceReputation
    first_seen: float                    # unix epoch
    last_seen: float
    probe_count: int                     # cumulative inbound probes matched
    legit_count: int                     # cumulative requests passed through
    notes: list[str]                     # operator annotations


# =============================================================================
# Pattern — a signature describing a probe family
# =============================================================================

# Pattern kind tells the matcher which fields to evaluate.
# Multiple patterns can match the same probe — first-match-wins by score.
PatternKind = Literal[
    "path",          # request path matches (e.g., /wp-admin, /.env)
    "header",        # specific header matches (User-Agent, Referer)
    "body",          # request body content matches (POST data, JSON keys)
    "timing",        # request frequency / cadence pattern (flood signature)
    "method",        # HTTP method anomaly (TRACE, CONNECT to non-proxy)
    "tls_fingerprint",  # JA3/JA4-style fingerprint
    "asn_burst",     # many requests from single ASN in time window
    "composite",     # AND/OR combination of other patterns (deferred to v1)
]

# Severity drives mirror response intensity AND operator alert tier.
# info: noise, log only. warn: real probe, mirror standard. critical:
# coordinated attack, mirror full + alert operator.
PatternSeverity = Literal["info", "warn", "critical"]

# Origin tracks where this pattern came from for trust / audit purposes.
PatternOrigin = Literal[
    "local",         # discovered by this node's classifier
    "mesh",          # received from another node via signed mesh intel
    "operator",      # operator manually added (highest trust)
    "vendor",        # ships with default pattern set from Net Ward maintainers
]


class Pattern(TypedDict, total=False):
    """A signature matching a probe family. Patterns are the unit of
    sharing across the mesh — when one node confirms a new probe family,
    its Pattern can propagate to other nodes (signed).

    Mutation tracking: when bots iterate variants seeking a vulnerability,
    each new variant becomes a Pattern linked to its parent via
    `parent_pattern_id`. This lets receivers see the evolution chain
    ("attack started as X, mutated to X', then X''") and stay one step
    ahead. The first-hit node continues relaying mutations as the attack
    progresses; relay is sustained, not one-shot."""

    id: str
    kind: PatternKind
    signature: str                       # regex or exact string for matcher
    description: str                     # human-readable ("Wordpress admin probe")
    severity: PatternSeverity
    origin: PatternOrigin
    origin_node_id: Optional[str]        # which node first published (mesh)
    created_at: float
    last_matched: Optional[float]
    match_count: int                     # local hits since pattern installed
    mirror_response_id: Optional[str]    # default response to use
    confidence: float                    # 0.0-1.0; raised by mesh confirmations
    parent_pattern_id: Optional[str]     # if this is a variant/mutation of an
                                          # earlier pattern, link to parent
    mutation_generation: int             # 0 = original; bumps each variant
                                          # (receivers prioritize fresher
                                          # mutations during sustained attacks)
    expires_at: Optional[float]          # unix epoch; mesh-derived patterns
                                          # default to created_at + INTEL_DEFAULT_TTL_SECS,
                                          # operator/vendor patterns leave None
    header_name: Optional[str]           # for header-kind patterns: restrict match to this
                                          # specific header (e.g. "User-Agent", "Authorization").
                                          # When absent, all header values are scanned (legacy).


# =============================================================================
# Probe — an inbound request matched against a pattern
# =============================================================================

# Classification of any inbound request after capture + classify pass.
# probe: matched a pattern. flood: rate-limited burst from one source.
# legit: passed through to upstream service (logged for baseline).
# unknown: no pattern matched, not flood — held briefly for inspection.
ProbeClassification = Literal["probe", "flood", "legit", "unknown"]


class RequestMetadata(TypedDict, total=False):
    """Captured fields from the inbound HTTP/network request.
    Schema is permissive — capture lane can populate what's available
    given operator's deployment topology (some won't have TLS fingerprints,
    etc.)."""

    method: str                          # HTTP verb
    path: str
    headers: dict[str, str]              # key-value (not raw)
    query_string: Optional[str]
    body_snippet: Optional[str]          # first ~4KB of body, never full
    body_size: Optional[int]
    tls_fingerprint: Optional[str]       # JA3/JA4 hash
    user_agent: Optional[str]            # convenience extract


class Probe(TypedDict, total=False):
    """A single inbound request that the classifier flagged.
    Probes are the audit trail — every one matched gets logged with
    enough context to reconstruct the attack pattern."""

    id: str
    timestamp: float
    source_id: str                       # FK -> Source
    pattern_id: Optional[str]            # FK -> Pattern (None for unknown/flood)
    classification: ProbeClassification
    request: RequestMetadata
    response_id: Optional[str]           # FK -> MirrorResponse (what we sent back)
    mirror_fired: bool                   # True if we returned a mirror response
    upstream_passed: bool                # True if request was let through


# =============================================================================
# MirrorResponse — the plausible-fake response returned to a probe
# =============================================================================

# Response intent: how convincing should the deception be?
# minimal: 200 OK + small body. moderate: realistic-looking error.
# elaborate: convincing site-not-found / login-form / honeypot redirect.
MirrorIntensity = Literal["minimal", "moderate", "elaborate"]


class MirrorResponse(TypedDict, total=False):
    """A canned response the mirror lane returns when a Probe matches a
    Pattern. Templates support variable substitution (random tokens, fake
    timestamps, plausible IDs) so two probes don't see identical responses
    — that breaks the deception fast."""

    id: str
    matches_pattern_id: str              # FK -> Pattern
    intensity: MirrorIntensity
    http_status: int                     # e.g., 200 (looks succeeded)
    headers: dict[str, str]              # response headers (Content-Type, etc.)
    body_template: str                   # may contain {{var}} substitutions
    body_template_vars: dict[str, str]   # variable -> generator kind
                                         # ("uuid", "timestamp", "fake_id", etc.)
    description: str                     # human note ("WordPress fake admin login")
    created_at: float


# =============================================================================
# Node — a deployed Net Ward instance
# =============================================================================

# What this node can do in the mesh.
NodeMeshCapability = Literal[
    "subscribe",     # receives intel from mesh
    "publish",       # publishes intel to mesh
    "verify",        # validates signed intel from other nodes
    "relay",         # forwards intel between nodes (gossip)
]


class NodeIdentity(TypedDict, total=False):
    """Public identity advertised to the mesh. Public key allows other
    nodes to verify intel signed by this node. Private key never leaves
    the node — stored locally, used for signing outbound intel only."""

    node_id: str                         # uuid4, stable across restarts
    operator_id: str                     # whose node is this
    hostname: str                        # for operator UI / logs
    region: Optional[str]                # geographic deployment region
    public_key: str                      # base64-encoded ed25519 pubkey
    version: str                         # Net Ward software version
    capabilities: list[NodeMeshCapability]


class NodeStatus(TypedDict, total=False):
    """Live operational state — heartbeat, counters, mesh connectivity.
    Refreshed every N seconds, persisted for last-known-good queries."""

    node_id: str
    last_heartbeat: float
    probes_processed_total: int
    probes_processed_window: int         # last 5 min
    mirror_responses_fired: int
    mesh_intel_received: int
    mesh_intel_published: int
    upstream_health: Literal["ok", "degraded", "down", "unknown"]
    storage_health: Literal["ok", "degraded", "down"]


# =============================================================================
# MeshIntel — signed payload shared across nodes
# =============================================================================

# What kind of intel is being propagated.
MeshIntelKind = Literal[
    "new_pattern",           # node discovered a new probe family
    "pattern_confirmation",  # node confirms a pattern from another node
    "attack_mutation",       # node observed a mutation/variant of an existing
                             # pattern — payload links parent + new variant.
                             # The "stay one step ahead" signal: bots iterating
                             # variants get tracked and the chain propagates
    "attack_sustained",      # same pattern keeps firing — refresh confidence
                             # in receivers; signals the attack is ongoing
                             # not a one-time probe
    "source_reputation",     # node asserts a Source's reputation level
    "node_announcement",     # node joining the mesh advertises identity
    "node_revocation",       # node explicitly leaving / key rotation
    "trust_manifest_update", # central distribution updates trust list
]


class MeshIntel(TypedDict, total=False):
    """A signed payload published to or received from the mesh.

    Open security problem: the propagation channel between nodes cannot
    itself become an attack surface. A poisoned mesh injects false attack
    patterns and turns every node into an attacker on legitimate traffic.

    Mitigations encoded in schema:
    - Every intel signed (signature field, ed25519 over canonical payload)
    - Receivers validate signature against trust_manifest before applying
    - TTL prevents infinite propagation
    - Origin node_id auditable; receivers can revoke trust on bad source
    """

    id: str                              # uuid4
    kind: MeshIntelKind
    origin_node_id: str                  # who first published
    payload: dict                        # kind-specific contents
    signature: str                       # ed25519 sig over canonical payload
    published_at: float
    expires_at: float                    # absolute epoch, not TTL delta
    propagation_count: int               # how many hops it's traveled
    received_at: Optional[float]         # local timestamp on receipt
    verified: bool                       # signature checked AND origin trusted


# =============================================================================
# Trust manifest — the operator's local list of trusted nodes
# =============================================================================

class TrustedNode(TypedDict, total=False):
    """A node this operator's Net Ward instance accepts intel from.
    Updated via trust_manifest_update intel from a central distribution
    OR manually by the operator."""

    node_id: str
    public_key: str
    operator_label: Optional[str]        # e.g. "my-hub", "coalition-node-3"
    trust_level: Literal["full", "verify_only", "muted"]
    added_at: float


class TrustManifest(TypedDict):
    """Operator's complete trust list. Versioned so updates can be
    cryptographically chained (replaying old manifest is detectable)."""

    version: int
    updated_at: float
    nodes: list[TrustedNode]
    central_authority_pubkey: Optional[str]  # if using central distribution


# =============================================================================
# Operator-facing types — alerts, config, dashboard
# =============================================================================

OperatorAlertSeverity = Literal["info", "warn", "critical"]
OperatorAlertChannel = Literal["email", "slack", "webhook", "ntfy", "sms"]


class OperatorAlert(TypedDict, total=False):
    """A notification surfaced to the human running the node.
    Dedup by (kind, source_id) within a window so a flood doesn't
    spam the operator's inbox."""

    id: str
    severity: OperatorAlertSeverity
    kind: str                            # "new_pattern" / "flood_active" / etc.
    title: str                           # short headline
    body: str                            # detail message, may be markdown
    source_id: Optional[str]             # FK -> Source if applicable
    pattern_id: Optional[str]            # FK -> Pattern if applicable
    triggered_at: float
    delivered_to: list[OperatorAlertChannel]
    acknowledged: bool
    acknowledged_at: Optional[float]


class OperatorConfig(TypedDict, total=False):
    """Per-node configuration. Operator-editable file, validated at
    startup. Net Ward never modifies this file at runtime — operator
    changes require deliberate config updates."""

    node_id: str                         # immutable once assigned
    upstream_target: str                 # URL of service we're protecting
    listen_address: str                  # where Net Ward accepts traffic
    storage_path: Optional[str]          # sqlite db path; defaults to "netward.db"
                                          # in the current working directory if omitted
    mirror_intensity_default: MirrorIntensity
    mesh_enabled: bool
    mesh_endpoint: Optional[str]         # mesh server (if hub-and-spoke)
    trust_manifest_url: Optional[str]    # auto-update source for trust list
    alert_channels: list[OperatorAlertChannel]
    alert_email: Optional[str]
    alert_slack_webhook: Optional[str]
    alert_ntfy_topic: Optional[str]


# =============================================================================
# Constants — defaults / thresholds shared across modules
# =============================================================================

# Pattern confidence thresholds for promoting local → published intel.
# Local discovery starts at 0.5, requires N hits to publish to mesh.
CONFIDENCE_PUBLISH_THRESHOLD = 0.7
CONFIDENCE_INSTALL_THRESHOLD = 0.6

# Intel TTL — how long a propagated pattern stays valid before re-confirm.
INTEL_DEFAULT_TTL_SECS = 86400 * 7        # 7 days

# Source reputation transitions — how many probes flip a Source from
# neutral → suspicious → known_bad.
PROBES_TO_SUSPICIOUS = 5
PROBES_TO_KNOWN_BAD = 25

# Operator alert dedup window — same (kind, source_id) within this gets
# rolled up into one alert with count.
ALERT_DEDUP_WINDOW_SECS = 300              # 5 min

# Heartbeat / mesh gossip interval — node publishes status this often.
HEARTBEAT_INTERVAL_SECS = 60
