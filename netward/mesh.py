"""
Net Ward — Mesh Layer (placeholder, not yet implemented)

Responsibility: cryptographically-signed propagation of MeshIntel between
nodes. Allows discovered patterns to spread across the operator network
so a probe pattern caught at one site pre-arms every other node.

OPERATING PRINCIPLE — sustained relay during sustained attack:

The first-hit node is NOT sacrificial. Every node maintains its mirror
layer at all times; whoever gets hit first is just whoever the attacker
happens to target first. They defend successfully because they've been
prepared all along — the entire mesh is already prepared.

What the first-hit node DOES contribute is REAL-TIME RELAY:

- First hit: publish `new_pattern` intel
- Subsequent hits on same pattern: publish `attack_sustained` intel
  to refresh confidence in mesh peers (signals "this is ongoing,
  not a one-time probe")
- Bot iterates a variant: publish `attack_mutation` intel with
  parent_pattern_id link, so peers see the evolution chain and
  pre-arm against further mutations

The relay is THROUGHOUT the attack, not one-shot. Receivers use the
sustained signal to:
- Keep Pattern confidence high while the attack is active
- Track mutation chains in case they're targeted with the next variant
- Refresh Source reputation on the attacker's IPs/ASNs

Public contract this module exposes:
    publish_intel(intel: MeshIntel, signing_key) -> None
        Sign the intel payload with this node's ed25519 private key,
        publish to mesh endpoint (hub-and-spoke OR gossip peers).

    receive_intel(raw_intel: dict, trust_manifest: TrustManifest) -> Optional[MeshIntel]
        Validate signature against trust manifest. Return verified intel
        OR None if signature fails / origin not trusted / TTL expired.

    apply_intel(intel: MeshIntel, ctx: ApplyContext) -> ApplyResult
        Once verified, install the intel into local state:
        - new_pattern: insert Pattern (origin=mesh, confidence per source)
        - pattern_confirmation: bump existing Pattern's confidence
        - attack_mutation: install new variant + link to parent
        - attack_sustained: refresh confidence on existing pattern
        - source_reputation: update local Source state
        - node_announcement: add to known peers
        - node_revocation: remove from peers, mark prior intel suspect
        - trust_manifest_update: replace local trust manifest

THE OPEN PROBLEM (security review pending before this module is implemented):

The mesh propagation channel cannot itself become an attack surface.

Concrete attacks the implementation must defend against:
1. Poisoned pattern injection — attacker compromises a trusted node and
   publishes a Pattern that matches LEGITIMATE traffic, causing every
   downstream node to deploy mirror responses to real users
2. Intel replay — attacker captures old intel, replays it after a
   pattern has been revoked, causing nodes to re-install obsolete rules
3. Gossip flood — malicious node publishes high-volume intel to exhaust
   peer resources (CPU/storage/bandwidth)
4. Trust manifest swap — attacker replaces operator's trust manifest
   with one favoring attacker-controlled nodes
5. Sybil node spawn — attacker spawns N fake nodes to vote up a
   poisoned pattern via "confirmation" intel kind

Mitigations encoded in schema (more needed in implementation):
- Every intel signed (signature field, ed25519)
- TTL prevents indefinite propagation (expires_at field, absolute epoch)
- propagation_count on intel — receivers can drop high-hop intel
- Trust manifest is versioned (replay detection)
- Trust manifest can chain to a central authority pubkey (operator opt-in)

Architecture choice still open:
A. Hub-and-spoke: a central mesh server, all nodes connect to it
   - Easier to audit, single trust authority, but central point of failure
B. P2P gossip: nodes know N peers, intel propagates pairwise
   - Resilient, no single failure, but harder to enforce trust uniformly
C. Federated hub: regional hubs that nodes connect to, hubs gossip
   - Hybrid; reasonable trust + reasonable resilience

Recommend a security review document is drafted BEFORE this module is
implemented. The schema doesn't lock the architecture choice.

DISTRIBUTED DECEPTION CONTINUATION (deferred to a later release):

Future feature where mirror responses across nodes JOINTLY maintain an
illusion. Example: A returns fake session token `ABC123`; A publishes
the token; bot tries `ABC123` against B; B recognizes the token and
responds as if the session is still valid; bot wastes more time
thinking they have a foothold across multiple sites.

Schema-wise this would add `MeshIntel.kind = "deception_continuation"`
plus `MirrorResponse.continuation_id`. Worth noting here so a future
security review can address it: joint illusion is a stronger deception
but a bigger attack surface if the mesh is compromised. This stays out of
the v0.4.1 standalone release.

For v0 schema, the existing MeshIntel kinds (new_pattern /
pattern_confirmation / attack_mutation / attack_sustained /
source_reputation / node_announcement / node_revocation /
trust_manifest_update) plus signed propagation cover the core relay.
"""
