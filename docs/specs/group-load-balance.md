# Spec: Load-balance proxy group (M1.C-1)

Status: Approved (architect 2026-04-11, engineer ready)
Owner: pm
Tracks roadmap item: **M1.C-1**
Depends on: none — load-balance composes existing `ProxyAdapter`
implementations via the same `Vec<Arc<dyn Proxy>>` pattern used by
URLTest/Fallback/Selector.
Related gap-analysis row: §proxy-groups "load-balance — enum variant
exists, no group impl".

> **Implementation status (2026-09, issue #485):** load-balance groups now join
> the same periodic health-check sweep as `url-test`/`fallback`.
> `meow_config::extract_health_check_specs` emits a `HealthCheckSpec` for a
> `load-balance` group, so its members are probed against `url` every
> `interval` seconds (default 300, `0` disables); `lazy: true` defers probing
> until the group next carries traffic. The `url`, `interval`, and `lazy`
> fields are therefore effective. `use:` / `include-all` provider members are
> supported (issue #533 item 3): they join the same pick space as static
> `proxies:` members — statics first, then each provider slot in order — and
> a provider refresh is visible to the next selection without rebuilding the
> group. Note on liveness: the periodic sweep resolves member **names**
> through the route map, so provider members are never probed by it — their
> `alive()` changes via provider refresh, the on-demand
> `/providers/proxies/{name}/healthcheck` endpoint, or the group's
> dial-failure escalation (repeated member dial errors mark the member dead,
> same as url-test/fallback). Escalation is one-way for provider members:
> nothing scheduled revives them, so a marked-dead provider member stays out
> of the pick space until its provider refreshes or is manually probed.

## Motivation

`type: load-balance` is the fourth proxy group type after Selector,
URLTest, and Fallback. Upstream Go mihomo supports two strategies:
round-robin (default) and consistent-hashing (sticky by source IP).
Real subscriptions use load-balance to distribute traffic across a
set of identically-capable peers (e.g. three SS nodes on the same
VPS network). Without it, users with load-balance groups in their
config get a parse error and no fallback, breaking the M1 "typical
subscription loads" goal.

The implementation is smaller than URLTest — it reuses the same
periodic health-check infrastructure but replaces the "fastest-wins"
selection with a counter or a hash. Estimate ~200 LOC total.

## Scope

In scope:

1. `LoadBalanceGroup` struct in `crates/meow-proxy/src/group/load_balance.rs`
   implementing `ProxyAdapter`.
2. Strategy `round-robin` (default): AtomicUsize counter, mod alive-
   proxy count. Per-request, not per-connection (so long-lived
   connections are assigned once at dial time).
3. Strategy `consistent-hashing`: FNV-1a hash of the source IP from
   `Metadata.src_addr`, mod alive-proxy count. Sticky by client IP
   for the lifetime of the provider's proxy list.
4. Periodic health-check using the same `url` + `interval` probe
   mechanism as URLTest. Unhealthy proxies are skipped by both
   strategies.
5. YAML config parser in `meow-config` for the
   `proxies: [{ type: load-balance }]` group variant.
6. `AdapterType::LoadBalance` variant added to
   `crates/meow-common/src/adapter_type.rs`.
7. Integration with `ProxyHealth` and the api-delay-endpoints probe
   path.

Out of scope:

- **`smart` strategy** — upstream has a "smart" strategy that mixes
  latency-awareness with spreading; niche, underdocumented, defer.
- **`strategy: bandwidth-aware`** — not in upstream's mainline.
- **Weighted load-balance** — upstream does not have weights; neither
  do we.
- **Least-connections** — would require connection-count tracking on
  each proxy; not in upstream, not in scope.

## User-facing config

```yaml
proxy-groups:
  - name: lb-group
    type: load-balance
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c
    url: https://www.gstatic.com/generate_204
    interval: 300          # health-check sweep interval in seconds
    strategy: round-robin  # round-robin (default) | consistent-hashing
    lazy: false            # defer the sweep until the group carries traffic
```

Field reference:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `proxies` | `[]string` | no* | — | Named proxies or groups to balance across. Same resolution as Selector for static names; `use:` / `include-all` provider members balance alongside them (statics first in rotation order). *Required only when neither `use:` nor `include-all` supplies members. |
| `url` | string | no | `https://www.gstatic.com/generate_204` | Health-check probe URL. Members are probed against it by the periodic sweep. |
| `interval` | integer | no | `300` | Health-check sweep interval in seconds. Each member is probed every `interval` seconds; a member whose probe fails is skipped by both strategies until it recovers. `0` disables the periodic sweep (upstream `HealthCheck.auto()`). |
| `strategy` | enum | no | `round-robin` | Selection strategy. |
| `lazy` | bool | no | `false` | When `true`, the periodic sweep is deferred until the group next carries traffic (same as `url-test`/`fallback`). Upstream defaults to `true`; see divergence 5. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Unknown `strategy` value — upstream falls back to round-robin | A | Unknown strategy means the user may get different distribution behaviour than intended. Hard-error at parse time. |
| 2 | `strategy: consistent-hashing` with no alive proxies — upstream panics (index out of bounds) | A | We return `MeowError::NoProxyAvailable` and surface it as a clean dial error. NOT a panic. |
| 3 | All proxies dead — upstream returns the round-robin slot (dead proxy) | B | We return `NoProxyAvailable` error immediately instead of dialing a known-dead proxy. Same reachability outcome (connection fails), but our failure is fast and named. |
| 4 | `strategy: consistent-hashing` uses modulo-hash, not ring-hash | B | Despite the name, upstream Go mihomo's implementation (`adapter/outbound/loadbalance.go`) uses the same `hash % alive.len()` modulo approach, not a ring. Rebalancing a proxy list reshuffles most assignments — users expecting minimal-disruption ring-consistent-hash should be aware. We match upstream; the label "consistent-hashing" means "stable for a given src IP given a fixed proxy list", not ring-consistent. |
| 5 | `lazy` defaults to `false` — upstream defaults to `true` (`GroupCommonOption{Lazy: true}`, `adapter/outboundgroup/parser.go`) | B | Pre-existing default shared with `url-test`/`fallback`; an unset `lazy` probes eagerly instead of only while the group carries traffic. Subscription-compatible either way; only background probe volume differs. Tracked in #555. |
| 6 | `expected-status:` on load-balance parses but is ignored — upstream honors it (`HealthCheckOption`) | B | `LoadBalanceGroup` does not store `expected_status`/`test_url` (unlike url-test/fallback's `with_runtime_options`), so the sweep probes with the default 2xx acceptance set. Pre-existing gap, amplified now that provider members balance here. Tracked in #555. |
| 7 | Duplicate `use:` entries are deduped — upstream appends per entry, so `use: [A, A]` double-weights provider A | B | A duplicated provider name can only ever produce an identical member view (group `filter:`/`exclude-*` are group scalars), so double-wiring it is always a weighting accident, never intent. Static `proxies:` duplicates still double-weight, matching upstream. |
| 8 | `include-all` pulls providers only; upstream's `include-all` also pulls statics (`include-all-providers` is the providers-only alias upstream) | B | Pre-existing shared group semantics — `include-all-proxies` already covers the all-statics case, so `include-all` here equals upstream's `include-all-providers`. Combined with `use:`, `include-all` wins and `use:` is ignored — same as upstream. |
| 9 | `use:` on a `relay` group warns and is ignored — upstream relay ignores it silently | B | A relay is a fixed static chain; provider members have no place in it. |

## Internal design

### Struct

```rust
// crates/meow-proxy/src/group/load_balance.rs

pub enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
}

pub struct LoadBalanceGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,  // live `use:`/`include-all` members
    strategy: LbStrategy,
    counter: AtomicUsize,   // only used for round-robin
    health: ProxyHealth,
    usage: UsageTracker,
    dial_failures: DialFailureTracker,  // onDialFailed escalation
}
```

`AtomicUsize` (not `RwLock<usize>`) for the round-robin counter —
load-balance's selection is a hot path and the counter needs only
relaxed-ordering increments, no lock. `fetch_add(1, Relaxed)` mod
alive-count is correct: occasional races on the modulo produce
non-optimal but not incorrect distribution (two consecutive
connections to the same proxy), which is acceptable for a
load-balancer where exact fairness is not guaranteed anyway.

### Selection logic

```rust
impl LoadBalanceGroup {
    // Two passes over statics + provider-slot members: count the eligible
    // set, take the strategy index, clone the nth eligible member. No Vec
    // is materialized on the dial path even with providers attached.
    fn pick(&self, metadata: &Metadata, udp_only: bool) -> Option<Arc<dyn Proxy>> {
        // Pass 1: count members where `alive() && (!udp_only || support_udp())`.
        let alive_count = ...;
        if alive_count == 0 {
            return None;
        }
        let idx = match self.strategy {
            LbStrategy::RoundRobin => {
                self.counter.fetch_add(1, Ordering::Relaxed) % alive_count
            }
            LbStrategy::ConsistentHashing => {
                let (bytes, len) = src_ip_bytes(metadata); // -> ([u8; 16], usize)
                (fnv1a(&bytes[..len]) as usize) % alive_count
            }
        };
        // Pass 2: clone the nth eligible member of the same walk.
        ...
    }

    fn src_ip_bytes(metadata: &Metadata) -> ([u8; 16], usize) {
        // Extract the raw bytes of src_addr's IP.
        // IPv4: 4 bytes. IPv6: 16 bytes. Both are valid hash inputs.
        // If src_addr is absent (local loopback test / API probe), hash 0.0.0.0
        // (4 zero bytes). Every connection without a src_addr hashes to the same
        // proxy — deterministic, not random, not an error.
    }
}
```

**FNV-1a for consistent hashing** — upstream Go mihomo uses
`fnv.New32()` (FNV-1 32-bit). We use FNV-1a 32-bit, which is
slightly better distributed and the same speed; we match the Go
implementation's input (raw IP bytes, not the `host:port` string).
The difference in hash function is an acceptable minor divergence —
consistent-hashing result is guaranteed to be *stable* for a given
src IP, not *identical* to Go mihomo's result on the same input.
This is Class B: routing is correct and sticky, just not bit-for-bit
identical to the Go output.

**No dependency on a crate for FNV** — 8 lines of inline math. Do
not add `fnv` crate for a 1-function use. Implement inline with a
comment `// FNV-1a 32-bit, matching upstream adapter/outbound/loadbalance.go::jumpHash logic shape`.

**Alive-set walk, no allocation** — `select()` walks statics then provider
slot contents twice (count, then nth) instead of materializing a `Vec`,
keeping the dial path allocation-free whether or not providers are
attached (same shape as url-test's `pick_for_dial`). A member dying
between the two passes can shift the pick or yield `None` for one dial —
benign and self-correcting.

### Health-check integration

`LoadBalanceGroup` participates in the same periodic health-check sweep as
`url-test`/`fallback`, driven by the `HealthCheckSupervisor` in
`crates/meow-tunnel/src/health_check.rs`:

- `meow_config::extract_health_check_specs` reads the raw group config and
  emits a `HealthCheckSpec` (`group_name`, `url`, `interval_secs`, `lazy`)
  for every `load-balance` group, using the shared defaults (`url` →
  `https://www.gstatic.com/generate_204`, `interval` → 300 s, `lazy` →
  false); `interval: 0` emits no spec. The supervisor reconciles the spec
  set on every config commit, so groups added or removed at runtime are
  picked up.
- The per-group task ticks every `interval` seconds. Each tick resolves the
  group's `members()` **names** through the route proxy map to their
  `Arc<dyn Proxy>` and probes them via
  `meow_proxy::health::probe_many_bounded(members, &spec.url, …)`, which
  records each result into that member's shared `ProxyHealth`
  (`record_delay`; `alive = delay > 0`). Provider-sourced members are not
  registered in the route map, so the sweep skips them — their liveness
  comes from the group's dial-failure escalation and provider refreshes
  (see the status note above).
- `select()` reads `p.alive()` on each member — no extra locking; the sweep
  and the group hold the same `Arc<dyn Proxy>`, so a recorded probe result is
  immediately visible to selection.
- `lazy: true` gates probing on `usage_generation()`: `LoadBalanceGroup` bumps
  a `UsageTracker` on every user dial (`dial_tcp` / `dial_udp` /
  `unwrap_proxy`), and the loop skips ticks until the generation advances, so
  an idle lazy group is not probed.

### `dial_tcp` / `dial_udp`

```rust
#[async_trait]
impl ProxyAdapter for LoadBalanceGroup {
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self.select(metadata)
            .ok_or(MeowError::NoProxyAvailable)?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // `pick(metadata, udp_only = true)` — same two-pass member walk with
        // the eligibility predicate narrowed to `alive() && support_udp()`.
        // ... same hash/counter logic as dial_tcp
    }

    fn support_udp(&self) -> bool {
        // true if any static or provider-slot member supports UDP
        self.any_member(|p| p.support_udp())
    }
}
```

Note: `support_udp()` returns true if *any* proxy supports UDP,
matching upstream's group-level behaviour. The actual UDP dial
filters to UDP-capable alive proxies and applies the strategy over
that subset.

## Acceptance criteria

1. Round-robin distributes across alive proxies in strict rotation
   order (modulo wrapping). Unit test: 10 dials, 3 alive proxies →
   sequence [0,1,2,0,1,2,...].
2. Consistent-hashing returns the same proxy for the same src IP,
   regardless of call order. Unit test: same `Metadata.src_addr`
   → always proxy B across 100 calls.
3. Consistent-hashing produces different assignment for two distinct
   src IPs (probabilistic — use well-separated IPs like `1.1.1.1`
   and `8.8.8.8`).
4. Both strategies skip dead proxies. Unit test: mark proxy-B dead,
   assert round-robin never selects it.
5. All proxies dead → `NoProxyAvailable` error, not a panic or a
   dial attempt to a dead proxy. Class A per ADR-0002.
6. Unknown `strategy` value → hard parse error at config load.
   Class A per ADR-0002.
7. Health-check sweep fires after `interval` seconds; `alive()` state
   updates; subsequent selections reflect the new health state.
8. `ProxyHealth` on the group itself integrates with the api-delay-
   endpoints probe path.
9. `AdapterType::LoadBalance` is present in the enum and serialises
   to `"LoadBalance"` in JSON (for REST API `/proxies` response).
10. Consistent-hashing with absent `src_addr` deterministically selects
    one proxy (not random, not `NoProxyAvailable`) — hashes to 0.0.0.0.
11. Round-robin does not panic or return a stale index when the alive-set
    shrinks between calls (proxy flap scenario).

## Test plan (starting point — qa owns final shape)

**Unit (`group/load_balance.rs`):**

- `round_robin_cycles_through_alive_proxies` — three alive proxies,
  10 consecutive `select()` calls, assert [0,1,2,0,1,2,0,1,2,0].
  Upstream: `adapter/outbound/loadbalance.go::RoundRobin.Addr`.
  NOT random; NOT skipping index on wrap — strictly sequential.
- `round_robin_skips_dead_proxy` — mark proxy-1 dead, assert only
  proxy-0 and proxy-2 appear in rotation.
- `consistent_hashing_stable_for_same_src` — same src IP, 100
  calls, assert same proxy every time.
  Upstream: `adapter/outbound/loadbalance.go::ConsistentHashing.Addr`.
  NOT volatile — consistent-hash must be deterministic.
- `consistent_hashing_differs_for_different_src` — two well-separated
  IPs hash to different proxies (assert with known-good fixture IPs).
- `consistent_hashing_skips_dead_proxy` — mark one proxy dead; assert
  the remaining alive proxies absorb the load deterministically.
- `all_proxies_dead_returns_no_proxy_available` — all dead, assert
  `Err(NoProxyAvailable)`. Class A per ADR-0002 (NOT panic, NOT
  dial-dead-proxy as upstream does).
  Upstream: Go code panics with index out of bounds in the consistent-
  hash path; we return a clean error.
- `consistent_hashing_absent_src_addr_deterministic` — `src_addr: None`,
  assert same proxy selected across 10 calls (hashes to 0.0.0.0 fallback).
  NOT random. NOT error. Upstream: undefined (assumes src always present).
- `round_robin_handles_alive_set_flap` — 3 alive proxies; call select()
  once; mark proxy-1 dead; call select() again; assert no panic and
  returned index is valid (0 or 2). NOT stale index, NOT out-of-bounds.
  Guards against future refactor that would make modulo unsafe on
  shrinking alive-set.

**Unit (config parser):**

- `parse_load_balance_default_strategy` — no `strategy:` field →
  round-robin selected.
- `parse_load_balance_explicit_round_robin` — `strategy: round-robin`.
- `parse_load_balance_consistent_hashing` — `strategy: consistent-hashing`.
- `parse_load_balance_unknown_strategy_hard_errors` — `strategy: sticky`
  → parse error. Class A per ADR-0002: NOT silent fallback to round-robin.
  Upstream: falls back silently.

**Integration:**

- `load_balance_round_robin_distributes_connections` — real
  URLTest-style probe with a local echo server on three ports, assert
  connections spread across all three ports over 9 dials.

## Implementation checklist (for engineer handoff)

- [ ] Add `AdapterType::LoadBalance` to `meow-common/src/adapter_type.rs`.
- [ ] Implement `group/load_balance.rs` with both strategies. Inline
      FNV-1a 32-bit (no crate dep). Comment cites upstream file.
- [ ] Wire `parse_proxy_group` in `meow-config` to recognise
      `type: load-balance` and produce a `LoadBalanceGroup`.
- [ ] Spawn health-check sweep task in `main.rs` for each
      load-balance group with `interval > 0`.
- [ ] Update `docs/roadmap.md` M1.C-1 row with merged PR link.
