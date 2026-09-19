use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::{DialFailureTracker, UsageTracker};

#[derive(Debug)]
pub enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
}

pub struct LoadBalanceGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    /// Provider-sourced members (`use:` / `include-all`), each a live
    /// slot whose contents the owning provider swaps on refresh — the
    /// same `ProviderSlot` shape url-test/fallback/selector carry.
    /// Invariant: slots only ever hold leaf adapters (provider payloads
    /// cannot declare groups), so member walks never recurse into another
    /// group's slot guards.
    provider_slots: Vec<ProviderSlot>,
    strategy: LbStrategy,
    counter: AtomicUsize,
    health: ProxyHealth,
    usage: UsageTracker,
    /// mihomo `GroupBase.onDialFailed` escalation: repeated member dial
    /// failures mark the member dead between sweeps — the only liveness
    /// signal provider members get, since the sweep resolves group members
    /// by name through the route map (provider names are not registered).
    dial_failures: DialFailureTracker,
}

impl LoadBalanceGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, strategy: LbStrategy) -> Self {
        Self::new_with_providers(name, proxies, strategy, Vec::new())
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        strategy: LbStrategy,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            strategy,
            counter: AtomicUsize::new(0),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
        }
    }

    /// Visit every member in canonical order — static `proxies:` entries
    /// first, then each provider slot under its read guard (the same order
    /// url-test/selector enumerate). `f` returning `false` stops the walk.
    fn for_each_member(&self, mut f: impl FnMut(&Arc<dyn Proxy>) -> bool) {
        for p in &self.static_proxies {
            if !f(p) {
                return;
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if !f(p) {
                    return;
                }
            }
        }
    }

    fn any_member(&self, mut pred: impl FnMut(&Arc<dyn Proxy>) -> bool) -> bool {
        let mut hit = false;
        self.for_each_member(|p| {
            hit = pred(p);
            !hit
        });
        hit
    }

    /// First alive member in canonical order (for `current()`/`delay_history`).
    fn first_alive_member(&self) -> Option<Arc<dyn Proxy>> {
        let mut out = None;
        self.for_each_member(|p| {
            if p.alive() {
                out = Some(Arc::clone(p));
                false
            } else {
                true
            }
        });
        out
    }

    /// Smallest positive delay across alive members (0 = none measured).
    fn min_alive_delay(&self, mut delay: impl FnMut(&Arc<dyn Proxy>) -> u16) -> u16 {
        let mut best = 0u16;
        self.for_each_member(|p| {
            if p.alive() {
                let d = delay(p);
                if d > 0 && (best == 0 || d < best) {
                    best = d;
                }
            }
            true
        });
        best
    }

    /// Strategy-specific index into a set of `alive_count` members.
    /// Callers must ensure `alive_count > 0`.
    fn pick_index(&self, alive_count: usize, metadata: &Metadata) -> usize {
        debug_assert!(alive_count > 0, "modulo over an empty pick space");
        match self.strategy {
            LbStrategy::RoundRobin => self.counter.fetch_add(1, Ordering::Relaxed) % alive_count,
            LbStrategy::ConsistentHashing => {
                let (bytes, len) = src_ip_bytes(metadata);
                (fnv1a(&bytes[..len]) as usize) % alive_count
            }
        }
    }

    /// Select a proxy from the alive set for a TCP connection.
    ///
    /// Returns `None` if no alive proxy exists.
    ///
    /// TODO(perf M2): cache alive-set or use a pre-filtered index if profiling shows this hot
    pub fn select(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.pick(metadata, false)
    }

    fn select_udp(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.pick(metadata, true)
    }

    /// Two passes over the member set — count eligible members, pick an index,
    /// then clone the nth eligible member. No materialized Vec even with
    /// provider slots (the same walk url-test's `pick_for_dial` does). A
    /// member dying between the passes can shift the pick or yield `None`
    /// for this one dial — benign, self-correcting on the next call.
    fn pick(&self, metadata: &Metadata, udp_only: bool) -> Option<Arc<dyn Proxy>> {
        let eligible = |p: &Arc<dyn Proxy>| p.alive() && (!udp_only || p.support_udp());
        let mut alive_count = 0usize;
        self.for_each_member(|p| {
            alive_count += usize::from(eligible(p));
            true
        });
        if alive_count == 0 {
            return None;
        }
        let idx = self.pick_index(alive_count, metadata);
        let mut picked = None;
        let mut i = 0usize;
        self.for_each_member(|p| {
            if eligible(p) {
                if i == idx {
                    picked = Some(Arc::clone(p));
                    return false;
                }
                i += 1;
            }
            true
        });
        picked
    }
}

/// Extract raw IP bytes from `Metadata.src_ip` for FNV hashing.
///
/// IPv4 → 4 bytes. IPv6 → 16 bytes.
/// `None` (no src_addr, e.g. local probe) → 4 zero bytes (0.0.0.0 fallback).
/// Every connection without a src_addr hashes to the same proxy — deterministic,
/// not random. Upstream: undefined (assumes src always present).
fn src_ip_bytes(metadata: &Metadata) -> ([u8; 16], usize) {
    let mut buf = [0u8; 16];
    match metadata.src_ip {
        Some(IpAddr::V4(v4)) => {
            let octets = v4.octets();
            buf[..4].copy_from_slice(&octets);
            (buf, 4)
        }
        Some(IpAddr::V6(v6)) => {
            buf.copy_from_slice(&v6.octets());
            (buf, 16)
        }
        None => (buf, 4),
    }
}

/// FNV-1a 32-bit hash.
///
/// Inline implementation — no crate dep.
/// upstream: adapter/outbound/loadbalance.go uses fnv.New32() (FNV-1, not FNV-1a);
/// we use FNV-1a which has slightly better avalanche properties at no cost.
/// Result is stable for a given input but NOT bit-for-bit identical to Go output.
fn fnv1a(data: &[u8]) -> u32 {
    const OFFSET_BASIS: u32 = 0x811c9dc5;
    const PRIME: u32 = 0x01000193;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[async_trait]
impl ProxyAdapter for LoadBalanceGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::LoadBalance
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.any_member(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self.select(metadata).ok_or(MeowError::NoProxyAvailable)?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.finish(proxy.dial_tcp(metadata).await)
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self
            .select_udp(metadata)
            .ok_or(MeowError::NoProxyAvailable)?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.finish(proxy.dial_udp(metadata).await)
    }

    fn unwrap_proxy(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.usage.touch_user_traffic(metadata);
        self.select(metadata)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for LoadBalanceGroup {
    fn alive(&self) -> bool {
        self.any_member(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.any_member(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.min_alive_delay(|p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.min_alive_delay(|p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.first_alive_member()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        let mut out = Vec::new();
        self.for_each_member(|p| {
            out.push(p.name().to_string());
            true
        });
        Some(out)
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        let mut out = Vec::new();
        self.for_each_member(|p| {
            out.push(Arc::clone(p));
            true
        });
        Some(out)
    }

    fn current(&self) -> Option<String> {
        // For load-balance, no single "current" proxy; return first alive for API compat.
        self.first_alive_member().map(|p| p.name().to_string())
    }

    fn usage_generation(&self) -> u64 {
        self.usage.generation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::{ConnType, DnsMode, Network};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn meta_no_src() -> Metadata {
        Metadata {
            src_ip: None,
            ..Metadata::default()
        }
    }

    fn meta_src(ip: IpAddr) -> Metadata {
        Metadata {
            src_ip: Some(ip),
            network: Network::Tcp,
            conn_type: ConnType::Http,
            src_port: 12345,
            dst_port: 80,
            dns_mode: DnsMode::Normal,
            ..Metadata::default()
        }
    }

    fn make_rr(proxies: Vec<Arc<dyn Proxy>>) -> LoadBalanceGroup {
        LoadBalanceGroup::new("test-lb", proxies, LbStrategy::RoundRobin)
    }

    fn make_ch(proxies: Vec<Arc<dyn Proxy>>) -> LoadBalanceGroup {
        LoadBalanceGroup::new("test-lb", proxies, LbStrategy::ConsistentHashing)
    }

    // ─── D. FNV-1a 32-bit implementation ─────────────────────────────────────

    #[test]
    fn fnv1a_known_vectors() {
        // Known-answer vectors for the inline FNV-1a 32-bit implementation.
        // Reference: https://fnvhash.github.io/fnv-calculator-online/
        // Case labels map to docs/specs/group-load-balance-test-plan.md D1-D3.
        // D3 ([1,1,1,1] = 0x154df079 / 357429369) guards consistent hashing,
        // which derives its proxy index from this hash.
        let cases: &[(&str, &[u8], u32)] = &[
            ("D1 empty input (offset basis)", &[], 0x811c_9dc5),
            ("D2 single null byte", &[0x00], 0x050c_5d1f),
            ("D3 ipv4 bytes 1.1.1.1", &[1, 1, 1, 1], 0x154d_f079),
        ];

        let mut failures = Vec::new();
        for (label, input, expected) in cases {
            let got = fnv1a(input);
            if got != *expected {
                failures.push(format!(
                    "{label}: fnv1a({input:?}) = {got:#010x}, expected {expected:#010x}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "FNV-1a vector mismatches:\n{}",
            failures.join("\n")
        );
    }

    // D4 is a build-time check: no `fnv` or `fnv1` crate dependency in Cargo.toml.

    // ─── A. Round-robin strategy ──────────────────────────────────────────────

    #[test]
    fn round_robin_cycles_through_alive_proxies() {
        // upstream: adapter/outbound/loadbalance.go::RoundRobin.Addr
        // NOT random; NOT skipping index on wrap — strictly sequential.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();

        let expected = ["A", "B", "C", "A", "B", "C", "A", "B", "C", "A"];
        for name in &expected {
            let selected = group.select(&meta).expect("should select");
            assert_eq!(selected.name(), *name, "expected {name}");
        }
    }

    #[test]
    fn round_robin_skips_dead_proxy() {
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        b.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();

        // 6 calls → only A and C appear, alternating [A,C,A,C,A,C]
        for i in 0..6 {
            let selected = group.select(&meta).expect("should select");
            let expect = if i % 2 == 0 { "A" } else { "C" };
            assert_eq!(selected.name(), expect);
        }
    }

    #[test]
    fn round_robin_single_alive_always_selects_it() {
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        b.set_alive(false);
        c.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();
        for _ in 0..5 {
            assert_eq!(group.select(&meta).unwrap().name(), "A");
        }
    }

    #[test]
    fn round_robin_counter_wraps_correctly() {
        // Guards against unchecked arithmetic on counter overflow.
        // 4 proxies alive; counter starts at usize::MAX - 1.
        let proxies: Vec<Arc<dyn Proxy>> = (0..4)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = LoadBalanceGroup {
            name: "wrap-test".into(),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            strategy: LbStrategy::RoundRobin,
            counter: AtomicUsize::new(usize::MAX - 1),
            health: ProxyHealth::new(),
            usage: super::UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
        };
        let meta = meta_no_src();
        // Should not panic; indices are (usize::MAX-1)%4 and (usize::MAX)%4
        let r1 = group.select(&meta);
        let r2 = group.select(&meta);
        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[test]
    fn round_robin_handles_alive_set_flap() {
        // Alive-set is rebuilt on every select() — modulo is on current alive count.
        // NOT out-of-bounds panic. NOT stale-index access. ADR-0002 acceptance criterion #11.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, Arc::clone(&b) as Arc<dyn Proxy>, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();

        let r1 = group.select(&meta);
        assert!(r1.is_some());

        b.set_alive(false);

        let r2 = group.select(&meta);
        assert!(
            r2.is_some(),
            "select after flap must not panic or return None"
        );
        assert!(r2.as_ref().unwrap().alive(), "selected proxy must be alive");
    }

    // ─── B. Consistent-hashing strategy ──────────────────────────────────────

    #[test]
    fn consistent_hashing_stable_for_same_src() {
        // upstream: adapter/outbound/loadbalance.go::ConsistentHashing.Addr
        // NOT volatile — same src IP + fixed proxy list → same proxy every time.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..99 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_differs_for_different_src() {
        // verified: fnv1a([1,1,1,1]) % 3 = 0, fnv1a([127,0,0,1]) % 3 = 1
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);

        let m1 = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let m2 = meta_src(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let p1 = group.select(&m1).unwrap().name().to_string();
        let p2 = group.select(&m2).unwrap().name().to_string();
        assert_ne!(
            p1, p2,
            "1.1.1.1 and 127.0.0.1 must map to different proxies"
        );
    }

    #[test]
    fn consistent_hashing_skips_dead_proxy() {
        // Mark the proxy that 1.1.1.1 would select as dead; another alive proxy is returned.
        // 1.1.1.1 → fnv1a([1,1,1,1]) % 3 = 0 → proxies[0]
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![Arc::clone(&a) as Arc<dyn Proxy>, b, c];
        let group = make_ch(proxies);
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        // Verify A is the normal selection
        assert_eq!(group.select(&meta).unwrap().name(), "A");
        // Mark A dead
        a.set_alive(false);
        // Must still return an alive proxy
        let selected = group
            .select(&meta)
            .expect("should still select with A dead");
        assert!(selected.alive(), "selected proxy must be alive");
    }

    #[test]
    fn consistent_hashing_absent_src_addr_deterministic() {
        // src_addr: None → hashes to 0.0.0.0 (4 zero bytes) → deterministic bucket.
        // NOT random. NOT NoProxyAvailable. NOT an error.
        // Upstream: undefined (assumes src always present) — we define the fallback.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let meta = meta_no_src();

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_ipv6_src_stable() {
        // IPv6 src IP → 16-byte hash input → same proxy across 10 calls.
        // Guards that src_ip_bytes() handles IpAddr::V6 without truncation.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let ip6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let meta = meta_src(ip6);

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_reshuffles_on_list_change() {
        // consistent-hashing = stable for given src+list, NOT ring-consistent.
        // Users should not assume minimal disruption on list change — ADR-0002 Class B row #4.
        // 1.1.1.1 maps to proxy A (idx 0) with [A, B, C].
        // Mark B dead → alive = [A, C]; 1.1.1.1 → fnv1a([1,1,1,1]) % 2 = 1 → C.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, Arc::clone(&b) as Arc<dyn Proxy>, c];
        let group = make_ch(proxies);
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        assert_eq!(group.select(&meta).unwrap().name(), "A");
        b.set_alive(false);
        // fnv1a([1,1,1,1]) % 2 = 1, alive=[A,C], so idx 1 = C
        assert_eq!(group.select(&meta).unwrap().name(), "C");
    }

    // ─── C. All-dead and zero-proxy error paths ───────────────────────────────

    #[test]
    fn all_proxies_dead_round_robin_returns_no_proxy_available() {
        // upstream Go: returns the round-robin slot (a dead proxy). NOT here.
        // ADR-0002 Class A.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        a.set_alive(false);
        b.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_rr(proxies);
        assert!(group.select(&meta_no_src()).is_none());
    }

    #[test]
    fn all_proxies_dead_consistent_hashing_returns_no_proxy_available() {
        // upstream Go panics with index out of bounds. NOT here — ADR-0002 Class A.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        a.set_alive(false);
        b.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_ch(proxies);
        assert!(group
            .select(&meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))))
            .is_none());
    }

    #[test]
    fn empty_proxy_list_returns_no_proxy_available() {
        // Guards against proxies[0] or unwrap() on empty vec at construction.
        let group = make_rr(vec![]);
        assert!(group.select(&meta_no_src()).is_none());
    }

    // ─── E. UDP support ───────────────────────────────────────────────────────

    #[test]
    fn support_udp_reflects_membership() {
        // support_udp() is `any()` over members: true when at least one member
        // supports UDP, false when none do.
        type Case = (&'static str, Vec<Arc<dyn Proxy>>, bool);
        let cases: Vec<Case> = vec![
            (
                "one of three members supports UDP",
                vec![
                    MockProxy::new_udp("A"),
                    MockProxy::new("B"),
                    MockProxy::new("C"),
                ],
                true,
            ),
            (
                "no member supports UDP",
                vec![MockProxy::new("A"), MockProxy::new("B")],
                false,
            ),
        ];

        let mut failures = Vec::new();
        for (label, proxies, expected) in cases {
            let got = make_rr(proxies).support_udp();
            if got != expected {
                failures.push(format!(
                    "{label}: expected support_udp() == {expected}, got {got}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    }

    #[tokio::test]
    async fn dial_udp_filters_to_udp_capable_alive_proxies() {
        // A: UDP+alive, B: no-UDP+alive, C: UDP+dead
        // dial_udp() must select only A.
        let a = MockProxy::new_udp("A");
        let b = MockProxy::new("B"); // no UDP
        let c = MockProxy::new_udp("C");
        c.set_alive(false);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let c_ref = Arc::clone(&c);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        // dial_udp returns error from MockProxy but that's OK — we care about which was tried
        let _ = group.dial_udp(&meta_no_src()).await;
        assert_eq!(a_ref.dials(), 1, "A (UDP+alive) must be tried");
        assert_eq!(b_ref.dials(), 0, "B (no UDP) must not be tried");
        assert_eq!(c_ref.dials(), 0, "C (dead) must not be tried");
    }

    #[tokio::test]
    async fn dial_udp_all_udp_proxies_dead_returns_error() {
        // All UDP-capable proxies dead → NoProxyAvailable. NOT a dial to non-UDP proxy.
        let a = MockProxy::new_udp("A");
        let b = MockProxy::new("B"); // no UDP, alive
        a.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_rr(proxies);
        let result = group.dial_udp(&meta_no_src()).await;
        assert!(
            matches!(result, Err(MeowError::NoProxyAvailable)),
            "expected NoProxyAvailable, got: {:?}",
            result.err()
        );
    }

    // ─── G. AdapterType and ProxyAdapter trait methods ────────────────────────

    #[test]
    fn adapter_type_is_load_balance() {
        let group = make_rr(vec![MockProxy::new("X")]);
        assert_eq!(group.adapter_type(), AdapterType::LoadBalance);
    }

    #[test]
    fn adapter_type_serialises_to_load_balance() {
        let json = serde_json::to_string(&AdapterType::LoadBalance).unwrap();
        assert_eq!(json, r#""LoadBalance""#);
    }

    #[test]
    fn group_name_returns_config_name() {
        let group = make_rr(vec![MockProxy::new("X")]);
        assert_eq!(group.name(), "test-lb");
    }

    #[test]
    fn group_addr_returns_empty() {
        let group = make_rr(vec![MockProxy::new("X")]);
        assert_eq!(group.addr(), "");
    }

    // ─── H. Lazy health-check / usage tracking ────────────────────────────────

    #[tokio::test]
    async fn dial_records_group_use_for_lazy_probe() {
        // #485: a lazy load-balance group is only probed after a dial bumps the
        // usage generation (health_check.rs::should_probe). Mirrors
        // fallback.rs::dial_tcp_routes_through_first_alive.
        let group = make_rr(vec![MockProxy::new("A")]);
        assert_eq!(group.usage_generation(), 0, "unused group has no use");
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(group.usage_generation(), 1, "dial records group use");
    }

    #[tokio::test]
    async fn health_probe_dials_do_not_count_as_use() {
        // Sweep probes dial members with `ConnType::Tunnel`; if that bumped the
        // usage generation a lazy group would keep itself awake forever.
        // Mirrors fallback.rs::health_probe_dials_do_not_count_as_use.
        let group = make_rr(vec![MockProxy::new("A")]);
        let probe_meta = Metadata {
            conn_type: ConnType::Tunnel,
            ..meta_no_src()
        };
        let _ = group.dial_tcp(&probe_meta).await;
        assert_eq!(
            group.usage_generation(),
            0,
            "probe dials must not mark the group as used"
        );
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(group.usage_generation(), 1, "real traffic still marks use");
    }

    // ─── I. Provider slots (issue #533 item 3) ──────────────────────────────

    fn slot_of(proxies: Vec<Arc<dyn Proxy>>) -> ProviderSlot {
        Arc::new(parking_lot::RwLock::new(proxies))
    }

    #[test]
    fn round_robin_cycles_statics_then_slot_members() {
        // One static + a two-member provider slot: the pick space is the
        // concatenation in canonical order (statics first, slot members after).
        let slot = slot_of(vec![MockProxy::new("P1"), MockProxy::new("P2")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let meta = meta_no_src();
        let got: Vec<String> = (0..6)
            .map(|_| group.select(&meta).unwrap().name().to_string())
            .collect();
        assert_eq!(got, ["A", "P1", "P2", "A", "P1", "P2"]);
    }

    #[test]
    fn provider_slot_refresh_is_seen_on_next_select() {
        // The slot is a live RwLock<Vec>: swapping its contents must change
        // both `members()` and the pick space without rebuilding the group.
        let slot = slot_of(vec![MockProxy::new("P1")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![],
            LbStrategy::RoundRobin,
            vec![Arc::clone(&slot)],
        );
        let meta = meta_no_src();
        assert_eq!(group.members().unwrap(), ["P1"]);
        assert_eq!(group.select(&meta).unwrap().name(), "P1");

        *slot.write() = vec![MockProxy::new("P9")];
        assert_eq!(group.members().unwrap(), ["P9"]);
        assert_eq!(group.select(&meta).unwrap().name(), "P9");
    }

    #[test]
    fn dead_slot_member_is_skipped() {
        let dead = MockProxy::new("PD");
        dead.set_alive(false);
        let slot = slot_of(vec![dead, MockProxy::new("P1")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let meta = meta_no_src();
        for _ in 0..4 {
            assert_ne!(group.select(&meta).unwrap().name(), "PD");
        }
    }

    #[test]
    fn consistent_hashing_stable_across_slots() {
        // Same src IP must keep landing on the same member whether the alive
        // set is static or slot-sourced.
        let slot = slot_of(vec![MockProxy::new("P1"), MockProxy::new("P2")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::ConsistentHashing,
            vec![slot],
        );
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn members_and_support_udp_include_slots() {
        let slot = slot_of(vec![MockProxy::new_udp("PU")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        assert_eq!(group.members().unwrap(), ["A", "PU"]);
        assert!(group.support_udp(), "slot member's UDP support counts");
    }

    #[test]
    fn select_udp_picks_udp_capable_slot_member() {
        let slot = slot_of(vec![MockProxy::new_udp("PU"), MockProxy::new("PN")]);
        let group =
            LoadBalanceGroup::new_with_providers("lb", vec![], LbStrategy::RoundRobin, vec![slot]);
        let meta = meta_no_src();
        for _ in 0..4 {
            assert_eq!(group.select_udp(&meta).unwrap().name(), "PU");
        }
    }

    #[tokio::test]
    async fn dial_udp_reaches_udp_capable_slot_member() {
        // End-to-end through `ProxyAdapter::dial_udp` — not just `select_udp`.
        let pu = MockProxy::new_udp("PU");
        let pn = MockProxy::new("PN");
        let pu_ref = Arc::clone(&pu);
        let pn_ref = Arc::clone(&pn);
        let slot = slot_of(vec![pu, pn]);
        let group =
            LoadBalanceGroup::new_with_providers("lb", vec![], LbStrategy::RoundRobin, vec![slot]);
        for _ in 0..3 {
            let _ = group.dial_udp(&meta_no_src()).await;
        }
        assert_eq!(
            pu_ref.dials(),
            3,
            "every UDP dial reaches the capable member"
        );
        assert_eq!(pn_ref.dials(), 0, "non-UDP member is never tried");
    }

    #[tokio::test]
    async fn repeated_dial_failures_mark_slot_member_dead() {
        // Provider members are never probed by the group sweep (their names
        // don't resolve through the route map), so mihomo's onDialFailed
        // escalation — DialAttempt/DialFailureTracker — is their only
        // liveness signal between refreshes. Mirrors urltest's
        // `repeated_dial_failures_mark_member_dead`.
        let failing = MockProxy::new_failing("P1", AdapterType::Shadowsocks, "dial timed out");
        let slot = slot_of(vec![Arc::clone(&failing) as Arc<dyn Proxy>]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        // Round-robin alternates A,P1,A,P1… — only P1's failures count (A is
        // a Direct adapter, exempt). The 5th P1 failure (dial #10) kills it.
        for i in 1..10 {
            let _ = group.dial_tcp(&meta_no_src()).await;
            assert!(
                failing.alive(),
                "failure {i} below the escalation threshold"
            );
        }
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert!(!failing.alive(), "five failures mark the slot member dead");
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(
            failing.dials(),
            5,
            "the dead member no longer receives dials"
        );
    }

    #[tokio::test]
    async fn connection_refused_marks_slot_member_dead_immediately() {
        // mihomo escalates "connection refused" without a streak.
        let failing = MockProxy::new_failing("P1", AdapterType::Shadowsocks, "connection refused");
        let slot = slot_of(vec![Arc::clone(&failing) as Arc<dyn Proxy>]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let _ = group.dial_tcp(&meta_no_src()).await; // A
        let _ = group.dial_tcp(&meta_no_src()).await; // P1 — refused
        assert!(!failing.alive(), "refused escalates on the first failure");
    }

    #[test]
    fn slot_members_feed_alive_for_url_current_and_delay() {
        // All statics dead, one alive slot member: group liveness, current
        // pick, and delay reporting must see the provider member.
        let member = MockProxy::new("P1");
        member.set_delay(50);
        let slot = slot_of(vec![member]);
        let dead = MockProxy::new("A");
        dead.set_alive(false);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![dead],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        assert!(group.alive());
        assert!(group.alive_for_url("https://x"));
        assert_eq!(group.current().as_deref(), Some("P1"));
        assert_eq!(group.last_delay(), 50);
        assert_eq!(group.last_delay_for_url("https://x"), 50);
        assert_eq!(
            group.delay_history().len(),
            1,
            "delay history comes from the alive slot member"
        );
    }

    #[test]
    fn consistent_hashing_picks_alive_after_slot_member_death() {
        // A slot member dying mid-run must not strand the hash: the pick
        // space shrinks and the same src IP lands on an *alive* member.
        let a = MockProxy::new("P1");
        let b = MockProxy::new("P2");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let slot = slot_of(vec![a, b]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![],
            LbStrategy::ConsistentHashing,
            vec![slot],
        );
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        let _ = group.select(&meta);
        a_ref.set_alive(false);
        b_ref.set_alive(false);
        assert!(
            group.select(&meta).is_none(),
            "all dead → None, not a dead pick"
        );
        b_ref.set_alive(true);
        for _ in 0..3 {
            assert_eq!(group.select(&meta).unwrap().name(), "P2");
        }
    }
}
