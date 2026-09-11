//! A matched rule whose target the registry does not hold falls back to
//! DIRECT — no longer silently (issue #513).
//!
//! Note the deliberate deviation from upstream mihomo: its match loop *skips*
//! a rule whose target is absent and keeps scanning later rules, reaching
//! DIRECT only via the no-match tail (and reporting no rule). meow-rs stops at
//! the first match and dials DIRECT — a subscription that dropped one node
//! keeps routing the rest, but a later rule upstream would have matched is
//! never consulted. The semantic parity question is a separate follow-up;
//! what this port got wrong regardless is that nothing said so. The log line
//! was a `debug!`, invisible at the default level, and the match statistics
//! derived their action label from the target *name* before the lookup ran,
//! so a rule naming `ghost-group` was counted as a PROXY hop that never
//! happened while the bytes left the machine over the direct adapter. These
//! tests pin the observable half — same DIRECT dial, honest counter.

use meow_common::{AdapterType, DnsMode, Metadata, Network, Rule, TunnelMode};
use meow_dns::Resolver;
use meow_rules::final_rule::FinalRule;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::sync::Arc;

fn resolver() -> Arc<Resolver> {
    Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ))
}

/// A tunnel in rule mode whose registry is the one every real load publishes:
/// the built-in DIRECT / REJECT / REJECT-DROP entries and nothing else.
fn tunnel_with_builtin_registry() -> Tunnel {
    let tunnel = Tunnel::new(resolver());
    let (proxies, _) = meow_config::rebuild_from_raw(&meow_config::raw::RawConfig::default())
        .expect("an empty config must build its built-in registry");
    tunnel.update_proxies(proxies);
    tunnel.set_mode(TunnelMode::Rule);
    tunnel
}

fn metadata() -> Metadata {
    Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    }
}

/// The rules a real config leaves behind when a node was dropped: a `MATCH`
/// naming something the registry does not hold.
fn tunnel_with_ghost_target() -> Tunnel {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("ghost-group"))];
    tunnel.update_rules(rules);
    tunnel
}

#[test]
fn a_matched_rule_with_a_missing_target_still_dials_direct() {
    let tunnel = tunnel_with_ghost_target();

    let (proxy, rule, _payload) = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("a MATCH rule always resolves");

    assert_eq!(rule, "MATCH");
    assert_eq!(
        proxy.adapter_type(),
        AdapterType::Direct,
        "meow-rs dials DIRECT here; upstream instead skips the rule and keeps matching"
    );
}

#[test]
fn the_fallback_is_counted_as_the_direct_dial_it_actually_is() {
    let tunnel = tunnel_with_ghost_target();
    tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("a MATCH rule always resolves");

    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "DIRECT"), 1)],
        "the counter must not report a proxy hop that never happened"
    );
}

#[tokio::test]
async fn the_lazy_resolve_path_falls_back_the_same_way() {
    let tunnel = tunnel_with_ghost_target();

    let mut md = metadata();
    let (proxy, _rule, _payload) = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "DIRECT"), 1)],
        "both resolve paths share `materialize_rule_match`, so both count alike"
    );
}

#[test]
fn a_target_the_registry_holds_is_used_as_is() {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("REJECT-DROP"))];
    tunnel.update_rules(rules);

    let (proxy, _rule, _payload) = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::RejectDrop);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "REJECT"), 1)],
        "a refusal the registry really performed is still counted as one"
    );
}

#[test]
fn a_rule_naming_direct_needs_no_registry_entry() {
    // DIRECT is a built-in the tunnel owns an adapter for, so a rule naming it
    // must resolve even before any registry snapshot has been published — and
    // must not be reported as a fallback, because it is the intended target.
    let tunnel = Tunnel::new(resolver());
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("DIRECT"))];
    tunnel.update_rules(rules);

    let (proxy, _rule, _payload) = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "DIRECT"), 1)]
    );
}

#[test]
fn no_rule_matching_still_falls_through_to_direct() {
    // Only a *matched* rule with an unresolvable target is relabelled. Nothing
    // matching at all is the ordinary end of the rule list, which has never
    // touched the match counters.
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![];
    tunnel.update_rules(rules);

    let (proxy, rule, _payload) = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("the no-match path still yields DIRECT");

    assert_eq!(rule, "Final");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert!(
        tunnel.statistics().rule_match.snapshot().is_empty(),
        "the fall-through is not a rule match and must not be counted as one"
    );
}
