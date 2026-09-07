//! A matched rule whose target the registry does not hold must refuse the
//! connection, never dial it out over DIRECT (issue #513).
//!
//! Upstream mihomo falls back to DIRECT here, which turns one misspelt proxy or
//! group name into a silent policy bypass: traffic the operator meant to route
//! through a proxy leaves the machine directly, and nothing in the connection
//! record says so. meow-rs substitutes its own REJECT adapter and reports the
//! match to the statistics as the refusal it now is.

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

#[test]
fn a_matched_rule_with_a_missing_target_is_refused_not_dialled_direct() {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("ghost-group"))];
    tunnel.update_rules(rules);

    let (proxy, rule, _payload) = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("a MATCH rule always resolves");

    assert_eq!(rule, "MATCH");
    assert_eq!(
        proxy.adapter_type(),
        AdapterType::Reject,
        "the connection must be refused, not sent out directly"
    );
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "REJECT"), 1)],
        "the stats must report the refusal rather than a proxy hop that never happened"
    );
}

#[tokio::test]
async fn the_lazy_resolve_path_refuses_a_missing_target_too() {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("ghost-group"))];
    tunnel.update_rules(rules);

    let mut md = metadata();
    let (proxy, _rule, _payload) = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::Reject);
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

    assert_eq!(
        proxy.adapter_type(),
        AdapterType::RejectDrop,
        "the registry's own REJECT-DROP must win over the substituted REJECT"
    );
}

#[test]
fn a_rule_naming_direct_needs_no_registry_entry() {
    // DIRECT is a built-in the tunnel owns an adapter for, so a rule naming it
    // must resolve even before any registry snapshot has been published —
    // otherwise the refusal above would swallow the common case.
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
    // Only a *matched* rule with an unresolvable target is refused. Nothing
    // matching at all is the ordinary end of the rule list.
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![];
    tunnel.update_rules(rules);

    let (proxy, rule, _payload) = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("the no-match path still yields DIRECT");

    assert_eq!(rule, "Final");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
}
