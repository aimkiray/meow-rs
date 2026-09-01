//! Rule-set (rule-provider) matchers.
//!
//! A `RuleSet` is a collection of rules loaded from an external source (file or
//! HTTP) that can be referenced from the main rule list via a single
//! `RULE-SET,<name>,<adapter>` entry. Three behaviors are supported:
//!
//! - `Domain` — payload is a list of domains / `+.domain` wildcards, stored
//!   in a `DomainTrie` for O(log N) lookup.
//! - `IpCidr` — payload is a list of IPv4/IPv6 CIDRs.
//! - `Classical` — payload is a list of full Clash rule strings; each line
//!   is parsed as a normal rule (adapter ignored).

use std::fmt;
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use meow_trie::DomainTrie;
use tracing::warn;

use crate::parser::{parse_rule, ParserContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl FromStr for RuleSetBehavior {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "ipcidr" | "ip-cidr" => Ok(Self::IpCidr),
            "classical" => Ok(Self::Classical),
            other => Err(format!("unknown rule-set behavior: {other}")),
        }
    }
}

impl fmt::Display for RuleSetBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain => write!(f, "Domain"),
            Self::IpCidr => write!(f, "IPCIDR"),
            Self::Classical => write!(f, "Classical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetFormat {
    Yaml,
    Text,
    Mrs,
}

impl FromStr for RuleSetFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "yaml" => Ok(Self::Yaml),
            "text" => Ok(Self::Text),
            "mrs" => Ok(Self::Mrs),
            other => Err(format!("unsupported rule-set format: {other}")),
        }
    }
}

pub trait RuleSet: Send + Sync {
    fn behavior(&self) -> RuleSetBehavior;
    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool;
    fn len(&self) -> usize;
    fn should_resolve_ip(&self) -> bool {
        false
    }
    fn should_find_process(&self) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Domain-only match for DNS `nameserver-policy` `rule-set:` entries.
    ///
    /// Unlike [`RuleSet::matches`], this takes a bare domain string instead of
    /// a full [`Metadata`], because DNS policy dispatch only has the query
    /// domain. IP-behavior sets return `false`; classical sets evaluate their
    /// rules against a host-only `Metadata` (IP rules never match).
    fn matches_domain(&self, _domain: &str) -> bool {
        false
    }
}

/// Build a rule-set of the given behavior from already-parsed entries.
///
/// `ctx` is only consulted when `behavior == Classical` (since classical
/// rule-set entries are full rule lines that may include context-requiring
/// types like GEOIP). Domain and IpCidr behaviors ignore it entirely.
pub fn build_rule_set(
    behavior: RuleSetBehavior,
    entries: &[String],
    ctx: &ParserContext,
) -> Box<dyn RuleSet> {
    match behavior {
        RuleSetBehavior::Domain => Box::new(DomainRuleSet::from_entries(entries)),
        RuleSetBehavior::IpCidr => Box::new(IpCidrRuleSet::from_entries(entries)),
        RuleSetBehavior::Classical => Box::new(ClassicalRuleSet::from_entries(entries, ctx)),
    }
}

/// Return `true` if `bytes` starts with the MRS magic `"MRS!"`.
pub fn is_mrs_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[..4] == crate::mrs_parser::MRS_MAGIC
            || bytes[..4] == crate::mrs_parser::ZSTD_MAGIC)
}

/// Parse an MRS binary payload and return the appropriate `RuleSet`.
/// The behavior is determined by the type tag in the header.
pub fn build_rule_set_from_mrs(
    bytes: &[u8],
    ctx: &ParserContext,
) -> Result<Box<dyn RuleSet>, String> {
    build_rule_set_from_mrs_with_behavior(bytes, ctx, None)
}

/// Parse an MRS binary payload and optionally validate it against the
/// configured provider behavior.
pub fn build_rule_set_from_mrs_with_behavior(
    bytes: &[u8],
    ctx: &ParserContext,
    expected: Option<RuleSetBehavior>,
) -> Result<Box<dyn RuleSet>, String> {
    use crate::mrs_parser::{
        decompress_payload, parse_header, parse_upstream_ruleset_mrs, TYPE_CLASSICAL, TYPE_DOMAIN,
        TYPE_IPCIDR, ZSTD_MAGIC,
    };
    if bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC {
        let payload = parse_upstream_ruleset_mrs(bytes).map_err(|e| e.to_string())?;
        let actual = behavior_from_type_tag(payload.behavior)?;
        if let Some(expected) = expected {
            if expected != actual {
                return Err(format!(
                    "mrs: behavior mismatch: config says {expected}, file says {actual}"
                ));
            }
        }
        return match actual {
            RuleSetBehavior::Domain => Ok(Box::new(DomainRuleSet::from_entries(&payload.entries))),
            RuleSetBehavior::IpCidr => Ok(Box::new(IpCidrRuleSet::from_entries(&payload.entries))),
            RuleSetBehavior::Classical => {
                Err("mrs: upstream format does not support classical behavior".to_string())
            }
        };
    }

    let (hdr, compressed) = parse_header(bytes).map_err(|e| e.to_string())?;
    let actual = behavior_from_type_tag(hdr.type_tag)?;
    if let Some(expected) = expected {
        if expected != actual {
            return Err(format!(
                "mrs: behavior mismatch: config says {expected}, file says {actual}"
            ));
        }
    }
    let payload = decompress_payload(compressed).map_err(|e| e.to_string())?;
    match hdr.type_tag {
        TYPE_DOMAIN => {
            let entries = parse_string_list_payload(&payload)?;
            Ok(Box::new(DomainRuleSet::from_entries(&entries)))
        }
        TYPE_IPCIDR => {
            let entries = parse_ipcidr_payload(&payload)?;
            Ok(Box::new(IpCidrRuleSet::from_entries(&entries)))
        }
        TYPE_CLASSICAL => {
            let entries = parse_string_list_payload(&payload)?;
            Ok(Box::new(ClassicalRuleSet::from_entries(&entries, ctx)))
        }
        other => Err(format!("mrs: unsupported type tag {other}")),
    }
}

fn behavior_from_type_tag(type_tag: u8) -> Result<RuleSetBehavior, String> {
    use crate::mrs_parser::{TYPE_CLASSICAL, TYPE_DOMAIN, TYPE_IPCIDR};
    match type_tag {
        TYPE_DOMAIN => Ok(RuleSetBehavior::Domain),
        TYPE_IPCIDR => Ok(RuleSetBehavior::IpCidr),
        TYPE_CLASSICAL => Ok(RuleSetBehavior::Classical),
        other => Err(format!("mrs: unsupported type tag {other}")),
    }
}

fn parse_string_list_payload(decompressed: &[u8]) -> Result<Vec<String>, String> {
    let mut pos = 0;
    let mut entries = Vec::new();
    while pos < decompressed.len() {
        if pos + 2 > decompressed.len() {
            return Err("mrs: truncated string length".to_string());
        }
        let len = u16::from_be_bytes([decompressed[pos], decompressed[pos + 1]]) as usize;
        pos += 2;
        if pos + len > decompressed.len() {
            return Err(format!("mrs: truncated string entry at offset {pos}"));
        }
        let s = std::str::from_utf8(&decompressed[pos..pos + len])
            .map_err(|e| format!("mrs: invalid UTF-8: {e}"))?;
        entries.push(s.to_string());
        pos += len;
    }
    Ok(entries)
}

fn parse_ipcidr_payload(decompressed: &[u8]) -> Result<Vec<String>, String> {
    let mut pos = 0;
    let mut entries = Vec::new();
    while pos < decompressed.len() {
        if pos + 1 > decompressed.len() {
            return Err("mrs: truncated ip family".to_string());
        }
        let family = decompressed[pos];
        pos += 1;
        let addr_len = match family {
            4 => 4usize,
            16 => 16usize,
            other => return Err(format!("mrs: unknown ip family {other}")),
        };
        if pos + addr_len + 1 > decompressed.len() {
            return Err("mrs: truncated ip address".to_string());
        }
        let addr_bytes = &decompressed[pos..pos + addr_len];
        pos += addr_len;
        let prefix_len = decompressed[pos];
        pos += 1;
        let cidr = if family == 4 {
            let arr: [u8; 4] = addr_bytes
                .try_into()
                .map_err(|_| "mrs: bad ipv4".to_string())?;
            let addr = std::net::Ipv4Addr::from(arr);
            format!("{addr}/{prefix_len}")
        } else {
            let arr: [u8; 16] = addr_bytes
                .try_into()
                .map_err(|_| "mrs: bad ipv6".to_string())?;
            let addr = std::net::Ipv6Addr::from(arr);
            format!("{addr}/{prefix_len}")
        };
        entries.push(cidr);
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

pub struct DomainRuleSet {
    trie: DomainTrie<()>,
    count: usize,
}

impl DomainRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        let mut count = 0;
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let inserted = trie.insert(entry, ());
            // `+.foo.com` should match both the bare `foo.com` and any
            // subdomain (upstream mihomo semantics). `DomainTrie::insert`
            // only registers the wildcards; also insert the bare host.
            let bare_inserted = if let Some(rest) = entry.strip_prefix("+.") {
                trie.insert(rest, ())
            } else {
                true
            };
            if inserted || bare_inserted {
                count += 1;
            } else {
                warn!("rule-set (domain): skipping invalid entry '{}'", entry);
            }
        }
        trie.seal();
        Self { trie, count }
    }
}

impl RuleSet for DomainRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Domain
    }

    fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host();
        if host.is_empty() {
            return false;
        }
        self.trie.search(host).is_some()
    }

    fn len(&self) -> usize {
        self.count
    }

    fn matches_domain(&self, domain: &str) -> bool {
        self.trie.search(domain).is_some()
    }
}

// ---------------------------------------------------------------------------
// IpCidr
// ---------------------------------------------------------------------------

/// ipcidr rule-set backed by split `IpRange` Patricia tries — lookup is
/// O(prefix-depth) instead of a linear scan over every CIDR. Country/ASN
/// providers commonly carry thousands of entries, and every connection that
/// reaches the rule paid O(N) comparisons with the previous `Vec<IpNet>`.
/// Same structure `country_index.rs` already uses for GEOIP rules.
pub struct IpCidrRuleSet {
    v4: IpRange<Ipv4Net>,
    v6: IpRange<Ipv6Net>,
    /// Parsed-entry count, as reported by `len()`. Kept separately because
    /// `simplify()` merges adjacent/nested networks inside the tries.
    count: usize,
}

impl IpCidrRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut v4: IpRange<Ipv4Net> = IpRange::new();
        let mut v6: IpRange<Ipv6Net> = IpRange::new();
        let mut count = 0usize;
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => {
                    v4.add(net);
                    count += 1;
                }
                Ok(IpNet::V6(net)) => {
                    v6.add(net);
                    count += 1;
                }
                Err(e) => warn!(
                    "rule-set (ipcidr): skipping invalid entry '{}': {}",
                    entry, e
                ),
            }
        }
        v4.simplify();
        v6.simplify();
        Self { v4, v6, count }
    }
}

impl RuleSet for IpCidrRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::IpCidr
    }

    fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let Some(ip) = metadata.dst_ip else {
            return false;
        };
        match ip {
            std::net::IpAddr::V4(v4) => self
                .v4
                .contains(&Ipv4Net::new(v4, 32).expect("/32 is always valid")),
            std::net::IpAddr::V6(v6) => self
                .v6
                .contains(&Ipv6Net::new(v6, 128).expect("/128 is always valid")),
        }
    }

    fn len(&self) -> usize {
        self.count
    }

    fn should_resolve_ip(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Classical
// ---------------------------------------------------------------------------

pub struct ClassicalRuleSet {
    rules: Vec<Box<dyn Rule>>,
    /// Indices into `rules` of the domain-family subset, pre-filtered once
    /// at construction (review H4): the DNS `nameserver-policy` hot path
    /// runs `matches_domain` on **every query**, so it must not re-test the
    /// rule-type whitelist against all `n` rules per call — it scans only
    /// these indices.
    domain_rule_indices: Vec<usize>,
}

/// Rule types eligible for DNS `nameserver-policy` domain dispatch. This is
/// a *rule-type whitelist*, not a host-only `Metadata` probe: rules such as
/// `NETWORK,TCP`, `IN-TYPE,HTTP`, or `DST-PORT,0` match the default
/// `Metadata` (network = Tcp, conn_type = Http, ports = 0) and would
/// otherwise hijack *every* query to this policy — a DNS leak. Logic rules
/// (`AND`/`OR`/`NOT`) and `MATCH` are excluded too: they either re-derive
/// from those default-matching leaves or match everything.
///
/// The whitelist is also the reentrancy guard (review H4): every eligible
/// type is host-only — `should_resolve_ip()` is false for all of them — so
/// matching can never trigger a nested DNS lookup even though
/// `RuleMatchHelper` carries no resolver.
fn is_domain_family_rule_type(t: RuleType) -> bool {
    matches!(
        t,
        RuleType::Domain
            | RuleType::DomainSuffix
            | RuleType::DomainKeyword
            | RuleType::DomainRegex
            | RuleType::DomainWildcard
            | RuleType::GeoSite,
    )
}

impl ClassicalRuleSet {
    pub fn from_entries(entries: &[String], ctx: &ParserContext) -> Self {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // Classical entries are `TYPE,PAYLOAD[,extra]` without an adapter.
            // The existing parser expects an adapter column, so splice a
            // placeholder in and discard it at match time (our wrapper owns
            // the real adapter). A MATCH-only shorthand is unusual in
            // classical sets and would be meaningless anyway.
            let patched = splice_placeholder_adapter(entry);
            match parse_rule(&patched, ctx) {
                Ok(rule) => rules.push(rule),
                Err(e) => warn!("rule-set (classical): skipping '{}': {}", entry, e),
            }
        }
        let domain_rule_indices = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| is_domain_family_rule_type(r.rule_type()))
            .map(|(i, _)| i)
            .collect();
        Self {
            rules,
            domain_rule_indices,
        }
    }
}

impl RuleSet for ClassicalRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Classical
    }

    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn len(&self) -> usize {
        self.rules.len()
    }

    fn should_resolve_ip(&self) -> bool {
        self.rules.iter().any(|rule| rule.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.rules.iter().any(|rule| rule.should_find_process())
    }

    fn matches_domain(&self, domain: &str) -> bool {
        // Nameserver-policy `rule-set:` dispatch only has the query domain,
        // so we restrict classical sets to their domain-family rules (see
        // `is_domain_family_rule_type`). The subset was pre-filtered at
        // construction, so this is O(domain rules) per query — not O(all
        // rules) with a type test each (review H4). Cost note: a large
        // classical set still pays a linear scan over its domain rules on
        // *every DNS query* that reaches this policy entry; prefer a
        // `behavior: domain` provider for large sets.
        //
        // Reentrancy: every eligible rule type is host-only
        // (`should_resolve_ip()` = false), so matching cannot trigger a
        // nested DNS lookup through `RuleMatchHelper` (which is a bare
        // marker with no resolver access).
        if self.domain_rule_indices.is_empty() {
            // Fast path: no domain-family rules (e.g. an IP-only classical
            // set) — also skips the ~272 B `Metadata` construction.
            return false;
        }
        let metadata = Metadata {
            host: domain.into(),
            ..Default::default()
        };
        self.domain_rule_indices.iter().any(|&index| {
            let rule = &self.rules[index];
            debug_assert!(
                is_domain_family_rule_type(rule.rule_type()),
                "domain_rule_indices must only hold domain-family rules"
            );
            rule.match_metadata(&metadata, &RuleMatchHelper)
        })
    }
}

/// Turn `TYPE,PAYLOAD[,extra]` into `TYPE,PAYLOAD,RULE-SET-PLACEHOLDER[,extra]`
/// so it satisfies `parse_rule`'s `type,payload,adapter[,extra]` shape.
fn splice_placeholder_adapter(entry: &str) -> String {
    const PLACEHOLDER: &str = "RULE-SET-PLACEHOLDER";
    let parts: Vec<&str> = entry.splitn(3, ',').collect();
    match parts.as_slice() {
        [ty, payload] => format!("{},{},{}", ty.trim(), payload.trim(), PLACEHOLDER),
        [ty, payload, rest] => format!(
            "{},{},{},{}",
            ty.trim(),
            payload.trim(),
            PLACEHOLDER,
            rest.trim()
        ),
        _ => entry.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::Metadata;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_host(host: &str) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    fn meta_ip(ip: &str) -> Metadata {
        Metadata {
            dst_ip: Some(ip.parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        }
    }

    #[test]
    fn domain_rule_set_matches_plus_wildcard() {
        let set = DomainRuleSet::from_entries(&["+.foo.com".to_string()]);
        assert!(set.matches(&meta_host("a.foo.com"), &helper()));
        assert!(set.matches(&meta_host("foo.com"), &helper()));
        assert!(!set.matches(&meta_host("bar.com"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches() {
        let set = IpCidrRuleSet::from_entries(&[
            "10.0.0.0/8".to_string(),
            "bogus".to_string(), // skipped
        ]);
        assert_eq!(set.len(), 1);
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(!set.matches(&meta_ip("11.0.0.1"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches_ipv6() {
        let set = IpCidrRuleSet::from_entries(&["fd00::/8".to_string()]);
        assert_eq!(set.len(), 1);
        assert!(set.matches(&meta_ip("fd12::1"), &helper()));
        assert!(!set.matches(&meta_ip("2001:db8::1"), &helper()));
        // An IPv4 destination must not match a v6-only rule set.
        assert!(!set.matches(&meta_ip("10.1.2.3"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches_mixed_families() {
        let set = IpCidrRuleSet::from_entries(&["10.0.0.0/8".to_string(), "fd00::/8".to_string()]);
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(set.matches(&meta_ip("fd12::1"), &helper()));
        assert!(!set.matches(&meta_ip("11.0.0.1"), &helper()));
        assert!(!set.matches(&meta_ip("2001:db8::1"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_coalesces_adjacent_cidrs_without_semantic_change() {
        // Adjacent /24s coalesce into one /23 inside the trie; matching
        // behavior must be identical to checking each CIDR independently.
        let set =
            IpCidrRuleSet::from_entries(&["10.0.0.0/24".to_string(), "10.0.1.0/24".to_string()]);
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_ip("10.0.0.128"), &helper()));
        assert!(set.matches(&meta_ip("10.0.1.128"), &helper()));
        assert!(!set.matches(&meta_ip("10.0.2.1"), &helper()));
    }

    #[test]
    fn classical_rule_set_delegates_to_parser() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-SUFFIX,google.com".to_string(),
                "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
            ],
            &ctx,
        );
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_host("mail.google.com"), &helper()));
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(!set.matches(&meta_host("example.org"), &helper()));
    }

    #[test]
    fn classical_rule_set_propagates_metadata_demands() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "IP-CIDR,10.0.0.0/8".to_string(),
                "PROCESS-NAME,curl".to_string(),
            ],
            &ctx,
        );
        assert!(set.should_resolve_ip());
        assert!(set.should_find_process());
    }

    #[test]
    fn build_rule_set_dispatches_by_behavior() {
        let ctx = ParserContext::empty();
        let set = build_rule_set(RuleSetBehavior::Domain, &["example.com".to_string()], &ctx);
        assert_eq!(set.behavior(), RuleSetBehavior::Domain);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn domain_rule_set_matches_domain_directly() {
        let set = DomainRuleSet::from_entries(&["+.foo.com".to_string()]);
        assert!(set.matches_domain("a.foo.com"));
        assert!(set.matches_domain("foo.com"));
        assert!(!set.matches_domain("bar.com"));
        // case-insensitive, like the full Metadata path
        assert!(set.matches_domain("A.Foo.COM"));
    }

    #[test]
    fn classical_rule_set_matches_domain_only() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-SUFFIX,google.com".to_string(),
                "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
                // A DST-PORT rule must NOT fire on a domain-only query even
                // though DNS runs on port 53 — guard against dst_port=53
                // false positives in matches_domain.
                "DST-PORT,53".to_string(),
            ],
            &ctx,
        );
        assert!(set.matches_domain("mail.google.com"));
        // IP and port rules must not fire on a domain-only query.
        assert!(!set.matches_domain("10.0.0.1"));
        assert!(!set.matches_domain("example.org"));
    }

    // Rules that match the *default* `Metadata` (network = Tcp,
    // conn_type = Http, ports = 0) but ignore the host would otherwise
    // hijack every query to this policy. The rule-type whitelist must
    // exclude them so nameserver-policy `rule-set:` cannot leak DNS.
    #[test]
    fn classical_rule_set_matches_domain_ignores_default_matching_rules() {
        let ctx = ParserContext::empty();
        let cases: &[(&str, &str)] = &[
            ("NETWORK,tcp", "totally-unrelated.example"),
            ("IN-TYPE,HTTP", "totally-unrelated.example"),
            ("DST-PORT,0", "totally-unrelated.example"),
            ("SRC-PORT,0", "totally-unrelated.example"),
            ("MATCH,DIRECT", "totally-unrelated.example"),
        ];
        for (rule, domain) in cases {
            let set = ClassicalRuleSet::from_entries(&[rule.to_string()], &ctx);
            assert!(
                !set.matches_domain(domain),
                "matches_domain must be false for '{rule}' against '{domain}'"
            );
        }
    }

    #[test]
    fn classical_rule_set_matches_domain_matches_geosite() {
        // GEOSITE is a domain-family rule and stays in the whitelist.
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &["GEOSITE,google".to_string(), "NETWORK,tcp".to_string()],
            &ctx,
        );
        // GEOSITE matching needs a loaded geosite DB; with none present it
        // simply does not match, but the NETWORK,tcp line still must not
        // hijack an unrelated domain.
        assert!(!set.matches_domain("totally-unrelated.example"));
    }

    #[test]
    fn ipcidr_rule_set_matches_domain_is_false() {
        let set = IpCidrRuleSet::from_entries(&["10.0.0.0/8".to_string()]);
        assert!(!set.matches_domain("10.0.0.1"));
        assert!(!set.matches_domain("foo.com"));
    }

    // Reentrancy guard (review H4): an `IP-CIDR` rule without
    // `no-resolve` demands IP resolution at match time — on the full
    // metadata path it can trigger a nested DNS lookup. The DNS-policy
    // domain whitelist must exclude it entirely, so `matches_domain` can
    // never re-enter the resolver through `RuleMatchHelper`.
    #[test]
    fn classical_rule_set_matches_domain_excludes_resolver_requiring_rules() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "IP-CIDR,10.0.0.0/8".to_string(),
                "DOMAIN-SUFFIX,example.com".to_string(),
            ],
            &ctx,
        );
        // The IP-CIDR rule is present and resolver-requiring on the full
        // metadata path…
        assert!(
            set.should_resolve_ip(),
            "IP-CIDR without no-resolve must stay resolver-requiring on the full path"
        );
        // …but the DNS domain dispatch subset holds only the DOMAIN-SUFFIX
        // rule, and matching never fires the IP-CIDR rule (so it cannot
        // trigger a nested lookup).
        assert_eq!(set.domain_rule_indices.len(), 1);
        assert!(set.matches_domain("www.example.com"));
        assert!(!set.matches_domain("unrelated.test"));
    }

    // The domain subset is pre-filtered at construction (review H4): an
    // IP-only classical set must take the empty fast path and never match.
    #[test]
    fn classical_rule_set_matches_domain_ip_only_set_never_matches() {
        let ctx = ParserContext::empty();
        let set =
            ClassicalRuleSet::from_entries(&["IP-CIDR,10.0.0.0/8,no-resolve".to_string()], &ctx);
        assert!(set.domain_rule_indices.is_empty());
        assert!(!set.matches_domain("anything.example"));
    }

    #[test]
    fn behavior_from_str() {
        assert_eq!(
            "domain".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::Domain
        );
        assert_eq!(
            "ipcidr".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::IpCidr
        );
        assert_eq!(
            "IPCIDR".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::IpCidr
        );
        assert_eq!(
            "classical".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::Classical
        );
        assert!("nope".parse::<RuleSetBehavior>().is_err());
    }
}
