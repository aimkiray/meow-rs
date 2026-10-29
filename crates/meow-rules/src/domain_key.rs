//! Predicates naming the "dead" shapes a domain key can take, shared by the
//! `rules:` parser and the DNS-side `DomainTrie` surfaces (`hosts:`,
//! `nameserver-policy`, `fallback-filter.domain`, `fake-ip-filter`, and the
//! sniffer `skip-domain`/`force-domain` lists).
//!
//! The same dead-key concept is encoded in three places that must stay
//! consistent:
//!
//! - [`domain_key_defect`] here — the config-time classification callers
//!   warn (lenient) or hard-error (`strict: true`) on;
//! - `DomainTrie::insert`/`insert_overwrite` in `meow-trie` — the writes
//!   that refuse a key outright or strand it on an unreachable node;
//! - `indexable_pattern` in `meow-tunnel`'s `match_engine` — the runtime
//!   index's eligibility test, which excludes the same shapes so a dead
//!   pattern stays on the linear scan rather than owning a trie slot.
//!
//! Every check is observability only: a flagged key is still handed to its
//! consumer — the warn/error surfaces a defect instead of changing what
//! the entry matches.

/// The defect a domain key carries on a `DomainTrie` surface, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKeyDefect {
    /// An empty label survives normalization (`a..b`, `..x`, `+..x`): the
    /// insert "succeeds", but the node it builds is unreachable because no
    /// query name ever contains an empty label (issue #822's shape, one
    /// level up — the trailing-dot half is fixed inside
    /// `DomainTrie::insert` itself).
    DeadLabel,
    /// The normalized body is empty (`"."`, `".."`, `"+."`, `"*."`, a
    /// whitespace-only key): `DomainTrie::insert` refuses the key
    /// outright — no node is built at all.
    NotInsertable,
}

/// The label string a `DomainTrie` works on: surrounding whitespace
/// trimmed, one `+.`/`*.`/`.` wildcard prefix removed, trailing dots
/// dropped — the same normalization `insert_inner` applies before it
/// splits labels, so `x.com.` and `x.com` share the live body `x.com`.
fn domain_key_body(key: &str) -> &str {
    let key = key.trim();
    key.strip_prefix("+.")
        .or_else(|| key.strip_prefix("*."))
        .or_else(|| key.strip_prefix('.'))
        .unwrap_or(key)
        .trim_end_matches('.')
}

/// Classify `key` on a `DomainTrie` surface: `Some(_)` when the key can
/// never be produced by a domain query — either it strands an unreachable
/// node or the trie refuses it outright. Callers warn (lenient) or
/// hard-error (`strict: true`); the key is still inserted either way, so
/// the check is observability, never a semantics change.
pub fn domain_key_defect(key: &str) -> Option<DomainKeyDefect> {
    let body = domain_key_body(key);
    if body.is_empty() {
        return Some(DomainKeyDefect::NotInsertable);
    }
    body.split('.')
        .any(str::is_empty)
        .then_some(DomainKeyDefect::DeadLabel)
}

/// True when `key` holds an empty label after normalization — `a..b`,
/// `..x`, `+..x`. A trailing-dot run is *not* dead on a trie surface:
/// `insert` strips it, so `x.com.` and `x.com..` are live spellings of
/// `x.com`.
pub fn domain_key_has_dead_label(key: &str) -> bool {
    domain_key_defect(key) == Some(DomainKeyDefect::DeadLabel)
}

/// True when `key` can never match on a `DomainTrie` surface — either a
/// dead label or a body the trie refuses.
pub fn domain_key_is_dead(key: &str) -> bool {
    domain_key_defect(key).is_some()
}

/// True when a `DOMAIN`/`DOMAIN-SUFFIX` `rules:` payload can never equal
/// the normalized [`Metadata::rule_host`] it is compared against:
///
/// - a trailing dot — `rule_host()` strips trailing dots, so `x.com.` can
///   only ever name `x.com`, which no `DOMAIN,x.com.` payload matches; or
/// - any [`domain_key_defect`] shape (`a..b`, `"."`, `"+."`).
///
/// Scope: wildcard-looking payloads (`*.x`, `+.x`, `.x`, a mid-string `*`)
/// are likewise unmatchable — `DomainRule` compares them verbatim — but
/// they are legal mihomo spellings that stay outside this check.
///
/// [`Metadata::rule_host`]: meow_common::Metadata::rule_host
pub fn domain_rule_payload_is_dead(payload: &str) -> bool {
    let payload = payload.trim();
    payload.is_empty() || payload.ends_with('.') || domain_key_is_dead(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `DomainTrie`-surface matrix: mid/leading empty labels are dead
    /// (they insert into an unreachable node), prefix-only/all-dots bodies
    /// are refused outright, and trailing dots normalize to a live key.
    #[test]
    fn domain_key_defect_matrix() {
        for key in ["a..b", "..x", "+..x", "+.a..b", "a...b", " a..b "] {
            assert_eq!(
                domain_key_defect(key),
                Some(DomainKeyDefect::DeadLabel),
                "{key:?} is a dead label"
            );
        }
        for key in [".", "..", "+.", "*.", "+..", " ", ""] {
            assert_eq!(
                domain_key_defect(key),
                Some(DomainKeyDefect::NotInsertable),
                "{key:?} is refused by insert"
            );
        }
        // A trailing-dot run is stripped by the trie (live); a mid `*`
        // stays a literal label.
        for key in [
            "x.com.", "x..", "a.*.b", "a.b", "x.com", "+.x.com", "*.x", ".x",
        ] {
            assert_eq!(domain_key_defect(key), None, "{key:?} is live");
        }
    }

    /// The `rules:` surface additionally treats a trailing dot as dead:
    /// `rule_host()` normalizes it away, so `DOMAIN,x.com.` can never
    /// equal a rule host.
    #[test]
    fn domain_rule_payload_is_dead_matrix() {
        for payload in [
            "a..b",
            "x.com.",
            "x.com..",
            ".",
            "..",
            "+.",
            "",
            "  ",
            "evil.com.",
        ] {
            assert!(
                domain_rule_payload_is_dead(payload),
                "{payload:?} is a dead rule payload"
            );
        }
        for payload in ["x.com", "evil.com", "*.x.com", "+.x.com", ".x.com", "a.*.b"] {
            assert!(
                !domain_rule_payload_is_dead(payload),
                "{payload:?} is a live rule payload"
            );
        }
    }
}
