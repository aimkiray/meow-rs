# Spec: DNS hosts and use-system-hosts (M1.E-5)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.E-5**
Supersedes: M0-5 (task #20, completed) — M0-5 wired the trie population from
`hosts:`; M1.E-5 adds wildcard hosts, `use-hosts` toggle, and system hosts.
Depends on: none.
Upstream reference: `dns/resolver.go::hostsTable`, `component/hosts/hosts.go`.

## Motivation

M0-5 wired `hosts:` YAML entries into the `DomainTrie`. However:
- `use-hosts` toggle (enable/disable the hosts table without removing entries)
  is parsed in `RawDns` but the resolver doesn't check it.
- `use-system-hosts` (read from `/etc/hosts`) is not implemented.
- Wildcard entries (`*.example.com: 1.2.3.4`) are not supported.

These gaps cause silently-wrong routing: users who set `use-hosts: false`
intending to disable static entries still get them, and users who configure
`*.corp.internal: 10.0.0.1` get a parse error or silent no-match.

## Scope

In scope:

1. `use-hosts: bool` (default `true`) — if false, skip the hosts trie lookup
   entirely during DNS resolution. The trie is still built at startup; the
   toggle is checked at query time.
2. Wildcard entries in `hosts:`: `"*.example.com": "1.2.3.4"` — matches
   any single-label subdomain of `example.com` (not the root, not deeper
   levels). Uses `DomainTrie` wildcard semantics verbatim; `+.example.com`
   is the distinct form that additionally covers the root and any depth.
3. `use-system-hosts: bool` (default `true`) — read the OS hosts file at
   startup (`/etc/hosts` on Unix, `%SystemRoot%\System32\drivers\etc\hosts`
   on Windows) and merge entries into the trie (lower priority than
   top-level `hosts:` config entries).
4. Multiple IPs per hostname in `hosts:`:
   `"example.com": ["1.2.3.4", "2.3.4.5"]` — returns all IPs as A records.
5. IPv6 addresses in `hosts:` entries — returned as AAAA records.

Out of scope:

- **Hot-reload of the OS hosts file** — read once at startup. M3+.
- **Hostnames with trailing dots** — strip at parse time, warn-once.
- **`0.0.0.0` entries in system hosts** (ad-blocker pattern) — treated as
  valid; resolve to `0.0.0.0` if queried.

## User-facing config

```yaml
dns:
  enable: true
  use-hosts: true         # default: true; set false to disable hosts table
  use-system-hosts: true  # default: true; read the OS hosts file at startup

hosts:                    # top-level key — NOT under dns:
  "localhost": "127.0.0.1"
  "*.corp.internal": "10.0.0.50"     # wildcard: any single-label subdomain of corp.internal
  "dns.corp.internal": "10.0.0.53"   # exact match takes priority over wildcard
  "dual-stack.example.com":
    - "1.2.3.4"
    - "2001:db8::1"                  # both A and AAAA records
```

**Priority order** (highest first):
1. Exact match in `hosts:` config.
2. Wildcard match in `hosts:` config.
3. Entry from the OS hosts file (system).
4. Upstream nameservers.

**Hosts vs `nameserver-policy`**: hosts trie lookup runs before `nameserver-policy`
matching — local data always wins over upstream routing. A domain resolved from
the hosts table never reaches the nameserver-policy dispatch.

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `use-system-hosts: true` on Windows — upstream reads `C:\Windows\System32\drivers\etc\hosts` | — | We match: `%SystemRoot%\System32\drivers\etc\hosts` is read at startup; an unreadable file logs a `warn!` and merges nothing. |
| 2 | Malformed IP in `hosts:` — upstream silently skips | A | Hard parse error. Malformed IPs in hosts are almost certainly typos. |
| 3 | Multiple IPs as list — upstream supports | — | We match. YAML list value accepted. |

## Internal design

### Trie population

```rust
// dns/resolver.rs Resolver::new()

let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();

if config.use_hosts {
    for (domain, ips) in &config.hosts {
        hosts.insert(domain, ips.clone());
    }
    if config.use_system_hosts {
        for (domain, ips) in parse_system_hosts() {
            // hosts: config takes priority: only insert if not already present
            if hosts.search(&domain).is_none() {
                hosts.insert(&domain, ips);
            }
        }
    }
}
// else: hosts trie stays empty; use-hosts: false is equivalent to hosts: {}
```

### System hosts parser

```rust
fn parse_system_hosts() -> Vec<(String, Vec<IpAddr>)> {
    let path = if cfg!(unix) { "/etc/hosts" }
               else { "%SystemRoot%\\System32\\drivers\\etc\\hosts" };
    let Ok(content) = std::fs::read_to_string(path)
        else { tracing::warn!("cannot read {}", path); return vec![]; };
    // startup-only sync I/O; do not call from query path
    // Skip comment lines (#); split each line on whitespace:
    // IP HOSTNAME [aliases...] → one entry per alias including primary hostname
    // ...
}
```

### Wildcard lookup

`DomainTrie` already supports wildcard semantics via its `*.`, `+.`, and
`.` prefixes. Hosts keys are inserted verbatim — `*.example.com` stays a
single-label `*.` pattern (there is no `*` → `+.` rewrite; configure `+.`
directly for apex-inclusive coverage) and resolves via the trie's existing
wildcard lookup. No new trie logic needed.

### Same-slot collisions

`hosts:` is carried in YAML document order (`RawHosts`, an `IndexMap` —
the same contract `nameserver-policy` has). Two keys can land on the same
(node, kind) trie slot: `x` vs `+.x` both write node `x`'s Exact slot,
`.x` vs `+.x` both write its Dot slot, and `X.com`/` x.com ` normalize to
`x.com`'s Exact slot (insert-side trim + lowercase). The document-last
writer wins each slot (`insert_overwrite`, mihomo `node.setData` parity)
— collisions resolve per-slot, so `x` written after `+.x` wins only the
Exact slot and `sub.x` still resolves through `+.x`'s Dot slot. The save
path emits the same document order, and `PUT /configs` order comes from
the submitted text.

Duplicate keys and merge keys follow the same contract `nameserver-policy`
has. A YAML-literal duplicate key (other than `<<`, a merge directive that
may repeat) is a hard parse error (`duplicate mapping key: …`): every
ingest path (`-f`/`-t`, `--config-string`, `PUT /configs`) funnels through
`parse_raw_yaml`, whose serde-saphyr parser rejects the document before
the hosts map is built. The `IndexMap::insert` fold — first position
kept, last value wins — only decides duplicates from non-literal
sources, such as a programmatically built map. serde-saphyr expands a
`<<:` merge key in the event stream: the anchor's entries append at the
END of the map no matter where the `<<:` line is written, and an explicit
key keeps its written position and wins over a merged same-name key —
so for document-last collision purposes, merged entries behave as if
written after every explicit key. The `<<:` line's own position carries
no ordering weight.

## Acceptance criteria

1. `use-hosts: false` → hosts trie lookup skipped; `hosts:` entries have
   no effect on resolution.
2. `use-hosts: true` (default) → `hosts:` entries take priority over
   upstream nameservers.
3. `*.corp.internal: 10.0.0.50` → `foo.corp.internal` resolves to
   `10.0.0.50`; `bar.corp.internal` resolves to `10.0.0.50`; `corp.internal`
   does NOT match and `a.b.corp.internal` does NOT match (`*.` is
   single-label; `+.corp.internal` is the form that includes the root).
4. Exact entry `dns.corp.internal: 10.0.0.53` overrides the wildcard
   `*.corp.internal: 10.0.0.50` for that specific hostname.
5. `use-system-hosts: true` → OS hosts file entries are included in resolution.
6. `hosts:` entry overrides a conflicting OS hosts file entry for the same domain.
7. `use-system-hosts: true` on Windows → `%SystemRoot%\System32\drivers\etc\hosts`
   entries are included in resolution.
8. Malformed IP in `hosts:` → hard parse error. Class A per ADR-0002.
9. Multiple IPs per hostname with mixed v4/v6 values: an A query returns only
   the v4 subset; an AAAA query returns only the v6 subset; if the queried address
   family has no entries in the hosts list, return **NOERROR with zero answers**
   (not NXDOMAIN — clients may retry on NXDOMAIN but not on empty-answer).

## Test plan (starting point — qa owns final shape)

**Unit (`dns/resolver.rs`):**

- `hosts_exact_match_takes_priority_over_upstream` — `hosts:` entry for
  `example.com`; mock upstream returns different IP; assert hosts IP returned.
  Upstream: `dns/resolver.go::hostsTable`. NOT upstream IP returned.
- `hosts_wildcard_matches_subdomain` — `*.corp.internal: 10.0.0.50`;
  query `foo.corp.internal` → 10.0.0.50. NOT NXDOMAIN.
- `hosts_wildcard_matches_root` — `+.corp.internal`; query `corp.internal`
  → the entry's value (root is included only for `+.`). A `*.corp.internal`
  key must NOT match `corp.internal`.
- `hosts_exact_overrides_wildcard` — both `*.corp.internal` and
  `dns.corp.internal`; query `dns.corp.internal` → exact match value.
  NOT wildcard value.
- `use_hosts_false_bypasses_table` — `use-hosts: false`; configured entry
  for `example.com`; assert upstream queried (not hosts value returned).
  NOT hosts entry returned when disabled.
- `system_hosts_loaded_when_enabled` — mock `/etc/hosts` with known entry;
  assert it resolves. NOT ignored.
- `system_hosts_overridden_by_config_hosts` — same domain in both; config
  hosts wins. NOT system hosts wins.
- `hosts_malformed_ip_hard_errors` — `"example.com": "not-an-ip"` →
  parse error at startup. Class A per ADR-0002.

## Implementation checklist (engineer handoff)

- [ ] Verify `use-hosts` is checked at query time in `Resolver::resolve_ip()`
      (not just at trie-build time).
- [x] Insert `*.foo` / `+.foo` / `.foo` / bare keys verbatim at `hosts:`
      parse time (no `*.` → `+.` rewrite — `*.` is single-label).
- [ ] Parse multi-value hosts (`[ip1, ip2]`) in `dns_parser.rs`.
- [ ] Implement `parse_system_hosts()` for Unix and Windows (the OS hosts
      file path differs); warn + merge nothing when it cannot be read.
- [ ] Wire system hosts population in `Resolver::new()` respecting priority.
- [ ] Update `docs/roadmap.md` M1.E-5 row with merged PR link.
