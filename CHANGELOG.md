# Changelog

All notable changes to meow-rs are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are mirrored onto the GitHub Release for each tag; this file is
the canonical, in-repo source a release is cut from.

## [Unreleased]

### Changed

- **`ipv6` now defaults to `true`.** Previously a config without an explicit
  `ipv6:` key resolved the resolver to IPv4-only; it now enables IPv6 so the
  runtime, `GET /configs`, and the documented default all agree
  (`crates/meow-config/src/lib.rs`, `crates/meow-api/src/routes.rs`,
  `website/guide/configuration.md`). This is a **silent behaviour change** for
  configs that omitted `ipv6`: dual-stack domains are now queried for both A
  and AAAA (concurrently, with IPv4 tried first as a connection fallback) and
  `DirectAdapter` can fall back to IPv6 when IPv4 connectivity fails. Operators
  that need the old IPv4-only behaviour must set `ipv6: false` explicitly.

- DNS dual-stack resolution (`resolve_ips` / `lookup_ip_with_ipv6_inner`) now
  queries A and AAAA **concurrently** when IPv6 is enabled, collecting both
  address families with IPv4 ordered first. `DirectAdapter::dial_tcp` iterates
  the full address list, so an IPv4 connect failure no longer discards the IPv6
  candidate — IPv6 remains a connection fallback.

### Fixed

- **`merge_family` no longer revives an expired sibling family.** When a new
  A answer merged into an entry whose AAAA had already expired, the old code
  unconditionally marked AAAA as `queried`, which `family_hit()` then read as a
  fresh `NoData`, suppressing re-resolution of AAAA. The sibling is now only
  carried forward when its own answer is still fresh; an expired sibling stays
  a `Miss` so the resolver re-queries it on demand.

- **`resolve_ips` no longer short-circuits when one family is cached.** A
  single-family cache entry (e.g. A already fresh, AAAA still `Miss`) no longer
  prevents the missing family from being queried. Only already-fresh families
  are dropped from the query set; the missing required family is always
  fetched, preserving `DirectAdapter`'s cross-family fallback.

- **`GET /configs` reports the correct `ipv6` default.** The API previously
  reported `ipv6: false` for an unset config while the runtime actually enabled
  IPv6, causing UIs/controllers to display a wrong state. Both now default to
  `true`.

- **A fast NXDOMAIN no longer suppresses a slow positive answer.** Within a
  single nameserver tier, the first definitive negative (NODATA/NXDOMAIN) is
  now held for a short grace period while the remaining upstreams keep racing;
  a positive answer arriving later always wins. This restores correct
  behaviour for split-horizon / multi-upstream configurations. Network errors
  (`Err`) are not treated as definitive and never short-circuit the pool.

- **Single-flight broadcast misses no longer surface as SERVFAIL.** A
  subscriber that attached just after the publisher sent (and removed its
  inflight slot) previously received `Closed` and could be judged `Failed`.
  `lookup_real_with_ttl` now re-reads the cache on a missed broadcast, so the
  already-merged result is served instead of a transient SERVFAIL.

- **DoH response bodies are now size-capped.** `doh_exchange` previously
  `read_to_end`-ed an unbounded buffer, letting a misbehaving or hostile
  upstream drive unbounded heap growth. Responses are now rejected once they
  exceed the DNS message maximum (65535 B) plus HTTP header headroom.

- **`snapshot()` hides IPs of an expired family.** When one family is still
  fresh and the other has expired, only the fresh family's IPs appear in the
  cache snapshot panel.

- **Hosts-table IPv6 overrides are honoured even with `ipv6: false`.** An
  AAAA query for a domain present in the hosts trie now returns the hosts-file
  IPv6 address instead of being short-circuited — the hosts file is an
  explicit user override that takes priority over the global `ipv6` toggle.