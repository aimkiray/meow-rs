# Geodata

Geolocation rules need data files: a GeoIP country database for `GEOIP`/`SRC-GEOIP` (and
the DNS `fallback-filter.geoip` gate), a GeoLite2-ASN database for `IP-ASN`/`SRC-IP-ASN`,
and a GeoSite database for `GEOSITE` rules and `geosite:` nameserver-policy keys. The
optional `geodata` block points at them and controls auto-updates.

```yaml
geodata:
  mmdb-path: /etc/meow/Country.mmdb
  auto-update: true
  auto-update-interval: 24
  proxy: hk-01
```

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mmdb-path` | string | auto | Path to `Country.mmdb` (GeoIP) |
| `asn-path` | string | auto | Path to `GeoLite2-ASN.mmdb` |
| `geosite-path` | string | auto | Path to the GeoSite database (`.dat` / `.mrs`) |
| `auto-update` | bool | `false` | Refresh the databases in the background |
| `auto-update-interval` | u32 (hours) | — | Hours between updates (min 1) |
| `url` | map | CDN defaults | Override download URLs (`mmdb`, `asn`, `geosite`) |
| `proxy` | string | default egress | Outbound used for geodata downloads |

## Startup downloads are reference-driven

meow-rs does not fetch databases unconditionally on boot. During the config build it
scans the rule set — top-level `rules:`, `sub-rules:` blocks, logic rules, and rule
provider payloads (inline and prefetched `file:`/`http:`) — plus the DNS side
(`geosite:` nameserver-policy keys and the fallback filter's geoip gate, both only when
`dns.enable: true`). Only a database the configuration actually references *and* that
is missing on disk is downloaded, before the parser context is built.

| Reference | Downloads when missing |
| --- | --- |
| `GEOIP` / `SRC-GEOIP` rules | Country MMDB |
| `fallback-filter.geoip` (DNS enabled + `fallback:` set, geoip not `false`) | Country MMDB |
| `IP-ASN` / `SRC-IP-ASN` rules | GeoLite2-ASN MMDB |
| `GEOSITE` rules, `geosite:` nameserver-policy keys | GeoSite DB |

A config with no geo references downloads nothing — a disabled `dns:` section
(`enable: false` or absent) contributes no references either, matching the resolver's
own early return.

## `geodata.proxy`

Downloads run through the outbound `geodata.proxy` names:

```yaml
geodata:
  proxy: hk-01          # a proxies: entry or a proxy-groups: name
```

- A proxy or group name routes the download through that adapter. Group names resolve
  as themselves — a `select` group uses your persisted (or first) choice, `url-test` /
  `fallback` probe at dial time.
- `DIRECT`, `REJECT`, `REJECT-DROP`, `COMPATIBLE`, `PASS`, `PASS-RULE`
  (case-insensitive) fetch directly — the full set of built-in adapter names a
  `proxies:`/`proxy-groups:` entry cannot shadow.
- Unset (or a blank/unknown name, which warns): the last top-level `MATCH,<target>`
  target — the config's default egress — then the first `proxies:` entry.
- If a proxied download's *connect phase* fails, the fetch retries once directly. This
  fallback is geodata-only: mid-chain (redirect) dial errors, TLS/HTTP/body errors, and
  every provider/subscription fetch never fall back.

## `geox-url` (mihomo alias)

mihomo's top-level `geox-url:` block is accepted as a flat alias for `geodata.url.*`:

```yaml
geox-url:
  mmdb: https://cdn.example.com/Country.mmdb
  asn: https://cdn.example.com/GeoLite2-ASN.mmdb
  geosite: https://cdn.example.com/geosite.dat
```

Precedence is per key: `geodata.url.*` beats `geox-url.*`, which beats the baked-in
CDN default — `geox-url` alone (no `geodata:` block) is enough. `geox-url.geoip` is
accepted and ignored with a warning: mihomo maps it to `geoip.dat`, which meow-rs has
no consumer for — put a GeoIP MMDB override under `geox-url.mmdb` or
`geodata.url.mmdb` instead.

## Discovery

When a path isn't given explicitly, meow-rs searches a standard chain:

```
$XDG_CONFIG_HOME/meow/<file>
$HOME/.config/meow/<file>
./meow/<file>
```

The `-d` / home directory flag also influences where resources are looked up.

The country database is found under any capitalisation of `Country.mmdb`, and `ASN.mmdb`
stands in for a missing `GeoLite2-ASN.mmdb`, so the copies a mihomo GUI such as Clash Party
puts in the home directory are used rather than downloaded again. A database meow-rs
downloads itself is saved as `Country.mmdb` / `GeoLite2-ASN.mmdb`.

## Auto-update

With `auto-update: true`, a background task re-downloads every `auto-update-interval`
hours and hot-reloads new data into memory — routing rules are rebuilt and the DNS
resolver is republished so `geosite:`/`rule-set:` nameserver-policy entries follow the
new generation. Failures are logged and retried next interval — they never crash the
process.

The loop refreshes only the databases the **startup** configuration references. The
referenced-set (`Config.geo_needs`) is a snapshot taken during the initial
`build_config` scan:

- `IP-ASN`/`SRC-IP-ASN` rules → the ASN MMDB.
- `GEOSITE` rules / `geosite:` policy keys → the GeoSite DB.
- The Country MMDB is never a tick target — country mappings change rarely, and
  skipping the refresh keeps the parser-built `CountryIndex` alive without churn.
  Replace `Country.mmdb` on disk and restart when you need a new GeoIP generation.

A `PUT /configs` that adds a geo reference does **not** widen the snapshot — the
auto-update set stays frozen at what the startup config used, matching the rebuild
path's own freeze on geo downloads. If all three flags are false the tick does no
work at all.

```yaml
geodata:
  auto-update: true
  auto-update-interval: 24
  url:
    mmdb: https://cdn.example.com/Country.mmdb
    asn: https://cdn.example.com/GeoLite2-ASN.mmdb
    geosite: https://cdn.example.com/geosite.dat
```

## Rule requirements

| Rule | Needs | If missing |
| --- | --- | --- |
| `GEOIP` / `SRC-GEOIP` | Country MMDB | Hard error at load |
| `IP-ASN` / `SRC-IP-ASN` | GeoLite2-ASN MMDB | Hard error at load |
| `GEOSITE` | GeoSite DB | Tolerated — the rule simply never matches |

GeoSite is intentionally lenient so configs that conditionally load it still parse. See
[Rules](./rules) for the matching semantics.
