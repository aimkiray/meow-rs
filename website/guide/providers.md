# Providers & Subscriptions

Providers let proxies and rules live **outside** your config — fetched from a URL or a
file, cached to disk, and optionally refreshed in the background. This is how you consume
airport subscriptions and shared rule sets.

## Proxy providers

`proxy-providers` is a map of named sources. A [proxy group](./proxy-groups) pulls members
from one via `use:`.

```yaml
proxy-providers:
  airport:
    type: http
    url: https://example.com/proxies.yaml
    path: ./providers/airport.yaml
    interval: 86400
    filter: "^(HK|JP)"
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300

proxy-groups:
  - name: Proxy
    type: select
    use: [airport]
```

### Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `type` | string | — | **Required.** `http` or `file` |
| `filter` | regex | — | Keep only proxies whose name matches |
| `exclude-filter` | regex | — | Drop proxies whose name matches |
| `exclude-type` | string \| list | `[]` | Drop proxy types, e.g. `[ss]` |
| `health-check` | block | — | Periodic probing (below) |
| `header` | map | `{}` | Extra HTTP request headers (`http` only) |
| `allow-external-plugin` | bool | `false` | Permit `ss` nodes to launch external SIP003 plugin executables. **Security-sensitive opt-in**: provider content is remote-controlled and the plugin name reaches `Command::new`, so off means such nodes are rejected. Built-in plugins (`obfs`, `simple-obfs`, `v2ray-plugin`, `gost-plugin`, `shadow-tls`, `restls`, `jls`, `kcptun`, `ech-tls-tunnel` — all in the default feature set) are always allowed; a non-default build without one treats its name as external. meow-rs extension; absent in mihomo |

### `type: http`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `url` | string | — | **Required.** Source URL |
| `path` | string | `provider_{name}.yaml` | Local cache (absolute or relative to config dir) |
| `interval` | u64 | `0` | Accepted for compatibility; proxy-provider payloads are not refreshed on a timer — refresh manually with `PUT /providers/proxies/{name}` or restart |

The cached file is the offline fallback: startup always fetches first and
writes the cache; the file is read only when that fetch fails.

### `type: file`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `path` | string | — | **Required.** Local YAML file of proxies |

### Health check

| Field | Type | Default |
| --- | --- | --- |
| `enable` | bool | `true` |
| `url` | string | `https://www.gstatic.com/generate_204` |
| `interval` | u64 | `300` |
| `timeout` | u64 (ms) | `5000` |
| `lazy` | bool | `false` |

## Rule providers

`rule-providers` supplies external rule sets, referenced from `rules` via
`RULE-SET,<name>,<target>`.

```yaml
rule-providers:
  gfw:
    type: http
    url: https://cdn.example.com/gfw.yaml
    path: ./rules/gfw.yaml
    behavior: domain
    format: yaml
    interval: 604800

rules:
  - RULE-SET,gfw,Proxy
  - MATCH,DIRECT
```

### Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `type` | string | — | **Required.** `http` · `file` · `inline` |
| `behavior` | string | — | **Required.** `domain` · `ipcidr` · `classical` |
| `format` | string | auto | `yaml` · `text` · `mrs` (auto-detected for http/file) |
| `interval` | u64 | `0` | Refresh seconds (ignored with a warning for `file`; rejected for `inline` — the provider fails to load, fatal under `strict: true`) |

`behavior` describes the payload: `domain` (domain list), `ipcidr` (CIDR list), or
`classical` (full `TYPE,payload` rule lines). `mrs` is the compiled binary format.

### `type: http` / `file`

- `http` — needs `url`; caches to `path` (default `rule-providers/{name}.yaml`).
- `file` — needs `path`; loaded from disk, no scheduled refresh (manual
  `PUT /providers/rules/{name}` re-reads the file).

### `type: inline`

Embed the rules directly:

```yaml
rule-providers:
  internal:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,internal.corp,Corporate
      - IP-CIDR,192.168.0.0/16,Corporate
```

`interval > 0` on an inline provider is rejected (nothing to refresh) — the
provider fails to load with a warning, and `RULE-SET` entries referencing it
warn-and-skip; under `strict: true` it is a hard config error.

Only HTTP **rule providers** with a non-zero `interval` are refreshed
automatically by a background task; proxy providers reload on manual
refresh (`PUT /providers/proxies/{name}` — a `file` provider re-reads its
file) or restart, and `inline` providers never refresh. The refresh tasks
are spawned once at startup from the providers configured then — a
rule-provider *added* later via `PUT /configs` gets no background task
(though a changed `interval` on an existing provider is picked up, since
each tick re-resolves the provider by name).

## Subscriptions

`subscriptions:` is the blunt instrument next to providers. `proxy-providers`
entries feed *nodes* into a named pool that groups pull from via `use:` —
local `proxies:` and `rules:` stay yours. A subscription instead **replaces the
whole `proxies:` / `proxy-groups:` / `rules:` sections** with the remote
document's contents, and the result is **written back to the config file**
on every successful refresh.

```yaml
subscriptions:
  - name: airport
    url: https://example.com/clash.yaml
    interval: 86400
```

See [Configuration — Subscriptions](./configuration#subscriptions) for the
full semantics (replace-not-merge, write-back, `-t` behaviour).

Subscriptions are also managed at runtime through the
[REST API](../reference/rest-api):

- `GET /api/subscriptions` — list, with the applied proxy/group/rule counts
  and last-updated times.
- `POST /api/subscriptions` — add `{ name, url, interval? }` and apply immediately.
- `POST /api/subscriptions/{name}/refresh` — re-fetch.
- `DELETE /api/subscriptions/{name}` — remove the entry **and empty all three
  sections** — previously-replaced local content is not restored. Note the
  delete itself saves, so `.bak` afterwards holds the *subscription-applied*
  file; the original local sections survive on disk only if no earlier
  write-back already rotated them out.
