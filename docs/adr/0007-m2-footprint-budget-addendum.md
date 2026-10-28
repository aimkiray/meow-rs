# ADR 0007 Addendum A — `ss` built-in SIP003 plugins split into per-plugin features

- Status: Accepted (addendum)
- Date: 2026-10-28
- Authors: aimkiray
- Amends: [ADR-0007](0007-m2-footprint-budget.md)
- Trigger: M2 footprint work — the `ss` feature pulled all four heavier
  built-in plugin transports into every `minimal` build even though
  ADR-0007 §1's minimal rationale only names the SS + `v2ray-plugin`
  story (`simple-obfs` ships inside `ss` as the second transport; the
  ADR itself does not name it).

## Context

`meow-proxy`'s `ss` feature used to enable every in-process SIP003 plugin
transport at once: `simple-obfs`/`obfs`, `v2ray-plugin`, `gost-plugin`,
`shadow-tls`, `restls`, `jls` (plus the already-separate `kcptun` and
`ech-tls-tunnel` features). The `minimal` bundle exists to satisfy the
ADR-0007 binary-size caps, and its `ss` contract only needs the two
transports that cover the dominant deployments — `simple-obfs` and
`v2ray-plugin`. Carrying `gost-plugin` (ws+TLS+smux), `shadow-tls`,
`restls` and `jls` (each a `meow-transport` layer plus its parser and
tests) in `minimal` spends size budget on plugins a minimal operator
never configures.

## Decision

The `ss` built-in-plugin contract narrows to `simple-obfs`/`obfs` +
`v2ray-plugin`. The four heavier built-in SIP003 transports become opt-in
cargo features — `gost-plugin`, `shadow-tls`, `restls`, `jls` — each
implying `ss` (and its `meow-transport` layer for the TLS ones), and each
re-bundled into `default`/`full` so release binaries are unchanged.

Disabled plugin names stay **reserved**: `is_builtin_sip003_plugin` lists
every built-in name unconditionally, and `ShadowsocksAdapter::new` answers
a compiled-out name with a clean `Config` error ("not compiled into this
build; rebuild with `--features <feat>`") instead of falling through to
the external `Plugin::start` subprocess path. `kcptun` and
`ech-tls-tunnel` get the same explicit error arm, closing their
pre-existing fallthrough (a disabled `kcptun`/`ech-tls-tunnel` used to
reach the external SIP003 spawn path).

## Consequences

- `minimal` (`ss` + `trojan` + `dns-server` + `listener-mixed`) no longer
  compiles the four plugin transports — a `plugin: gost-plugin` node in a
  minimal build fails config validation with the feature-named error.
- `default`/`full` feature sets are unchanged: every release binary keeps
  all built-in plugins, so the ADR-0007 default-build measurements carry
  over.
- CI feature-powerset jobs grow by the four new features' leg count —
  expected, no workflow change needed.
