# Changelog

All notable changes to meow-rs are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are mirrored onto the GitHub Release for each tag; this file is
the canonical, in-repo source a release is cut from.

## [Unreleased]

### Added

- **In-process `gost-plugin` for Shadowsocks** — `plugin: gost-plugin` now
  runs natively instead of spawning a SIP003 subprocess, matching mihomo's
  built-in: TCP → optional TLS (ALPN `http/1.1`, SNI from `host` or a `Host`
  header override) → WebSocket → optional smux v1 session (`mux` defaults
  to `true` upstream; one session per connection, stream close tears it
  down). The full option surface is supported — `mode` (required,
  `websocket`), `host` (default `bing.com`), `path`, `tls`, `mux`,
  `headers`, `skip-cert-verify`, `name-cert-verify`, `fingerprint`
  (SHA-256 certificate pin — `TlsConfig::cert_pin` replaces CA
  verification, matching upstream SSL pinning), `certificate`/`private-key`
  (mTLS; inline PEM or file path — upstream's file-watch reload is not
  mirrored), and `ech-opts.enable` + `ech-opts.config` (inline
  ECHConfigList, bounded to the u16 wire limit; DNS-queried ECH is not
  supported and errors clearly). `name-cert-verify` is wired through a new
  `TlsConfig::verify_name` — the certificate is verified against it while
  the wire SNI stays `host`. Nested `plugin-opts` maps now flatten
  correctly for all plugins (`headers` → repeated `header=K:V`, other maps
  → `key.sub=value`). `mux` requires the `mux` cargo feature; builds
  without it reject `mux=true` at parse time. (#533)

- **In-process `shadow-tls` for Shadowsocks** — `plugin: shadow-tls` now
  runs natively (mihomo `transport/sing-shadowtls` parity) instead of
  spawning a SIP003 subprocess. All three protocol versions are
  supported: v1 (TLS 1.2 cover handshake then plaintext), v2 (8-byte
  HMAC-SHA1 transcript tag on the first framed record), and v3
  (ClientHello `legacy_session_id` authentication + XOR-swizzled cover
  records with embedded rolling HMACs). Options mirror upstream:
  `host` (required cover SNI), `password`, `version` (required — 1, 2
  or 3; upstream has no default),
  `alpn` (default `h2,http/1.1` — YAML list values flatten),
  `skip-cert-verify`, `name-cert-verify` (`TlsConfig::verify_name`),
  `fingerprint` (SHA-256 certificate pin), `certificate`/`private-key`
  (mTLS, PEM or path), and the node-level `client-fingerprint` uTLS
  shaping. Two deliberate divergences from upstream, both forced by
  BoringSSL lacking uTLS's `SessionIDGenerator` hook: the v3 cover
  handshake always ends in an expected transcript-mismatch failure that
  is recovered from after the shim has verified a swizzled cover record
  (TLS 1.2 covers still run real certificate verification before the
  failure; TLS 1.3 covers cannot be cert-verified at all — the post-
  ServerHello flight is undecryptable under the diverged transcript, so
  `skip-cert-verify`/`fingerprint` have no effect there), and the cover
  session is torn down quietly rather than completed. (#533)

- **In-process `restls` for Shadowsocks** — `plugin: restls` now runs
  natively (mihomo `transport/restls` parity). Because restls commits its
  BLAKE3 authentication tag into the TLS `session_id` — part of the
  handshake transcript — no generic TLS stack can speak it; the client is
  implemented at the record level in `meow-transport` (the pattern
  established by `reality_tls`), driving real TLS 1.3 *and* TLS 1.2
  handshakes with full certificate-chain, hostname, CertificateVerify and
  optional SHA-256-pin verification. After the handshake the cover's
  first encrypted record is unmasked to detect a restls relay; a plain
  cover falls back to transparent TLS automatically. Data then travels in
  script-shaped tagged records with per-direction BLAKE3 MACs and rolling
  counters (`250?100<1,350~100<1,600~100,300~200,300~100` by default).
  Options mirror upstream: `host`, `password` and `version-hint`
  (`tls12`/`tls13`) are required, `restls-script`, `skip-cert-verify`,
  `name-cert-verify` and `fingerprint` (SHA-256 certificate pin) are
  supported; the upstream `force-tls12` test knob maps to the `tls12`
  path. UDP relay is unsupported, matching upstream. (#533)

- **In-process `jls` for Shadowsocks** — `plugin: jls` now runs natively
  (mihomo `transport/jls` / `metacubex/jls-tls` parity). jls authenticates
  inside a genuine TLS 1.3 handshake: `ClientHello.random` is replaced by
  a 16-byte seed sealed with AES-256-GCM under
  `SHA-256(password ‖ authData)` / nonce `SHA-256(username ‖ authData)`,
  where `authData` is the serialized hello with `random` zeroed, and the
  server answers with the same construction in `ServerHello.random`. No
  generic TLS stack can control those fields, so the client is driven at
  the record level on the shared TLS 1.3 machinery introduced for restls.
  When the server's random authenticates, certificate-chain and
  CertificateVerify checks are skipped exactly as upstream (the
  camouflage certificate is a throwaway); when it does not, the full
  checks run against `host` — an unauthenticated jls server relays to a
  real cover, so the handshake completes and is then rejected
  (`ErrJLSAuthFailed` parity). Post-handshake traffic is plain TLS
  application records — no tagging, masking, or script — with KeyUpdate
  rotation and `close_notify` handled. Options mirror upstream: `host`,
  `username` and `password` are required, `alpn` defaults to
  `h2,http/1.1`; there is no `skip-cert-verify` because jls's
  authentication *is* the certificate check. UDP relay is unsupported,
  matching upstream. (#533)

- **In-process `kcptun` for Shadowsocks** — `plugin: kcptun` now runs
  natively (kcptun/kcp-go wire parity). The transport lives in
  `meow-transport` as a poll-driven `KcpStream` (ARQ over UDP on the
  zonyitoo `kcp` core) plus the kcp-go-compatible crypt envelope
  (`none`/`xor`/`salsa20`/CFB ciphers/`aes-128-gcm`, PBKDF2-HMAC-SHA1
  KDF), Reed-Solomon FEC with peer auto-tuning, and optional snappy
  stream compression. `meow-proxy` adds the SIP003 option parser, a
  pooled session layer (round-robin `conn` KCP sessions with lazy
  `autoexpire` reuse expiry; `scavengettl` is parsed but is a no-op —
  client-side linger does not apply) over in-tree smux v1 with
  keepalive NOPs and `frameSize`/`smuxbuf`/`streambuf` sizing, and
  upstream-compatible UDP relay: UDP datagrams travel as
  UDP-over-TCP records (`sp.udp-over-tcp.arpa:0`, length-prefixed)
  through a pooled smux stream. The KCP socket goes through
  `dial_udp_endpoint`, so `dialer-proxy` chains tunnel the datagrams
  instead of leaking raw UDP. Options mirror upstream kcptun
  (`key`/`crypt`/`mode`/`conn`/`autoexpire`/`scavengettl`/`mtu`/
  `ratelimit`/`sndwnd`/`rcvwnd`/`datashard`/`parityshard`/`dscp`/
  `nocomp`/`nodelay`/`interval`/`resend`/`nc`/`sockbuf`/`smuxver`/
  `smuxbuf`/`streambuf`/`framesize`/`keepalive`/`acknodelay`), and only
  `smuxver=1` is supported, matching our smux layer. The KCP core is a
  vendored `kcp` crate reworked to `kcp-go` v5.6.72 retransmission/Input
  semantics (immediate flush on window slide or fast-retransmit, ACK
  clocking, `acknodelay`, linear RTO backoff, FEC-aware RTT/window
  filtering). The feature is in the `full` bundle and excluded from
  `minimal` (cipher/FEC/snappy dependency weight). One operational
  note: `KcpStream` progress is poll-driven — retransmits and
  dead-link detection advance while the stream is polled, which the
  smux session reader guarantees for pooled sessions. (#533)
- **Opt-in `strict: true` config mode** — by default an entry that fails
  to parse (a `proxies:` node, a `proxy-groups:` block, a `rules:` line,
  a `proxy-providers:`/`rule-providers:` definition, or a node inside a
  provider payload) is logged and skipped so one bad line cannot take
  down the whole config. `strict: true` promotes every such skip to a
  hard load-time error — plus group members/`use:` names that resolve to
  nothing, entries shadowing built-in adapter names, and malformed
  `dialer-proxy` values. Applies on startup and on `PUT /configs`
  rebuilds of those sections; `proxy-providers:` definitions whose
  identity changed are re-validated on rebuild while unchanged defs are
  reused, and their initial *fetch* stays deferred to commit time. It
  is opt-in because it
  rejects real-world mihomo subscriptions that mix in node types meow-rs
  does not support; provider *fetch* failures stay lenient (a transient
  download error starts the provider empty rather than failing the
  config). Also fixes a pre-existing hole where a dropped
  built-in-shadowing `proxies:` entry could still chain the built-in
  adapter via its `dialer-proxy` field. Public API signatures changed:
  `parse_rules_full`, `ProxyProvider::new`, `load_proxy_providers`, and
  `rule_provider::load_providers_prefetched`. (#533)

### Changed

- **`AppState::config_mutation_lock` was removed** — the per-state mutex
  serialised only `swap_config_and_reconcile_tun`, whose every caller
  already holds the process-global `CONFIG_MUTATION` lane. The nested
  lock added no exclusion; the lane is now the sole serialisation of the
  read-old → write-new → TUN/DNS-reconcile sequence (issue #543).
  Embedders constructing `AppState` literals drop the field.
  `POST /api/config/save` now holds the lane too, so a save cannot
  snapshot mid-commit state (e.g. a `tun.enable` the runtime is about
  to roll back).

- **BoringSSL is now the only crypto library; rustls is gone from the runtime.**
  Two changes land together. First, every TLS handshake moved off rustls onto
  BoringSSL (`meow_transport::tls::TlsLayer`): proxy handshakes (Trojan, VLESS,
  VMess, HTTP/SOCKS5-over-TLS, SS plugins, ECH tunnel, AnyTLS), URL-test health
  probes, DoT/DoH upstreams, and every internal HTTP(S) fetch (`reqwest`
  removed; the in-tree client gained direct dialing through the host
  resolver/`SocketProtector` hooks, custom headers, and a Content-Length
  precheck). Second, the **Hysteria2 outbound was ported from quinn (rustls) to
  quiche**, Cloudflare's BoringSSL-native QUIC + HTTP/3 stack, using quiche's
  `boringssl-boring-crate` feature so it links the SAME vendored BoringSSL as
  the TLS layer. rustls, tokio-rustls, quinn, h3, h3-quinn, reqwest,
  and webpki-roots are no longer runtime dependencies; rustls remains only as a
  dev-dependency for the loopback TLS test servers.
  **Build change:** `boring`, `tokio-boring` and `boring-sys` move together
  through the workspace table (5.2 as of #572; quiche 0.30 accepts
  `boring >=4.19,<6`) so that quiche and meow-transport share one
  `links = "boringssl"` copy; `boring-sys` (cmake + a C++ compiler) is a hard
  build requirement on every target. The `boring-tls`/`ech` features are
  no-op aliases. The Hysteria2 quiche client is a single driver task that
  bridges quiche's synchronous state machine to the async `DuplexStream` (TCP)
  and `UdpSession` (UDP datagrams) with real QUIC-flow-control backpressure;
  Salamander obfs and port-hopping are applied on the driver's own UDP socket.
  Observable runtime differences: BoringSSL's default ClientHello replaces
  rustls' for proxies without `client-fingerprint`; TLS session resumption is
  per BoringSSL `SSL_CTX` (64-entry cache); the QUIC ClientHello is now quiche's.

- **boring/tokio-boring 4.22 → 5.2 and quiche 0.29 → 0.30.** quiche 0.30
  accepts `boring >=4.19,<6`, which unblocks the 5.x line the workspace had
  been waiting on. One observable difference, from the newer vendored
  BoringSSL: the *default* ClientHello — every handshake without a
  `client-fingerprint`, including DoT/DoH and the Hysteria2 QUIC handshake —
  now advertises a post-quantum key share (`X25519MLKEM768`), which makes it
  about 1.2 KiB larger and can split the QUIC Initial across two packets
  (verified against Hysteria 2.9.2). Named fingerprint profiles pin their
  curve list explicitly, so their ClientHello and the JA3 pins in
  `boring_tls_test` are unchanged. The 4.x-era `TolerantFlushStream` flush
  workaround is removed (see the #569 entry under Fixed). (#572)

- **lru 0.16 → 0.18.4.** Clears RUSTSEC-2026-0253 (`LruCache::pop()` not
  panic-safe, fixed in 0.18.2). Not reachable here — the release profile is
  `panic = "abort"` and the DNS cache / fake-IP keys (`Arc<str>`, `SmolStr`,
  `IpAddr`) have no panicking `Drop` — so no behaviour change; the lock loses
  its last `hashbrown` 0.16 copy (lru now shares the existing 0.17).

- **`ipv6` is now effective end-to-end and keeps the `false` default.** The
  `ipv6` flag previously only gated a handful of code paths — the resolver
  queried A and AAAA regardless — so the documented `false` default and
  `GET /configs` disagreed with the actual runtime behaviour. The flag now
  drives the whole resolution pipeline: with `ipv6: false` (the default,
  matching mihomo/Clash) AAAA lookups are skipped and the resolver answers
  IPv4-only; with `ipv6: true` dual-stack domains are queried for both A and
  AAAA (concurrently, with IPv4 tried first as a connection fallback) and
  `DirectAdapter` can fall back to IPv6 when IPv4 connectivity fails. The
  default literal is now centralized in `meow_config::effective_ipv6`
  (previously scattered across six `unwrap_or(...)` sites), and the parser,
  `GET /configs`, and `website/guide/configuration.md` all agree on `false`.
  **Operators who relied on the old always-dual-stack behaviour of an
  omitted `ipv6` key must now set `ipv6: true` explicitly.**

- DNS dual-stack resolution (`resolve_ips` / `lookup_ip_with_ipv6_inner`) now
  queries A and AAAA **concurrently** when IPv6 is enabled, collecting both
  address families with IPv4 ordered first. `DirectAdapter::dial_tcp` iterates
  the full address list, so an IPv4 connect failure no longer discards the IPv6
  candidate — IPv6 remains a connection fallback.

- **CI and local builds share a pinned toolchain.** `rust-toolchain.toml`
  pins channel 1.98.1 (with `rustfmt`/`clippy`), so every cargo invocation
  in the checkout — CI steps and local runs alike — resolves the same
  rustc/clippy/rustfmt; a floating `@stable` can no longer fail CI on lints
  that do not exist yet locally. Jobs needing a different toolchain opt out
  explicitly — MSRV via a directory `rustup override` (it stays on
  `rust-version`), the drift canary via `RUSTUP_TOOLCHAIN` — and
  cross-target / llvm-tools jobs now attach components to the pinned
  channel. A weekly
  `toolchain-drift` workflow runs the lint gate on floating `stable` as an
  early-warning canary for the next pin bump. (#533)

- **The `subscriptions:` config key is documented.** The guide now covers
  its wholesale-replace of `proxies:`/`proxy-groups:`/`rules:`, the config
  write-back on every successful refresh, the `-t`-doesn't-fetch boundary,
  and a providers.md contrast note against `use:` provider pools. The
  proxy-provider `interval` field is also corrected: no scheduled refresh
  exists for proxy providers. (#533)

### Fixed

- **Provider-sourced group members are now health-checked** (#543 item 1,
  #555). The periodic sweep and `GET /group/{name}/delay` resolved
  `group.members()` names through the route table, where `use:` /
  `include-all` provider members are not keys, so a `use:`-only
  `url-test` / `fallback` group woke every interval to probe nothing,
  never became `alive`, and the delay endpoint returned `{}` for it. The
  `Proxy` trait gains `member_proxies()`, which every group implements
  over its static members *and* provider slots; both callers probe
  through it. Providers have no scheduled check of their own yet.

- **`RULE-SET` rules now see refreshed rule-provider content without a
  config rebuild** (#553). The rule parser received a snapshot `Arc` of
  each provider's set, so a periodic refresh or `PUT /providers/rules/{name}`
  logged "refreshed: N rules" and bumped `updated_at` while live traffic
  kept matching the startup payload until the next `PUT /configs` or
  restart. `RuleProvider` now implements `RuleSet` by reading through its
  lock, and the parser map (`rule_provider::live_ruleset_map`, replacing
  `snapshot_ruleset_map`) hands rules the provider itself; the DNS
  `nameserver-policy` `rule-set:` matcher reads through the same way
  instead of cloning a snapshot per query. Providers rebuilt by a config
  reload still bypass the API registry (#543 item 2).

- **HTTP/2 transports (gRPC, h2, xhttp) and the h2mux multiplexer now
  advertise 4 MiB per-stream / 16 MiB per-connection receive windows.**
  Every client handshake used h2's defaults, so the download direction of a
  gRPC / h2 / xhttp / h2mux stream stalled every 64 KiB waiting for a
  WINDOW_UPDATE round-trip — a throughput ceiling of roughly 64 KiB per RTT
  (#495 item 12). The windows now match Go's `http2.Transport` defaults,
  which is what mihomo's gun / h2 clients and sing-mux's h2mux client
  advertise; the upload direction is unchanged (bounded by the server's
  window). Per-stream memory stays bounded by the 4 MiB window because
  every read still releases capacity chunk by chunk.

- **Built-in dashboard Overview loads with live traffic streaming.** Consume
  `/traffic` through one reconnecting WebSocket instead of waiting for an
  endless HTTP JSON response. Mode, listeners, and connections load
  independently; changing the API secret refreshes authentication. Add
  dashboard browser and lifecycle regression tests to CI.

- **A deleted subscription's payload could resurrect on a raced
  refresh.** `POST /api/subscriptions/{name}/refresh` and the scheduled
  refresh loop both resolve the URL and fetch before taking the mutation
  lane; if the subscription was deleted meanwhile, the fetched
  proxies/groups/rules were committed unconditionally. The endpoint now
  re-verifies the subscription exists inside the lane and returns 404
  otherwise (409 if the same-name entry was re-added with a different
  URL), and the loop discards the payload on the same recheck. The
  loop also keeps the lane through its disk save so the file's last
  writer follows commit order (issue #543).
- **Concurrent config saves could publish a torn file.** Every writer
  shared the same `{path}.tmp` scratch name, so one save's
  create+truncate could land inside another's `write_all` and the
  victim's `rename` would publish the mixed file. Saves now use a
  unique scratch name per call, and the scratch is swept when the write
  or rename fails so repeated failures can't fill the config dir.
  The same fixed-scratch splice affected rule-provider cache writes
  (`{name}.tmp`), proxy-provider cache writes (not even atomic),
  selector-store persistence (`{path}.json.tmp`), fake-IP snapshots,
  and geodata downloads (`with_extension("tmp")`, which also collided
  for same-stem targets like `Country.mmdb`/`Country.yaml`) — all now
  write through unique per-call scratch names (issue #543).

- **AnyTLS UDP-over-TCP reads poison the conn on an incomplete frame**
  (feature `anytls`). `AnytlsPacketConn::read_packet` consumed the uot
  address + length + payload incrementally under the stream's reader
  mutex — a dropped/cancelled read released the lock mid-datagram and
  every later read silently parsed payload bytes as frame headers, the
  same desync class the trojan/vless poison fixed in #545. The shared
  `PoisonOnIncomplete`/`check_not_desynced` pair now covers `read_packet`
  (with the write side fail-fasting on an already-desynced conn, since
  each anytls write is one atomic frame enqueue and cannot itself tear
  framing) (issue #543).

- **A bare `Fin` before `SynAck` no longer hangs the anytls dial**
  (feature `anytls`). `Session::handle_frame`'s Fin arm evicted the
  stream from `streams`/`stream_receive_tx` but never notified the
  pending synack-waiter — the client keeps `Arc<Stream>` so `synack_tx`
  stayed alive and `synack_rx` pended with no wake of its own (internal
  bound 30 s; the 5 s dial deadline surfaced first). A server that FINs
  instead of SynAck-erroring a refused stream now marks it closed
  locally and wakes the waiter immediately with `StreamClosed`,
  producing a clean dial error (issue #543). The outbound-Fin eviction
  in `process_stream_data` now notifies symmetrically — `open_stream`
  is pub, so an out-of-tree caller can hold a live waiter across a
  local close — and runs after the writer's `select!` so a racing
  session close can no longer drop it mid-eviction. A `SynAck` carrying
  an error payload now evicts and closes the stream too, so callers
  that dropped the receiver no longer leak map entries.

- **Scheduled subscription refreshes no longer reset `select` group
  choices or drop provider-backed group members.** The refresh loop
  rebuilt each fetched candidate with `rebuild_from_raw_with_resolver`,
  which wires no `SelectorStore` — every `select` group in the committed
  config fell back to its first member on each refresh, discarding the
  user's persisted pick until a manual reload rebuilt through the API
  path. `use:`/`include-all` groups now also resolve against the live
  provider registry, keeping provider slot, health, and fetched state
  instead of a detached empty map. The loop now rebuilds via
  `rebuild_from_raw_runtime`, matching `PUT /configs` (issue #543).

- **Geodata DB refreshes now republish the resolver.** When the
  ASN/geosite DB files were replaced on disk, the geodata paths rebuilt
  routing but left the running resolver's `geosite:` nameserver-policy
  matchers bound to the DB generation captured at DNS publish time — a
  `geosite:`-only policy was never republished at all (the
  PUT-vs-candidate input diff does not count geosite keys), and a
  `rule-set:` policy only republished when an unrelated `PUT /configs`
  triggered it. Both geodata commit paths (startup-fetch and the
  periodic auto-update loop) now reparse and republish the resolver
  inside the mutation lane, binding the same live rule-provider map the
  rebuilt rules use (issue #543). The FFI-visible
  `geodata_fetch::run_on_startup` / `auto_update_loop` signatures gain a
  `dns_server` handle parameter for this.

- **`lazy` proxy groups no longer count housekeeping traffic as use.** A
  `lazy` group is only probed after real traffic uses it, but the marker
  distinguishing probe dials (`ConnType::Tunnel`) did not survive two
  internal paths: `dialer-proxy` chained dials rebuilt metadata as
  `ConnType::Inner`, and provider/geodata downloads plus DNS-via-proxy
  exchanges constructed `Inner`/`Http` metadata directly —
  so a `lazy` group referenced as a node's `dialer-proxy` or used for
  downloads was probed every interval forever, silently degrading `lazy`
  to eager. `Metadata` now carries an `internal` flag for housekeeping
  traffic; `TcpDialer::dial`/`dial_addr` take it from the caller's
  metadata and `ProxyDialer` copies it onto the reconstructed metadata
  (as does the relay chain's next-hop rebuild), the internal HTTP fetcher
  and the DNS proxy exchange set it at construction, and group usage
  accounting skips both it and the existing
  `Tunnel` marker via `Metadata::is_internal()`. Mux session-establishment
  dials deliberately stay user-classed — a shared mux conn exists to
  serve user streams regardless of which dial triggered it — and pooled
  kcptun session establishment follows the same rule: it is the only
  dial signal a lazy front hop sees for that chain.

- **Relay groups can now terminate on real protocol adapters, not just
  `http`/`socks5`/`snell`.** Every hop after the first runs
  `ProxyAdapter::connect_over`, which previously only `direct`, `reject`,
  `http`, `socks5`, and `snell` implemented — a `relay` chain ending on a
  `vless`/`vmess`/`trojan`/`anytls`/`ss` node failed at hop 1 with
  `connect_over not supported`. `connect_over` now means the adapter's full
  post-connect pipeline over the passed stream — its own TLS/WS/obfs stack
  to its own server, then the protocol handshake (mihomo
  `DialContextWithDialer` semantics) — and is implemented by `vless`,
  `vmess`, `trojan`, `shadowsocks`, and `anytls` on top of the existing
  five. Two latent bugs surfaced and were fixed along the way:
  `http`/`socks5` `connect_over` silently skipped the adapter's own TLS
  layer, so a `tls: true` node in a non-first position sent a plaintext
  handshake to a TLS endpoint; and `RelayGroup::connect_over` did not
  resolve group members, so a nested relay holding a selector hit
  `NotSupported` on the group instead of running the selected leaf.
  Nested `relay` groups are now *flattened* into the outer chain at any
  position — the preceding hop dials the inner chain's entry point
  (previously a group member at a non-first position yielded `""`/`0`
  target metadata for the preceding hop). A `dialer-proxy` member whose
  inner outbound is itself a `relay` group is spliced the same way — the
  enclosing chain already defines the path, so the per-outbound dialer is
  not applied again. Expansion deeper than 16 fails the dial outright
  rather than retaining an unexpanded group mid-chain (config resolution
  already guarantees the group graph is acyclic; the bound stops
  pathological hand-built graphs). Hops with an empty
  `addr()` (REJECT, unresolvable groups) are skipped for metadata but
  still run their own `connect_over` so failures stay correctly
  attributed. Boundaries: `hysteria2` stays first-hop-only (QUIC cannot ride a TCP
  stream), `ss` with an external SIP003 plugin fails loudly (the subprocess
  owns its outbound leg), and mux pooling is bypassed on relay hops because
  a relay-supplied stream is single-use. The same fix makes `dialer-proxy`
  work for `anytls`, which previously fell back to the relay wrapper and
  still failed. (#570)

- **The `dialer-proxy` by-name registry no longer pins every superseded
  route generation.** Chained adapters held a strong `Arc` back to their
  build's registry, closing a `registry → proxy map → adapter → registry`
  reference cycle: each config reload leaked the entire previous proxy map
  for the life of the process. The registry cell is now held weakly by the
  adapters and owned per generation by the route table (plus a keepalive in
  rule-provider fetch contexts and the startup `Config`), so a replaced
  generation is freed once its last owner drops — and a chained adapter that
  outlives its generation fails closed instead of silently dialing direct.
  Because a DNS `#name` nameserver snapshots adapters at resolver-build
  time, the resolver is now rebuilt on every API commit / subscription
  refresh whenever either the old or candidate config uses proxy tags — the
  only way to keep its chained upstreams bound to a live generation.
  (#533)

- **Startup prefetch no longer bypasses `dialer-proxy` chains.** The
  pre-registry rule-provider payload prefetch and `ensure_geodata`'s
  download proxy were built by re-parsing raw `proxies:` entries — a
  provider fetch through a chained node egressed without its front hop.
  Both now share one pre-registry proxy layer built by the same code path
  as the runtime map — `dialer-proxy` chains, groups, and GLOBAL included —
  published into a private registry cell for the fetch's duration, so a
  chained or group front hop resolves exactly as it will at runtime. A
  rejected layer aborts the build before any fetch can egress — the same
  validation error the real build would report — and a `proxy:` name the
  layer cannot resolve is skipped and retried against the full registry
  rather than egressing unchained. (#533)

- **`load-balance` groups now balance provider members.** `use:` /
  `include-all` on a `load-balance` group were parsed but dropped with a
  warning — only static `proxies:` entries were balanced, and a
  provider-only group built empty so every dial failed. The group now
  carries the same live `ProviderSlot` set as selector/url-test/fallback:
  provider members join the pick space (statics first, then slot order)
  for both round-robin and consistent-hashing, a provider refresh is
  visible to the next selection without a config reload, and `members()`,
  `alive`, `support_udp`, and delay reporting all see the combined set.
  Load-balance also gains the dial-failure escalation its siblings already
  had: a member that keeps failing dials is marked dead between sweeps,
  complementing the periodic sweep, which probes provider members too via
  `member_proxies()`. (#533)

- **Lazy rule matching no longer warns twice for the same missing
  target.** The two-phase lazy matcher warned inline when a matched rule
  named a missing/dead adapter; when a later rule then demanded IP or
  process enrichment (`NeedsEnrichment`), the strict re-scan warned the
  same match again — two identical warnings per connection. Phase one now
  buffers missing-target matches and emits them only when it reaches a
  final outcome (`Matched`/`NoMatch`); on `NeedsEnrichment` the buffer is
  dropped because the deterministic strict re-scan re-fires each skip
  exactly once. Strict `match_rules` behaviour is unchanged; the buffer
  keeps up to two skips inline, so a dead-target match stays
  allocation-free in the common case. (#533)

- **`PASS`, `PASS-RULE` and `COMPATIBLE` now exist as real built-ins and
  the match loop honours their upstream semantics.** Rules targeting
  `PASS` — or a group whose `unwrap_proxy` chain contains it — are skipped
  silently (mihomo's `continue GetRules`), and inner rules inside a
  `sub-rules:` block resolving to `PASS-RULE` (by name or by adapter type,
  upstream's `CheckPassRule`) skip to the next inner rule. Top-level
  `PASS-RULE` behaves like `REJECT`, and `COMPATIBLE` dials direct while
  carrying its own adapter type, matching upstream. `PASS`, `PASS-RULE`,
  `COMPATIBLE`, and `REJECT-DROP` are filtered out of the auto-created
  `GLOBAL` member list (only DIRECT, REJECT, and user entries seed it);
  `COMPATIBLE` remains usable as a rule target and group member. To support
  side-effect-free chain probing, `ProxyAdapter::unwrap_proxy` gained a
  `touch` flag (upstream `Unwrap(metadata, touch)` parity): `false` peeks
  without advancing round-robin counters or recording usage stats.
  `Rule::match_and_resolve` now takes a `&dyn TargetProbe` — a plain
  `Fn(&str) -> bool` closure still satisfies it (`true` → usable, `false`
  → missing-and-warned). Both are breaking trait changes for external
  implementers. (#533)

- **TLS handshakes no longer fail on multiplexed transports whose
  `poll_flush` pends.** Every TLS-over-mux handshake — AnyTLS, smux, and any
  stream whose `poll_flush` waits on a writer-task acknowledgement — died at
  the first `BIO_flush` with the misleading "TLS handshake failed operation
  would block". tokio-boring's BIO bridge turns `Poll::Pending` into
  `ErrorKind::WouldBlock`, and boring 4.22.0's `BIO_CTRL_FLUSH` handler stored
  the error but never called `BIO_set_retry_write`, so `SSL_get_error` mapped
  a routine retry to fatal `SSL_ERROR_SYSCALL`. Upstream fixed this in
  cloudflare/boring@ed76885, which only the 5.x line ships: #571 first
  carried an in-tree wrapper that reported a pending flush as complete, and
  #572 replaced it with the upstream fix by moving the workspace to boring
  5.2 (quiche 0.30 lifted the `boring < 5` constraint). HTTPS
  URL-test probes over AnyTLS/smux recover (visible symptom: url-test groups
  with `https://` URLs reported nearly all mux members dead while the same
  nodes carried real traffic fine). Regression test:
  `d1_tls_handshake_over_pending_flush_stream`. (#569, #571, #572)

- **Provider `header:` maps now accept mihomo's list form, and rule-providers
  honor `header:` at all.** mihomo types provider headers as
  `map[string][]string`, but meow-rs typed `proxy-providers` `header` as
  `map[string]string`, so a mihomo-style config failed to load with
  `invalid type: sequence, expected a string`; rule providers had no
  `header` key and silently ignored one. Both provider kinds now accept the
  list form (single-string values keep working for meow-rs-legacy configs)
  and send multi-value headers as repeated field lines (RFC 9110 §5.2; meow
  emits every list value, whereas Go's HTTP/1.1 writer special-cases
  `User-Agent` to its first value). Headers apply to rule-provider initial
  load, prefetch, and periodic refresh, and to proxy-provider load (a
  proxy-provider `interval` is parsed but not scheduled, so those providers
  have no periodic refresh yet). A user-supplied `User-Agent` replaces the
  built-in default instead of duplicating it, and reserved/framing header
  names (`Host`, `Connection`, `Content-Length`, `Accept-Encoding`, and the
  rest of the hop-by-hop set) are dropped at emission rather than written,
  mirroring Go `net/http`'s `reqWriteExcludeHeader` — a second `Host:` or
  `Content-Length:` line is a request-smuggling primitive
  (mihomo parity: `component/http/http.go`). Header field names and values
  are validated per RFC 9110 (token-only names, CTL-free values) rather
  than only checking CR/LF/colon, so padded names like `Host ` / ` Host` /
  `Host\t` — which could dodge the reserved-name match and be normalized by
  tolerant intermediaries into a duplicate `Host:` line — are now rejected
  instead of emitted. Note: non-string header values
  (e.g. `header: {X: 123}`) were previously coerced to `"123"` on API-pushed
  configs and are now rejected, matching mihomo.

- **`load-balance` groups are now health-checked, so `url`, `interval`, and
  `lazy` take effect.** A `load-balance` group accepted these fields but never
  ran a health check, so it could keep routing to a dead member. It now joins
  the same periodic sweep as `url-test`/`fallback`: members are probed every
  `interval` seconds (default 300; `0` disables the sweep) against `url`
  (default `https://www.gstatic.com/generate_204`), and `lazy: true` defers
  probing until the group next carries traffic. Two known divergences from
  mihomo remain and are tracked in #555: `lazy` still defaults to `false`
  (upstream `true`, shared with `url-test`/`fallback`), and `select`/`relay`
  members are still not swept. (`use:` / `include-all` provider members were
  ignored with a warning when this landed; they now balance — see the
  provider-members entry above.) See #485.

- Proxy groups declared before their nested groups now retain those forward
  references even when either group also names a missing proxy.

- **Shadowsocks AEAD-2022 UDP now interoperates in both directions**
  (#566). Both the inbound listener and the outbound adapter previously ran
  with an all-zero `UdpSocketControlData`: inbound replies echoed
  `client_session_id = 0` with a zero server session ID (strict clients like
  sing-box reject them), and every outbound datagram repeated
  `client_session_id = 0`/`packet_id = 0`, so a conforming ssserver's replay
  filter dropped everything after the first packet. Inbound relay sessions
  are now keyed by `client_session_id` (SIP022 §3.2.4, matching ssserver's
  `NatKey::SessionId`) with a random non-zero server session ID, a
  session-wide reply packet counter shared across flows, and a per-session
  client packet-ID replay window; outbound associations mint a random client
  session ID, count packet IDs up, and filter replies through
  per-server-session windows. The inbound session table shares the
  listener's `max-connections` bound and retains each session for the spec's
  60-second minimum measured from its last datagram, independent of flow
  liveness; both packet-ID counters are checked (32-bit targets terminate
  the association rather than wrapping), and the outbound reply tracker
  evicts single least-recently-used windows instead of clearing the table.
  Reply headers now carry the responder's real socket address, and malformed
  reply datagrams are dropped per-packet instead of killing the association.

- Hysteria2 authentication no longer advertises HTTP/3 datagrams, preventing
  the server's HTTP/3 receiver from consuming raw QUIC UDP relay packets.
  The TProxy test image now includes the mandatory BoringSSL build toolchain.
- Internal HTTP downloads strip authentication and cookie headers when a
  redirect changes origin, and reject bodies that do not match Content-Length
  before replacing provider caches.
- Hysteria2 bounds queued TCP writes by bytes, retries exhausted QUIC stream
  limits without discarding requests, and propagates terminal stream errors.
  Restored idle keepalive and the remote response wait for `fast-open: false`;
  cancelling authentication or dropping a client releases its driver socket.
- **Auto-created `GLOBAL` selectors now default to the config's primary
  outbound.** Global mode always dispatches through `GLOBAL`, but the implicit
  selector previously sorted every registry key and used the first one when no
  choice was stored. That made global mode silently select `DIRECT` or route
  through an alphabetically-first quota/expiry pseudo-node. The generated
  selector still lists every proxy for mihomo-compatible dashboards, while its
  first member is now the final valid `MATCH` target, falling back to the first
  declared group or leaf proxy. Explicit user-defined `GLOBAL` groups remain
  unchanged.
- **AnyTLS UDP no longer deadlocks against sing-box/mihomo inbounds**
  (#535). sing-box reads the udp-over-tcp request before reporting handshake
  success, so the stream SYNACK is gated on the request arriving — while the
  client waited for SYNACK first and only sent the request lazily with the
  first datagram, leaving both sides waiting until the dial timed out. The
  UoT request is now flushed on the stream-open path, ahead of the SYNACK
  wait (`Client::create_proxy_stream_with_payload`); ordinary TCP streams
  and the vendored server's unconditional-SYNACK shape are unchanged. The
  same ordering fix was applied to the vendored `Client::create_udp_proxy`
  for consistency.

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

- **`GET /configs` reports the same `ipv6` default the runtime uses.** The API
  previously reported `ipv6: false` for an unset config while the runtime
  actually queried AAAA anyway, causing UIs/controllers to display a state the
  resolver ignored. Both sides now share `meow_config::effective_ipv6` and
  default to `false` — and the reported value is the one actually enforced.

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

- **Hosts-table AAAA answers follow the global `ipv6` switch.** An AAAA query
  for a domain present in the hosts trie is gated by `ipv6` exactly like every
  other AAAA path: with `ipv6: false` it returns NODATA even when the hosts
  file carries an IPv6 address for the domain (the entry remains reachable for
  A queries and for `ipv6: true` configs). This keeps the global toggle a
  single, predictable switch — dual-stack operators who pin addresses in
  `hosts:` must enable `ipv6: true` for the v6 entries to be served.

- **`tun:` parameter changes now restart the running listener.** A `PUT
  /configs` that left `tun.enable: true` untouched but changed `mtu`,
  `auto-route`, `dns-hijack`, the address fields, or the inherited
  `max-connections` cap committed the new raw while the listener kept
  running on the old parameters — the two silently diverged until the next
  restart. The reconcile now diffs the parsed `TunConfig` (not just
  `enable`) and restarts a listener on any semantic difference, alongside
  the existing fake-IP-input trigger; no-op respellings and warn-only
  ignored fields do not bounce the device, a dead-but-enabled listener is
  respawned rather than skipped, and a restart failure rolls `enable`
  back to `false`. `PUT /configs` also validates the `tun:` section at
  admission — an unparsable section is a 400 (bypassed by `?force`)
  instead of being committed and tearing the healthy listener down when
  the restart hits the spawn-side parse error.

- **VMess body ciphers no longer pay for unused key schedules.** Every
  connection built two `BodyCipher` objects — one per relay task — and each
  expanded *both* directions' AEAD key schedules, so four schedules were
  computed and two dropped unused (the boxed AES-128-GCM schedule is the
  expensive half). `BodyCipher` now has directional constructors
  (`new_writer`/`new_reader`); the unbuilt direction is a distinct `Unbuilt`
  variant that hard-errors on misuse rather than passing as the plaintext
  `none` codec. Per-connection cost is halved. (#533)

- **Reloaded `rule-providers` gain or lose their interval refresh task
  without a restart.** Provider refresh loops were spawned once at
  startup over the startup-era registry, so a `PUT /configs` or
  subscription refresh that added, removed, or re-`interval`ed an HTTP
  rule provider never gained or lost its background task. A new
  `RefreshSupervisor` (`meow-config::rule_provider_refresh`) diffs the
  wanted (name → interval) set against running tasks on every commit
  that swaps the registry — spawning missing, aborting removed or
  interval-changed, and reaping dead loops — and each loop resolves its
  provider by name on every tick so it follows registry swaps. Ticks use
  `MissedTickBehavior::Delay`, so a suspend longer than `interval` no
  longer fires a back-to-back refresh storm. A successful `refresh()`
  also writes the provider's payload cache file now, so a `prefer_cache`
  restart loads the newest refresh rather than the initial-load-era
  file; an `interval` beyond ~10 years is warn-skipped instead of
  panicking its task. Embedders: `ApiServer::new` and
  `subscription_refresh::run_loop` each gained a required
  `Arc<RefreshSupervisor>` parameter. (issue #543)

- **The DNS rebuild now shares the commit's prefetched rule-provider
  payload snapshot.** Its parser context was built from an empty payload
  map — blind to `GEOIP`/`GEOSITE`/`IP-ASN` rules that live only inside
  provider payloads — and the private provider load it runs when no
  shared provider map is in hand re-read the same bytes the routing
  rebuild had just fetched, potentially seeing different file content
  mid-commit. `RebuildResult` now carries the prefetched payload `Arc`
  and every commit path (`PUT /configs`, subscription refresh,
  `apply_raw_to_tunnel`) passes it to the DNS rebuild, so both parser
  contexts scan the same bytes and a private load parses the
  commit-consistent snapshot. Embedders: `reconcile_dns_config` and
  `parse_dns_from_raw` gained a `prefetched_payloads` parameter.
  (issue #543)
