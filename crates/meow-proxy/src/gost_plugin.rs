//! Built-in `gost-plugin` SIP003 client transport (issue #533).
//!
//! Implements the WebSocket (+ optional TLS, optional smux) transport that
//! mihomo runs in-process for `plugin: gost-plugin`, natively in Rust —
//! no external `gost-plugin` binary is spawned.
//!
//! Upstream: `adapter/outbound/shadowsocks.go` (`gostObfsOption`) and
//! `transport/gost/websocket.go` (`NewGostWebsocket`).  Wire behaviour per
//! connection: TCP → optional TLS (ALPN `http/1.1`, SNI from `host`, or the
//! `Host` header when present) → WebSocket upgrade → when `mux` (upstream
//! default **true**) a fresh smux v1 session carries one stream.
//!
//! Option mapping (upstream `plugin-opts` map → flattened SIP003 tokens by
//! `meow-config::serialize_plugin_opts`):
//!
//! | upstream key          | flattened token      | notes                        |
//! |-----------------------|----------------------|------------------------------|
//! | `mode`                | `mode`               | required, must be `websocket`|
//! | `host`                | `host`               | default `bing.com`           |
//! | `path`                | `path`               | default `/`                  |
//! | `tls`                 | `tls`                | bool                         |
//! | `mux`                 | `mux`                | bool, default `true`         |
//! | `headers` map         | repeated `header=K:V`| Host entry also sets TLS SNI |
//! | `skip-cert-verify`    | `skip-cert-verify`   |                              |
//! | `name-cert-verify`    | `name-cert-verify`   | cert check name ≠ SNI        |
//! | `fingerprint`         | `fingerprint`        | SHA-256 cert pin (not uTLS)  |
//! | `certificate`         | `certificate`        | PEM cert or file path (mTLS) |
//! | `private-key`         | `private-key`        | PEM key or file path         |
//! | `ech-opts.enable`     | `ech-opts.enable`    | bool                         |
//! | `ech-opts.config`     | `ech-opts.config`    | base64 ECHConfigList         |
//!
//! Divergence: upstream reloads cert/key files on change (fswatch); the
//! files here are read once at config load.

use std::collections::HashMap;

use meow_common::{MeowError, Result};
use meow_transport::{
    tls::{ClientCert, EchOpts, TlsConfig, TlsLayer},
    ws::{WsConfig, WsLayer},
    Transport,
};
use tracing::{debug, warn};

use crate::plugin_util::{load_pem_or_path, parse_bool_strict, parse_cert_pin, sip003_opts};
use crate::transport_to_proxy_err;

const PLUGIN: &str = "gost-plugin";

/// Parsed `gost-plugin` client options.
#[derive(Debug, Clone)]
pub struct GostPluginConfig {
    /// Host header and TLS SNI.  Upstream default: `bing.com` (the dial
    /// still goes to the SS server; `host` is only the camouflage name).
    pub host: String,
    /// WebSocket upgrade path.
    pub path: String,
    /// Wrap the WebSocket in TLS.
    pub tls: bool,
    /// Multiplex each connection through a fresh smux v1 session.
    /// Upstream defaults to `true`.
    pub mux: bool,
    /// Extra WebSocket request headers (`headers` map upstream).
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    /// Certificate-verification hostname override (`name-cert-verify`).
    pub name_cert_verify: Option<String>,
    /// SHA-256 certificate pin (`fingerprint` — SSL pinning per upstream
    /// `ca.NewFingerprintVerifier`, *not* a uTLS ClientHello profile;
    /// upstream reserves `client-fingerprint` for uTLS).
    pub cert_pin: Option<[u8; 32]>,
    /// mTLS client certificate (`certificate` + `private-key`, PEM).
    pub client_cert: Option<ClientCert>,
    /// ECH config (`ech-opts.enable` + base64 `ech-opts.config`).
    pub ech: Option<EchOpts>,
}

/// Parse a flattened SIP003 opts string for `gost-plugin`
/// (`mode=websocket;tls;host=example.com;mux=true;header=K:V`).
///
/// - Bare keys (e.g. `tls`) are treated as `key=true`.
/// - `mode` is required and must be `websocket` (upstream rejects any
///   other value with `obfs mode error`).
/// - Unknown keys are logged at `warn` level and ignored.
pub fn parse_opts(s: &str) -> Result<GostPluginConfig> {
    // Upstream seeds `gostObfsOption{Host: "bing.com", Mux: true}` before
    // decoding — empty plugin-opts still produces host=bing.com, mux=true.
    let mut cfg = GostPluginConfig {
        host: "bing.com".to_string(),
        path: "/".to_string(),
        tls: false,
        mux: true,
        headers: HashMap::new(),
        skip_cert_verify: false,
        name_cert_verify: None,
        cert_pin: None,
        client_cert: None,
        ech: None,
    };
    let mut mode_seen = false;
    let mut cert_pem: Option<Vec<u8>> = None;
    let mut key_pem: Option<Vec<u8>> = None;
    let mut ech_enable = false;
    let mut ech_config: Option<String> = None;

    for (key, value) in sip003_opts(s) {
        match key.as_str() {
            "mode" => {
                if value.eq_ignore_ascii_case("websocket") || value.eq_ignore_ascii_case("ws") {
                    mode_seen = true;
                } else {
                    return Err(MeowError::Config(format!(
                        "{PLUGIN}: unsupported mode '{value}' (only 'websocket'/'ws' is supported)"
                    )));
                }
            }
            "host" => {
                if value.is_empty() {
                    return Err(MeowError::Config(format!(
                        "{PLUGIN}: 'host' must not be empty"
                    )));
                }
                cfg.host = value;
            }
            // Go's URL writer normalizes an empty request path to `/`.
            // A `path` without a leading `/` is malformed as a request
            // target — prepend it (upstream accepts it because the value
            // lands in `http.Request.URL.Path` which re-escapes; our WsLayer
            // composes the request line from the raw string).
            "path" => {
                if value.chars().any(|c| c.is_ascii_control() || c == ' ') {
                    return Err(MeowError::Config(format!(
                        "{PLUGIN}: 'path' contains an invalid character: {value:?}"
                    )));
                }
                cfg.path = if value.is_empty() {
                    "/".into()
                } else if value.starts_with('/') {
                    value
                } else {
                    format!("/{value}")
                };
            }
            "tls" => cfg.tls = parse_bool_strict(&value, PLUGIN, "tls")?,
            "mux" => cfg.mux = parse_bool_strict(&value, PLUGIN, "mux")?,
            "skip-cert-verify" => {
                cfg.skip_cert_verify = parse_bool_strict(&value, PLUGIN, "skip-cert-verify")?;
            }
            // Upstream guards `NameCertVerify != ""` — an empty value is
            // ignored, not an (always-failing) empty verify name.
            "name-cert-verify" if !value.is_empty() => {
                cfg.name_cert_verify = Some(value);
            }
            // Upstream `fingerprint` is a SHA-256 certificate pin, not a
            // uTLS profile — `NewFingerprintVerifier` rejects the uTLS
            // names explicitly and hex-decodes the rest. Empty = ignored.
            "fingerprint" if !value.is_empty() => {
                cfg.cert_pin = Some(parse_cert_pin(&value, PLUGIN)?);
            }
            "name-cert-verify" | "fingerprint" => {}
            // Upstream `NewTLSKeyPairLoader` accepts inline PEM or file
            // paths (with fswatch reload — not mirrored here).
            "certificate" => cert_pem = Some(load_pem_or_path(&value, "certificate", PLUGIN)?),
            "private-key" => key_pem = Some(load_pem_or_path(&value, "private-key", PLUGIN)?),
            "ech-opts.enable" | "ech-enable" => {
                ech_enable = parse_bool_strict(&value, PLUGIN, "ech-opts.enable")?;
            }
            "ech-opts.config" | "ech-config" => ech_config = Some(value),
            "header" => {
                // Form: header=Key:Value (SIP003 convention shared with
                // v2ray-plugin). A `Host` entry doubles as the ws request
                // Host and TLS SNI; keep it under one canonical case so
                // `Host`/`host` duplicates cannot race in the map.
                if let Some((k, v)) = value.split_once(':') {
                    let k = if k.trim().eq_ignore_ascii_case("host") {
                        "Host"
                    } else {
                        k.trim()
                    };
                    cfg.headers.insert(k.to_string(), v.trim().to_string());
                } else {
                    // The value may be a credential — log shape, not content.
                    warn!("{PLUGIN}: ignoring malformed header entry (expected 'Key:Value')");
                }
            }
            other => {
                warn!("{PLUGIN}: ignoring unknown opt '{}'", other);
            }
        }
    }

    if !mode_seen {
        return Err(MeowError::Config(format!(
            "{PLUGIN}: missing required 'mode=websocket' opt"
        )));
    }

    if cfg.mux && !cfg!(feature = "mux") {
        return Err(MeowError::Config(format!(
            "{PLUGIN}: mux=true (the upstream default) needs the `mux` \
             cargo feature for smux — rebuild with it or set `mux: false`"
        )));
    }

    // mTLS: both halves or none — a lone cert or key is a config error.
    match (cert_pem, key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            cfg.client_cert = Some(ClientCert { cert_pem, key_pem });
        }
        (None, None) => {}
        _ => {
            return Err(MeowError::Config(format!(
                "{PLUGIN}: 'certificate' and 'private-key' must both be set"
            )));
        }
    }

    if ech_enable {
        match ech_config {
            Some(b64) => {
                use base64::Engine;
                let list = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| {
                        MeowError::Config(format!(
                            "{PLUGIN}: base64 decode ech-opts.config failed: {e}"
                        ))
                    })?;
                cfg.ech = Some(EchOpts::Config(list));
            }
            None => {
                // Upstream falls back to a DNS HTTPS-record query; that
                // resolver path is not implemented — declare it rather than
                // silently running without ECH.
                return Err(MeowError::Config(
                    "{PLUGIN}: ech-opts.enable without ech-opts.config \
                     (DNS-queried ECH is not supported)"
                        .into(),
                ));
            }
        }
    }

    Ok(cfg)
}

/// Build a reusable `TlsLayer` for a gost config with `tls=true`.
///
/// Call once at adapter construction time. Returns `None` when TLS is
/// disabled.  SNI is `host`, overridden by a `Host` entry in `headers`
/// (upstream: `config.Headers.Get("Host")` replaces `ServerName`).
pub fn build_tls_layer(cfg: &GostPluginConfig) -> Result<Option<TlsLayer>> {
    if !cfg.tls {
        return Ok(None);
    }
    let sni = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v)
        .filter(|h| !h.is_empty())
        .cloned()
        .unwrap_or_else(|| cfg.host.clone());
    let mut tls_config = TlsConfig::new(sni);
    tls_config.alpn = vec!["http/1.1".to_string()];
    tls_config.skip_cert_verify = cfg.skip_cert_verify;
    tls_config.verify_name = cfg.name_cert_verify.clone();
    tls_config.cert_pin = cfg.cert_pin;
    tls_config.client_cert = cfg.client_cert.clone();
    tls_config.ech = cfg.ech.clone();
    TlsLayer::new(&tls_config)
        .map(Some)
        .map_err(transport_to_proxy_err)
}

/// Build a reusable `WsLayer` for a gost config.
///
/// Call once at adapter construction time — `WsLayer::new` validates the
/// request shape (path, header names/values) eagerly, so a malformed
/// `headers` map fails at config load instead of on every dial.
///
/// Upstream lets a `Host` entry in `headers` override the request's Host
/// header (`request.Host = host`; the same entry already drove TLS SNI),
/// so it is lifted out of `extra_headers` into `host_header` instead of
/// being sent twice.
pub fn build_ws_layer(cfg: &GostPluginConfig) -> Result<WsLayer> {
    let host_header = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v)
        .filter(|h| !h.is_empty())
        .cloned()
        .unwrap_or_else(|| cfg.host.clone());
    let mut extra_headers: Vec<(String, String)> = cfg
        .headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("host"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Upstream dials the ws upgrade through Go's net/http, which injects
    // `User-Agent: Go-http-client/1.1` when the request doesn't set one —
    // match that default (a user-supplied UA wins, as upstream's does).
    if !cfg
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    {
        extra_headers.push(("User-Agent".into(), "Go-http-client/1.1".into()));
    }
    WsLayer::new(WsConfig {
        path: cfg.path.clone(),
        host_header: Some(host_header),
        extra_headers,
        ..WsConfig::default()
    })
    .map_err(transport_to_proxy_err)
}

/// Dial a TCP (+ optional TLS) + WebSocket (+ optional smux) connection to
/// `server_host:server_port` and return the framed stream ready to be
/// wrapped by the SS encryption layer.
///
/// When `tls_layer` is `Some`, it is reused across connections so the
/// BoringSSL `SSL_CTX` and root cert store are allocated only once.
///
/// With `mux=true` a fresh smux session wraps the WebSocket and the
/// returned stream is its first `open_stream` — upstream
/// `NewGostWebsocket` creates one session per dial, so the session dies
/// when the stream drops.
pub async fn dial(
    cfg: &GostPluginConfig,
    tls_layer: Option<&TlsLayer>,
    ws_layer: &WsLayer,
    server_host: &str,
    server_port: u16,
    dialer: &dyn crate::dialer::TcpDialer,
) -> Result<Box<dyn meow_transport::Stream>> {
    debug!(
        "{PLUGIN}: dialing {}:{} tls={} host={} path={} mux={}",
        server_host, server_port, cfg.tls, cfg.host, cfg.path, cfg.mux
    );

    // 1) Raw TCP.
    let tcp = dialer
        .dial(server_host, server_port)
        .await
        .map_err(MeowError::Io)?;

    // 2) Optional TLS handshake via the pre-built TlsLayer.  `dial` already
    //    returns `Box<dyn Stream>` — no double-boxing.
    debug_assert_eq!(cfg.tls, tls_layer.is_some());
    let stream: Box<dyn meow_transport::Stream> = if let Some(tls) = tls_layer {
        tls.connect(tcp).await.map_err(transport_to_proxy_err)?
    } else {
        tcp
    };

    // 3) WebSocket upgrade via the pre-built WsLayer.
    let stream = ws_layer
        .connect(stream)
        .await
        .map_err(transport_to_proxy_err)?;

    // 4) Optional smux session (upstream `smux.DefaultConfig()` +
    //    `KeepAliveDisabled` — meow's smux v1 never *sends* keepalive NOPs,
    //    matching upstream, but inbound NOP frames from the peer are
    //    handled: `CMD_NOP` is consumed in the session read loop).
    //    The session is single-stream by construction, so the stream gets
    //    the whole session receive budget (upstream: per-stream
    //    MaxReceiveBuffer).
    if !cfg.mux {
        return Ok(stream);
    }
    #[cfg(feature = "mux")]
    {
        let session = std::sync::Arc::new(
            crate::mux::smux::Session::client_with_stream_buffer(
                stream,
                crate::mux::smux::MAX_RECEIVE_BUFFER,
            )
            .map_err(MeowError::Io)?,
        );
        let stream = session.open_stream().await.map_err(MeowError::Io)?;
        Ok(Box::new(stream))
    }
    #[cfg(not(feature = "mux"))]
    {
        // Unreachable — `parse_opts` rejects mux=true without the feature.
        Err(MeowError::Config(format!(
            "{PLUGIN}: mux requires the `mux` cargo feature"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_opts_cases() {
        struct Case {
            name: &'static str,
            input: &'static str,
            check: fn(&Result<GostPluginConfig>) -> bool,
        }

        let cases = [
            Case {
                name: "upstream_defaults",
                // `gostObfsOption{Host: "bing.com", Mux: true}` — only mode
                // is required.  The mux default itself is asserted by
                // `mux_default_true_under_mux_feature` (mux builds only).
                input: "mode=websocket",
                check: |r| match r {
                    Ok(c) => c.host == "bing.com" && !c.tls && c.path == "/",
                    Err(_) => false,
                },
            },
            Case {
                name: "full",
                input: "mode=websocket;tls;mux=false;host=cdn.example.com;path=/ws;\
                        skip-cert-verify=true;header=CF-Token:abc;\
                        fingerprint=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                check: |r| match r {
                    Ok(c) => {
                        c.tls
                            && !c.mux
                            && c.host == "cdn.example.com"
                            && c.path == "/ws"
                            && c.skip_cert_verify
                            && c.cert_pin == Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
                            && c.headers.get("CF-Token").map(String::as_str) == Some("abc")
                    }
                    Err(_) => false,
                },
            },
            Case {
                name: "fingerprint_utls_name_errors",
                // Upstream `NewFingerprintVerifier` rejects uTLS profile
                // names — `fingerprint` is cert pinning, not ClientHello.
                input: "mode=websocket;mux=false;fingerprint=chrome",
                check: |r| r.is_err(),
            },
            Case {
                name: "fingerprint_bad_hex_errors",
                input: "mode=websocket;mux=false;fingerprint=zz",
                check: |r| r.is_err(),
            },
            Case {
                name: "fingerprint_wrong_len_errors",
                input: "mode=websocket;mux=false;fingerprint=aabb",
                check: |r| r.is_err(),
            },
            Case {
                name: "missing_mode_errors",
                input: "host=example.com",
                check: |r| r.is_err(),
            },
            Case {
                name: "bad_mode_errors",
                input: "mode=quic",
                check: |r| r.is_err(),
            },
            Case {
                name: "lone_certificate_errors",
                input: "mode=websocket;certificate=PEM",
                check: |r| r.is_err(),
            },
            Case {
                name: "cert_pair_ok",
                input: "mode=websocket;certificate=-----BEGIN CERTIFICATE-----x;\
                        private-key=-----BEGIN KEY-----k",
                check: |r| matches!(r, Ok(c) if c.client_cert.is_some()),
            },
            Case {
                name: "cert_path_unreadable_errors",
                input: "mode=websocket;certificate=/nonexistent/cert.pem",
                check: |r| r.is_err(),
            },
            Case {
                name: "ech_enable_without_config_errors",
                input: "mode=websocket;ech-opts.enable=true",
                check: |r| r.is_err(),
            },
            Case {
                name: "ech_config_decodes",
                // "QUJD" = base64("ABC")
                input: "mode=websocket;ech-opts.enable=true;ech-opts.config=QUJD",
                check: |r| match r {
                    Ok(c) => matches!(&c.ech, Some(EchOpts::Config(b)) if b == b"ABC"),
                    Err(_) => false,
                },
            },
            Case {
                name: "ech_bad_base64_errors",
                input: "mode=websocket;ech-opts.enable=true;ech-opts.config=!!!",
                check: |r| r.is_err(),
            },
            Case {
                name: "name_cert_verify",
                input: "mode=websocket;name-cert-verify=real.example.com",
                check: |r| matches!(r, Ok(c) if c.name_cert_verify.as_deref() == Some("real.example.com")),
            },
            Case {
                name: "unknown_key_ignored",
                input: "mode=websocket;foo=bar",
                check: |r| r.is_ok(),
            },
            Case {
                name: "ws_alias",
                input: "mode=ws",
                check: |r| r.is_ok(),
            },
            Case {
                name: "case_insensitive_keys",
                // Upstream decodes via mapstructure — keys match case-insensitively.
                input: "MODE=websocket;MUX=false;HOST=Example.COM;PATH=/Up;TLS",
                check: |r| matches!(r, Ok(c) if c.tls && !c.mux
                    && c.host == "Example.COM" && c.path == "/Up"),
            },
            Case {
                name: "path_without_slash_normalized",
                input: "mode=websocket;mux=false;path=ws",
                check: |r| matches!(r, Ok(c) if c.path == "/ws"),
            },
            Case {
                name: "path_with_space_errors",
                input: "mode=websocket;mux=false;path=/a b",
                check: |r| r.is_err(),
            },
            Case {
                name: "bad_tls_bool_errors",
                // `tls=bogus` must not silently degrade to plaintext ws.
                input: "mode=websocket;tls=enbale",
                check: |r| r.is_err(),
            },
            Case {
                name: "bad_mux_bool_errors",
                input: "mode=websocket;mux=maybe",
                check: |r| r.is_err(),
            },
            Case {
                name: "bad_skip_cert_verify_errors",
                input: "mode=websocket;mux=false;skip-cert-verify=tru",
                check: |r| r.is_err(),
            },
            Case {
                name: "bad_ech_enable_bool_errors",
                input: "mode=websocket;mux=false;ech-opts.enable=yep;ech-opts.config=QUJD",
                check: |r| r.is_err(),
            },
        ];

        let mut failures = Vec::new();
        for case in &cases {
            // Without the `mux` feature the upstream mux default (`true`)
            // is a parse error; neutralize it for inputs that do not
            // exercise mux themselves.
            let owned;
            let input = if cfg!(feature = "mux") || case.input.contains("mux") {
                case.input
            } else {
                owned = format!("{};mux=false", case.input);
                &owned
            };
            let r = parse_opts(input);
            if !(case.check)(&r) {
                failures.push(format!("{}: {r:?}", case.name));
            }
        }
        assert!(failures.is_empty(), "parse_opts failures: {failures:?}");
    }

    /// Empty values: `host` is a hard error, `path`/`name-cert-verify`/
    /// `fingerprint` normalize to defaults/absent (upstream parity).
    #[test]
    fn parse_opts_empty_values() {
        assert!(parse_opts("mode=websocket;mux=false;host=").is_err());
        assert_eq!(
            parse_opts("mode=websocket;mux=false;path=").unwrap().path,
            "/"
        );
        assert!(parse_opts("mode=websocket;mux=false;name-cert-verify=")
            .unwrap()
            .name_cert_verify
            .is_none());
        assert!(parse_opts("mode=websocket;mux=false;fingerprint=")
            .unwrap()
            .cert_pin
            .is_none());
    }

    /// `Host` entries normalize to one canonical key regardless of input
    /// case, so the SNI/host_header lookup cannot race duplicates.
    #[test]
    fn parse_opts_host_header_canonical() {
        let cfg =
            parse_opts("mode=websocket;mux=false;header=host:a.com;header=Host:b.com").unwrap();
        assert_eq!(cfg.headers.len(), 1);
        assert_eq!(cfg.headers.get("Host").map(String::as_str), Some("b.com"));
        assert!(!cfg.headers.contains_key("host"));
    }

    #[cfg(feature = "mux")]
    #[test]
    fn mux_default_true_under_mux_feature() {
        let cfg = parse_opts("mode=websocket").unwrap();
        assert!(cfg.mux);
        assert!(!parse_opts("mode=websocket;mux=false").unwrap().mux);
    }

    /// Full transport loopback: gost `dial` → WebSocket upgrade → smux
    /// session → echo.  The server side is a ws acceptor feeding a
    /// frame-level smux echo — the same wire shape a gost server speaks.
    #[cfg(feature = "mux")]
    #[tokio::test]
    async fn dial_ws_smux_echo_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut ws = ws;
            // smux echo: read a frame header+payload, echo PSH back.
            use futures::{SinkExt, StreamExt};
            let mut buf = Vec::new();
            while let Some(msg) = ws.next().await {
                let Ok(msg) = msg else { return };
                if !msg.is_binary() {
                    continue;
                }
                buf.extend_from_slice(&msg.into_data());
                while buf.len() >= 8 {
                    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                    if buf.len() < 8 + len {
                        break;
                    }
                    let frame: Vec<u8> = buf.drain(..8 + len).collect();
                    if frame[1] == 2 {
                        // CMD_PSH → echo payload back on the same stream id.
                        let mut out = Vec::with_capacity(8 + len);
                        out.extend_from_slice(&frame[..8]);
                        out.extend_from_slice(&frame[8..]);
                        ws.send(tokio_tungstenite::tungstenite::Message::Binary(out.into()))
                            .await
                            .unwrap();
                    }
                }
            }
        });

        let cfg = parse_opts("mode=websocket;host=test.example;mux=true").unwrap();
        let ws = build_ws_layer(&cfg).unwrap();
        let dialer = crate::dialer::DirectDialer;
        let mut stream = dial(&cfg, None, &ws, "127.0.0.1", port, &dialer)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.abort();
    }

    /// ws-only path (mux=false): raw WebSocket echo, no smux framing.
    /// Ungated on purpose — this is the only dial path a `ss`-without-`mux`
    /// build can exercise, so it must compile and run there too.
    #[tokio::test]
    async fn dial_ws_echo_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut ws = ws;
            use futures::{SinkExt, StreamExt};
            while let Some(msg) = ws.next().await {
                let Ok(msg) = msg else { return };
                if msg.is_binary() {
                    ws.send(msg).await.unwrap();
                }
            }
        });

        let cfg = parse_opts("mode=websocket;host=test.example;mux=false").unwrap();
        let ws = build_ws_layer(&cfg).unwrap();
        let dialer = crate::dialer::DirectDialer;
        let mut stream = dial(&cfg, None, &ws, "127.0.0.1", port, &dialer)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.abort();
    }

    /// A wss acceptor for the loopback tests: rcgen leaf → rustls → ws echo.
    /// Returns (port, leaf sha256 pin, server task).
    async fn start_wss_echo(cn: &str) -> (u16, String, tokio::task::JoinHandle<()>) {
        use sha2::Digest;

        let ck = rcgen::generate_simple_self_signed(vec![cn.into()]).unwrap();
        let pin: String = sha2::Sha256::digest(ck.cert.der())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    ck.cert.der().to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
                ),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
            use futures::{SinkExt, StreamExt};
            while let Some(msg) = ws.next().await {
                let Ok(msg) = msg else { return };
                if msg.is_binary() {
                    ws.send(msg).await.unwrap();
                }
            }
        });
        (port, pin, server)
    }

    /// The `tls=true` wire path: real TLS handshake + ws upgrade through the
    /// `TlsLayer`, authenticated by `fingerprint` alone — a self-signed cert
    /// with no `skip-cert-verify`, so a dropped pin-plumbing or TLS-skip
    /// mutant cannot pass.
    #[tokio::test]
    async fn dial_wss_cert_pin_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (port, pin, server) = start_wss_echo("test.example").await;
        let cfg = parse_opts(&format!(
            "mode=websocket;tls;mux=false;host=test.example;fingerprint={pin}"
        ))
        .unwrap();
        let tls = build_tls_layer(&cfg).unwrap();
        let ws = build_ws_layer(&cfg).unwrap();
        let dialer = crate::dialer::DirectDialer;
        let mut stream = dial(&cfg, tls.as_ref(), &ws, "127.0.0.1", port, &dialer)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.abort();
    }

    /// A wrong pin must still reject under `skip-cert-verify` — the custom
    /// verify callback overrides `VERIFY_NONE`, so the combination can never
    /// silently downgrade to an unverified connection.
    #[tokio::test]
    async fn dial_wss_wrong_pin_rejected_despite_skip_cert_verify() {
        let (port, _pin, server) = start_wss_echo("test.example").await;
        let cfg = parse_opts(
            "mode=websocket;tls;mux=false;host=test.example;\
             skip-cert-verify=true;\
             fingerprint=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let tls = build_tls_layer(&cfg).unwrap();
        let ws = build_ws_layer(&cfg).unwrap();
        let dialer = crate::dialer::DirectDialer;
        match dial(&cfg, tls.as_ref(), &ws, "127.0.0.1", port, &dialer).await {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("TLS") || msg.contains("tls") || msg.contains("certificate"),
                    "expected a TLS verification failure, got: {msg}"
                );
            }
            Ok(_) => panic!("a non-matching pin must reject the handshake"),
        }
        server.abort();
    }

    /// A `Host` entry in `headers` must win the wire Host header over `host`
    /// (upstream: `config.Headers.Get("Host")` replaces `request.Host` and
    /// drives SNI). Without it the request carries `host` verbatim.
    #[tokio::test]
    async fn dial_ws_host_header_overrides_host_opt() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn one_round(opts: &str) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tx, rx) = tokio::sync::oneshot::channel::<String>();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tx = Some(tx);
                let mut ws = tokio_tungstenite::accept_hdr_async(
                    tcp,
                    // tungstenite's `Callback` fixes the error type at
                    // `Response<Option<String>>` — nothing to box.
                    #[allow(
                        clippy::result_large_err,
                        reason = "tungstenite callback signature is fixed"
                    )]
                    move |req: &http::Request<()>,
                          resp: http::Response<()>|
                          -> std::result::Result<
                        http::Response<()>,
                        http::Response<Option<String>>,
                    > {
                        if let Some(tx) = tx.take() {
                            let host = req
                                .headers()
                                .get(http::header::HOST)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let _ = tx.send(host);
                        }
                        Ok(resp)
                    },
                )
                .await
                .unwrap();
                use futures::{SinkExt, StreamExt};
                while let Some(msg) = ws.next().await {
                    let Ok(msg) = msg else { return };
                    if msg.is_binary() {
                        ws.send(msg).await.unwrap();
                    }
                }
            });

            let cfg = parse_opts(opts).unwrap();
            let ws = build_ws_layer(&cfg).unwrap();
            let dialer = crate::dialer::DirectDialer;
            let mut stream = dial(&cfg, None, &ws, "127.0.0.1", port, &dialer)
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            server.abort();
            rx.await.unwrap()
        }

        assert_eq!(
            one_round("mode=websocket;mux=false;host=test.example;header=Host:cdn.override").await,
            "cdn.override"
        );
        assert_eq!(
            one_round("mode=websocket;mux=false;host=test.example").await,
            "test.example"
        );
    }
}
