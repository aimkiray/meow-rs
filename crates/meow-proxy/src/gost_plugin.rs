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

use crate::transport_to_proxy_err;

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

/// Strict bool for all gost boolean knobs (`tls`, `mux`,
/// `skip-cert-verify`, `ech-opts.enable`): an unrecognized
/// value is a config error — silently coercing `tls=bogus` to `false`
/// would produce a plaintext websocket the operator believes is TLS.
fn parse_bool_strict(s: &str, opt: &str) -> Result<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(MeowError::Config(format!(
            "gost-plugin: '{opt}' expects a boolean, got '{s}'"
        ))),
    }
}

/// Parse a `fingerprint` option value: `:`-separated hex of the 32-byte
/// SHA-256 of the pinned certificate (upstream
/// `ca.NewFingerprintVerifier`).  uTLS profile names are rejected with a
/// pointer at `client-fingerprint`, mirroring upstream's explicit check.
fn parse_cert_pin(s: &str) -> Result<[u8; 32]> {
    // Upstream guards against the easy confusion between this pin and a
    // uTLS ClientHello profile name.
    const UTLS_NAMES: &[&str] = &[
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
    ];
    if UTLS_NAMES.contains(&s.to_ascii_lowercase().as_str()) {
        return Err(MeowError::Config(
            "gost-plugin: 'fingerprint' is a TLS certificate pin (SHA-256 hex), \
             not a uTLS profile — ClientHello shaping is not supported on ss nodes"
                .to_string(),
        ));
    }
    let stripped: String = s.trim().replace(':', "");
    let bytes = hex::decode(&stripped).map_err(|e| {
        MeowError::Config(format!("gost-plugin: fingerprint hex decode failed: {e}"))
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        MeowError::Config(format!(
            "gost-plugin: fingerprint must be a SHA-256 hash (32 bytes), got {}",
            bytes.len()
        ))
    })
}

/// Upstream `NewTLSKeyPairLoader` accepts PEM content or a file path for
/// `certificate`/`private-key`.  A `-----BEGIN` marker means inline PEM;
/// anything else is read from the filesystem once at config load.
/// Relative paths resolve against the meow home dir (upstream `C.Path`),
/// not the process CWD.  With no explicit `-d` home we fall back to the
/// same XDG default `meow_config` uses (`$XDG_CONFIG_HOME/meow` or
/// `~/.config/meow`) rather than silently anchoring on the daemon's CWD —
/// meow-proxy cannot depend on meow-config (cycle), so the fallback chain
/// is duplicated here.
fn load_pem_or_path(value: &str, opt: &str) -> Result<Vec<u8>> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        let path = std::path::Path::new(value);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            let base = meow_common::meow_home_dir().unwrap_or_else(|| {
                let base = std::env::var_os("XDG_CONFIG_HOME")
                    .map(std::path::PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME")
                            .map(|h| std::path::PathBuf::from(h).join(".config"))
                    })
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                base.join("meow")
            });
            base.join(path)
        };
        std::fs::read(&resolved).map_err(|e| {
            MeowError::Config(format!(
                "gost-plugin: '{opt}' is neither inline PEM nor a readable file ({}): {e}",
                resolved.display()
            ))
        })
    }
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

    for token in s.split(';').map(str::trim).filter(|t| !t.is_empty()) {
        // Upstream decodes plugin-opts through mapstructure — option keys
        // are case-insensitive (`plugin-opts: {Mode: websocket}` works).
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => (token.to_ascii_lowercase(), "true".to_string()),
        };

        match key.as_str() {
            "mode" => {
                if value.eq_ignore_ascii_case("websocket") || value.eq_ignore_ascii_case("ws") {
                    mode_seen = true;
                } else {
                    return Err(MeowError::Config(format!(
                        "gost-plugin: unsupported mode '{value}' (only 'websocket'/'ws' is supported)"
                    )));
                }
            }
            "host" => {
                if value.is_empty() {
                    return Err(MeowError::Config(
                        "gost-plugin: 'host' must not be empty".into(),
                    ));
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
                        "gost-plugin: 'path' contains an invalid character: {value:?}"
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
            "tls" => cfg.tls = parse_bool_strict(&value, "tls")?,
            "mux" => cfg.mux = parse_bool_strict(&value, "mux")?,
            "skip-cert-verify" => {
                cfg.skip_cert_verify = parse_bool_strict(&value, "skip-cert-verify")?;
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
                cfg.cert_pin = Some(parse_cert_pin(&value)?);
            }
            "name-cert-verify" | "fingerprint" => {}
            // Upstream `NewTLSKeyPairLoader` accepts inline PEM or file
            // paths (with fswatch reload — not mirrored here).
            "certificate" => cert_pem = Some(load_pem_or_path(&value, "certificate")?),
            "private-key" => key_pem = Some(load_pem_or_path(&value, "private-key")?),
            "ech-opts.enable" | "ech-enable" => {
                ech_enable = parse_bool_strict(&value, "ech-opts.enable")?;
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
                    warn!("gost-plugin: ignoring malformed header entry (expected 'Key:Value')");
                }
            }
            other => {
                warn!("gost-plugin: ignoring unknown opt '{}'", other);
            }
        }
    }

    if !mode_seen {
        return Err(MeowError::Config(
            "gost-plugin: missing required 'mode=websocket' opt".into(),
        ));
    }

    if cfg.mux && !cfg!(feature = "mux") {
        return Err(MeowError::Config(
            "gost-plugin: mux=true (the upstream default) needs the `mux` \
             cargo feature for smux — rebuild with it or set `mux: false`"
                .into(),
        ));
    }

    // mTLS: both halves or none — a lone cert or key is a config error.
    match (cert_pem, key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            cfg.client_cert = Some(ClientCert { cert_pem, key_pem });
        }
        (None, None) => {}
        _ => {
            return Err(MeowError::Config(
                "gost-plugin: 'certificate' and 'private-key' must both be set".into(),
            ));
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
                            "gost-plugin: base64 decode ech-opts.config failed: {e}"
                        ))
                    })?;
                cfg.ech = Some(EchOpts::Config(list));
            }
            None => {
                // Upstream falls back to a DNS HTTPS-record query; that
                // resolver path is not implemented — declare it rather than
                // silently running without ECH.
                return Err(MeowError::Config(
                    "gost-plugin: ech-opts.enable without ech-opts.config \
                     (DNS-queried ECH is not supported)"
                        .into(),
                ));
            }
        }
    }

    // TLS-only knobs parsed but `tls` unset: upstream drops them silently;
    // warn so a typo doesn't produce a plaintext connection the operator
    // believes is encrypted.
    if !cfg.tls {
        let mut ignored = Vec::new();
        if cfg.skip_cert_verify {
            ignored.push("skip-cert-verify");
        }
        if cfg.name_cert_verify.is_some() {
            ignored.push("name-cert-verify");
        }
        if cfg.cert_pin.is_some() {
            ignored.push("fingerprint");
        }
        if cfg.client_cert.is_some() {
            ignored.push("certificate/private-key");
        }
        if cfg.ech.is_some() {
            ignored.push("ech-opts");
        }
        if !ignored.is_empty() {
            warn!(
                "gost-plugin: {} ignored without `tls` (plaintext websocket)",
                ignored.join(", ")
            );
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
        "gost-plugin: dialing {}:{} tls={} host={} path={} mux={}",
        server_host, server_port, cfg.tls, cfg.host, cfg.path, cfg.mux
    );

    debug_assert_eq!(cfg.tls, tls_layer.is_some());

    // 1) Raw TCP.
    let tcp = dialer
        .dial(server_host, server_port)
        .await
        .map_err(MeowError::Io)?;

    // 2) Optional TLS handshake via the pre-built TlsLayer.
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
        Err(MeowError::Config(
            "gost-plugin: mux requires the `mux` cargo feature".into(),
        ))
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
    #[cfg(feature = "mux")]
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
}
