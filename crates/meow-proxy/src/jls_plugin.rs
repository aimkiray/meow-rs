//! In-process `jls` SIP003 plugin for Shadowsocks (mihomo
//! `transport/jls` parity — the record-level TLS client and random-field
//! authentication live in [`meow_transport::jls`]).
//!
//! `plugin: jls` with `plugin-opts` keys:
//!
//! | opt | meaning | default |
//! |-----|---------|---------|
//! | `host` | camouflage server name — TLS SNI | *(required)* |
//! | `username` | jls user — feeds the auth nonce (`user_iv`) | *(required)* |
//! | `password` | jls password — feeds the auth key (`user_pwd`) | *(required)* |
//! | `alpn` | comma-separated ALPN list for the handshake | `h2,http/1.1` |
//!
//! `host`/`username`/`password` are non-`omitempty` upstream
//! (`jlsOption`), so all three are required here.
//!
//! Unlike `shadow-tls`/`restls` there is no `skip-cert-verify` option:
//! jls's authentication *is* the certificate check — when the ServerHello
//! random opens under the credentials the camouflage certificate is not
//! PKI-verified (upstream `jlsAuthenticated()` skips it); when it does
//! not, the full chain and CertificateVerify checks run against `host`
//! before the connection is rejected.
//!
//! The node-level `client-fingerprint` option selects a uTLS ClientHello
//! profile upstream; this client crafts its own ClientHello, so the
//! option has no effect here. UDP relay is rejected (upstream jls is
//! TCP-only).

use meow_common::error::{MeowError, Result};
use meow_transport::{jls::JlsConfig, Stream};
use tracing::{debug, warn};

use crate::plugin_util::sip003_opts;
use crate::transport_to_proxy_err;

const PLUGIN: &str = "jls";

/// Parsed `jls` client options.
#[derive(Debug, Clone)]
pub struct JlsPluginConfig {
    /// Camouflage server name — the TLS handshake's SNI.
    pub host: String,
    /// jls username (`user_iv` in rustls-jls terms).
    pub username: String,
    /// jls password (`user_pwd`).
    pub password: String,
    /// ALPN protocol list; defaults to `h2,http/1.1`.
    pub alpn: Vec<String>,
}

/// Parse a flattened SIP003 opts string for `jls`
/// (`host=cover.example.com;username=…;password=…;alpn=h2,http/1.1`).
///
/// `host`, `username` and `password` are required (upstream marks all
/// three non-`omitempty`). Unknown keys are logged at `warn` level and
/// ignored.
pub fn parse_opts(s: &str) -> Result<JlsPluginConfig> {
    let mut cfg = JlsPluginConfig {
        host: String::new(),
        username: String::new(),
        password: String::new(),
        alpn: Vec::new(),
    };

    for (key, value) in sip003_opts(s) {
        match key.as_str() {
            "host" => cfg.host = value,
            "username" => cfg.username = value,
            "password" => cfg.password = value,
            "alpn" => {
                cfg.alpn = value
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            other => warn!("{PLUGIN}: ignoring unknown opt '{other}'"),
        }
    }

    // Required upstream (`obfs:"…"` non-omitempty fields).
    for (key, val) in [
        ("host", &cfg.host),
        ("username", &cfg.username),
        ("password", &cfg.password),
    ] {
        if val.is_empty() {
            return Err(MeowError::Config(format!(
                "{PLUGIN}: missing required '{key}' opt"
            )));
        }
    }
    Ok(cfg)
}

/// Dial a TCP + jls connection to `server_host:server_port` and return
/// the TLS stream ready to be wrapped by the SS layer.
pub async fn dial(
    cfg: &JlsPluginConfig,
    server_host: &str,
    server_port: u16,
    dialer: &dyn crate::dialer::TcpDialer,
) -> Result<Box<dyn Stream>> {
    debug!(
        "{PLUGIN}: dialing {}:{} via host={} username={}",
        server_host, server_port, cfg.host, cfg.username
    );
    let tcp = dialer
        .dial(server_host, server_port)
        .await
        .map_err(MeowError::Io)?;
    let config = JlsConfig {
        server_name: cfg.host.clone(),
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        alpn: cfg.alpn.clone(),
        additional_roots: Vec::new(),
    };
    meow_transport::jls::dial(Box::new(tcp), &config)
        .await
        .map_err(transport_to_proxy_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_opts_cases() {
        let cases: &[(&str, bool)] = &[
            // minimal — host, username and password all required
            ("host=cover.example.com;username=u;password=p", true),
            ("host=h;username=u;password=p;alpn=h2,http/1.1", true),
            ("host=h;username=u;password=p;alpn=", true),
            // missing required opts
            ("username=u;password=p", false),       // no host
            ("host=h;password=p", false),           // no username
            ("host=h;username=u", false),           // no password
            ("host=h;username=;password=p", false), // empty username
            ("", false),
        ];
        for (opts, ok) in cases {
            assert_eq!(
                parse_opts(opts).is_ok(),
                *ok,
                "opts {opts:?} expected ok={ok}"
            );
        }
    }

    /// `sip003_opts` lowercases keys — upstream decodes the opts map
    /// through mapstructure, which matches case-insensitively.
    #[test]
    fn parse_opts_case_insensitive_keys() {
        let cfg = parse_opts("Host=cover.example.com;USERNAME=u;Password=p").unwrap();
        assert_eq!(cfg.host, "cover.example.com");
        assert_eq!(cfg.username, "u");
        assert_eq!(cfg.password, "p");
    }

    #[test]
    fn parse_opts_full() {
        let cfg =
            parse_opts("host=cover.example.com;username=alice;password=secret;alpn=h3,h2").unwrap();
        assert_eq!(cfg.host, "cover.example.com");
        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.password, "secret");
        assert_eq!(cfg.alpn, ["h3", "h2"]);
    }
}
