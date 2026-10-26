use std::fmt;
use std::net::IpAddr;

use hickory_proto::op::ResponseCode;

/// A parsed nameserver URL in one of the supported transport forms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameServerUrl {
    Udp {
        addr: HostOrIp,
        port: u16,
    },
    Tcp {
        addr: HostOrIp,
        port: u16,
    },
    Tls {
        addr: HostOrIp,
        port: u16,
        sni: String,
    },
    Https {
        addr: HostOrIp,
        port: u16,
        path: String,
        sni: String,
    },
    RCode {
        code: ResponseCode,
        label: String,
    },
}

/// Either a resolved IP address or a hostname that requires bootstrap resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOrIp {
    Ip(IpAddr),
    Host(String),
}

impl fmt::Display for HostOrIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostOrIp::Ip(ip) => write!(f, "{ip}"),
            HostOrIp::Host(h) => write!(f, "{h}"),
        }
    }
}

impl fmt::Display for NameServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameServerUrl::Udp { addr, port } => write!(f, "udp://{addr}:{port}"),
            NameServerUrl::Tcp { addr, port } => write!(f, "tcp://{addr}:{port}"),
            NameServerUrl::Tls { addr, port, sni } => write!(f, "tls://{addr}:{port}#{sni}"),
            NameServerUrl::Https {
                addr,
                port,
                path,
                sni,
            } => {
                write!(f, "https://{addr}:{port}{path}#{sni}")
            }
            NameServerUrl::RCode { label, .. } => write!(f, "rcode://{label}"),
        }
    }
}

/// A nameserver entry — a [`NameServerUrl`] plus an optional proxy tag
/// telling the resolver to tunnel queries through the named proxy.
///
/// See [ADR-0012](../../../../docs/adr/0012-dns-via-proxy.md) for the
/// design (issue #67 phase 2). Plain `Udp` / `Tcp` forms take the proxy
/// name in the `#PROXY` fragment; `Tls` / `Https` forms already use `#`
/// for SNI, so they take it in the `?proxy=NAME` parameter section
/// instead. Both spellings land in this same `proxy` slot.
///
/// `?` parameter-section rule [canonical — every doc/test must state it
/// the same way]:
///
/// **A `?` parameter section is only legal on `tls://` / `https://`
/// entries. Using the entry's *last* `?` as the boundary: when any
/// `&`-separated segment of the tail is a `proxy=` key, that `?` section
/// is a parameter section — an `&`-separated `k=v` list whose only
/// currently-legal key is `proxy`. The `proxy` value is trimmed like the
/// `#PROXY` slot and must then be non-empty and contain no `#`/`?`/`&`;
/// any other key is a hard [`NameServerParseError::InvalidParams`], so
/// `?a=b&proxy=P` errors rather than silently dropping the proxy tag.
/// When no `&`-separated segment is a `proxy=` key, the `?` section is
/// not a parameter section and stays in the URL (path) verbatim — and if
/// an earlier `?` section still carries a `proxy=` segment (the
/// `?proxy=P?x=1` double-`?` typo), a warn is logged because that segment
/// travels inside the request path instead of tagging a proxy. Detection
/// of the `proxy=` key is ASCII case-insensitive; only exact lowercase
/// `proxy` is legal — `?Proxy=`/`?PROXY=` are hard `InvalidParams`, never
/// path parameters.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServerEntry {
    pub url: NameServerUrl,
    pub proxy: Option<String>,
}

impl NameServerEntry {
    pub fn plain(url: NameServerUrl) -> Self {
        Self { url, proxy: None }
    }

    /// Parse a nameserver string, returning the parsed `NameServerUrl` plus
    /// the optional proxy name carried by a plain-form `#PROXY` fragment or
    /// an encrypted-form `?proxy=NAME` parameter section.
    pub fn parse(s: &str) -> Result<Self, NameServerParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NameServerParseError::EmptyInput);
        }

        // Only `tls://` / `https://` entries may carry a `?` parameter
        // section; strip it here so the `#` fragment dispatch below —
        // and `NameServerUrl::parse`'s hostname/path consumption — sees
        // the remainder untouched. On plain forms any `?` at all is a
        // config bug (previously it was silently swallowed into the
        // hostname).
        let is_encrypted_form = s.starts_with("tls://") || s.starts_with("https://");
        let mut head = s;
        let mut query_proxy: Option<String> = None;
        if is_encrypted_form {
            if let Some(qidx) = s.rfind('?') {
                let tail = &s[qidx + 1..];
                // The tail is a parameter section when ANY `&`-separated
                // segment is a `proxy=` key — `?a=b&proxy=P` must hard-
                // error on the unknown `a` key below, not silently lose
                // the proxy tag inside the path (r15 review I1).
                // Detection is ASCII case-insensitive (`get(..6)` — never
                // `kv[..6]`, which panics on a short/multibyte segment):
                // a `?Proxy=` tail marks the section too and is then
                // rejected by the exact-case key check below, closing the
                // DoH path leak where `?Proxy=P` survived into `path`.
                if tail.split('&').any(|kv| {
                    kv.get(..6)
                        .is_some_and(|p| p.eq_ignore_ascii_case("proxy="))
                }) {
                    // The tail is a parameter section: an `&`-separated
                    // `k=v` list. `proxy` is the only legal key.
                    let mut value: Option<&str> = None;
                    for kv in tail.split('&') {
                        let (key, val) = kv.split_once('=').unwrap_or((kv, ""));
                        // Case-variant keys reached this section through
                        // the case-insensitive detection above — name the
                        // canonical spelling instead of reporting `Proxy`
                        // as just another unknown key.
                        if key.eq_ignore_ascii_case("proxy") && key != "proxy" {
                            return Err(NameServerParseError::InvalidParams(format!(
                                "nameserver parameter '{key}' must be spelled \
                                 lowercase 'proxy' in '{s}'"
                            )));
                        }
                        if key != "proxy" {
                            return Err(NameServerParseError::InvalidParams(format!(
                                "unknown nameserver parameter '{key}' in '{s}' \
                                 (only 'proxy' is supported)"
                            )));
                        }
                        if value.is_some() {
                            return Err(NameServerParseError::InvalidParams(format!(
                                "duplicate 'proxy' parameter in '{s}'"
                            )));
                        }
                        // Same trim as the `#PROXY` slot below:
                        // `?proxy= P` means the proxy named `P`.
                        let val = val.trim();
                        if val.is_empty() || val.contains('#') {
                            return Err(NameServerParseError::InvalidParams(format!(
                                "invalid proxy name '{val}' in '{s}'"
                            )));
                        }
                        value = Some(val);
                    }
                    query_proxy = value.map(str::to_string);
                    head = &s[..qidx];
                } else {
                    // No `&`-separated segment is a `proxy=` key — the
                    // `?` section is part of the URL (DoH path) and
                    // stays. But if an *earlier* `?` section still
                    // carries a `proxy=` segment — the `?proxy=P?x=1`
                    // double-`?` typo — that segment is silently sent to
                    // the server inside the request path instead of
                    // tagging a proxy. Warn rather than hard-error: a
                    // legitimate path can contain the substring.
                    if head.contains("?proxy=") || head.contains("&proxy=") {
                        tracing::warn!(
                            "nameserver '{s}' keeps a 'proxy=' segment inside the \
                             URL — the ?proxy=NAME parameter section must be the \
                             entry's LAST '?' section; as written it travels \
                             inside the request path. Did you mean to move \
                             '?proxy=NAME' last?"
                        );
                    }
                }
            }
            // The fragment that survives `?`-section stripping must be
            // clean SNI material: leftover `&`/`?` is the classic mihomo
            // `#sni&proxy=P` migration typo — under our `#`=SNI
            // divergence it is a garbage SNI that would only fail at
            // handshake time, so refuse it at parse time instead.
            if let Some(hidx) = head.find('#') {
                let frag = &head[hidx + 1..];
                if frag.contains('&') || frag.contains('?') {
                    return Err(NameServerParseError::InvalidParams(format!(
                        "invalid SNI fragment '#{frag}' in '{s}'"
                    )));
                }
                // `#P?proxy=Q` would be read by a mihomo migrant as a
                // second proxy tag; in meow-rs `#` is SNI, so the pair is
                // unresolvable — a bare fragment (no `.`, proxy-name
                // shaped) next to an explicit `?proxy=` is refused loudly.
                // `#dns.google?proxy=P` is the intended SNI+proxy form.
                if query_proxy.is_some() && !frag.contains('.') {
                    return Err(NameServerParseError::InvalidParams(format!(
                        "'#{frag}' next to '?proxy=' is ambiguous — '#' on a \
                         tls:///https:// entry is SNI in meow-rs, so a bare \
                         fragment reads as a second proxy tag (a config bug). \
                         Use a dotted SNI, e.g. '#dns.google?proxy=NAME'"
                    )));
                }
            }
        } else if s.contains('?') {
            return Err(NameServerParseError::InvalidParams(format!(
                "'?' parameters are only valid on tls:// / https:// nameserver \
                 entries, got '{s}'"
            )));
        }

        // Only plain forms (no scheme, `udp://`, `tcp://`) treat the `#`
        // fragment as a proxy name. For `tls://` / `https://` the
        // fragment is SNI — leave it intact and let NameServerUrl::parse
        // consume it normally.
        if !is_encrypted_form {
            if let Some(idx) = head.find('#') {
                let proxy = head[idx + 1..].trim();
                if proxy.is_empty() {
                    return Err(NameServerParseError::InvalidHost(s.to_string()));
                }
                let url = NameServerUrl::parse(&head[..idx])?;
                return Ok(Self {
                    url,
                    proxy: Some(proxy.to_string()),
                });
            }
        }
        Ok(Self {
            url: NameServerUrl::parse(head)?,
            proxy: query_proxy,
        })
    }
}

impl From<NameServerUrl> for NameServerEntry {
    fn from(url: NameServerUrl) -> Self {
        Self::plain(url)
    }
}

impl NameServerUrl {
    /// Returns `Some(hostname)` if this entry needs bootstrap DNS resolution,
    /// `None` if the address is already an IP literal.
    pub fn needs_bootstrap(&self) -> Option<&str> {
        let addr = match self {
            NameServerUrl::Udp { addr, .. }
            | NameServerUrl::Tcp { addr, .. }
            | NameServerUrl::Tls { addr, .. }
            | NameServerUrl::Https { addr, .. } => addr,
            NameServerUrl::RCode { .. } => return None,
        };
        match addr {
            HostOrIp::Host(h) => Some(h.as_str()),
            HostOrIp::Ip(_) => None,
        }
    }

    /// Returns true if this is a plain (non-encrypted) nameserver.
    pub fn is_plain(&self) -> bool {
        matches!(
            self,
            NameServerUrl::Udp { .. } | NameServerUrl::Tcp { .. } | NameServerUrl::RCode { .. }
        )
    }

    /// Parse a nameserver string into a `NameServerUrl`.
    ///
    /// Accepted forms:
    /// - `8.8.8.8` / `8.8.8.8:53`  — plain UDP
    /// - `dns.google` / `dns.google:53`  — plain UDP with hostname
    /// - `udp://host[:port]`
    /// - `tcp://host[:port]`
    /// - `tls://host[:port][#sni]`
    /// - `https://host[:port][/path][#sni]`
    pub fn parse(s: &str) -> Result<Self, NameServerParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NameServerParseError::EmptyInput);
        }

        // Split off #fragment before any URL parsing — the fragment is NOT a
        // standard URL anchor in this context; it carries the SNI override.
        let (s_no_frag, fragment) = match s.find('#') {
            Some(idx) => (&s[..idx], Some(&s[idx + 1..])),
            None => (s, None),
        };

        // Dispatch on scheme
        if let Some(rest) = s_no_frag.strip_prefix("tls://") {
            return Self::parse_tls(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("https://") {
            return Self::parse_https(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("udp://") {
            let (addr, port) = parse_host_port(rest, 53)?;
            return Ok(NameServerUrl::Udp { addr, port });
        }
        if let Some(rest) = s_no_frag.strip_prefix("tcp://") {
            let (addr, port) = parse_host_port(rest, 53)?;
            return Ok(NameServerUrl::Tcp { addr, port });
        }
        if let Some(rest) = s_no_frag.strip_prefix("rcode://") {
            return parse_rcode(rest);
        }
        if s_no_frag.starts_with("quic://") {
            return Err(NameServerParseError::QuicNotSupported);
        }
        // Any other explicit scheme → unsupported
        if let Some(colon) = s_no_frag.find("://") {
            let scheme = &s_no_frag[..colon];
            // Make sure it's actually a scheme (letters only, reasonable length)
            if scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                && colon <= 20
            {
                return Err(NameServerParseError::UnsupportedScheme(scheme.to_string()));
            }
        }

        // No scheme — bare IP or hostname, defaults to UDP port 53
        let (addr, port) = parse_host_port(s_no_frag, 53)?;
        Ok(NameServerUrl::Udp { addr, port })
    }

    #[cfg(feature = "encrypted")]
    fn parse_tls(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        let (addr, port) = parse_host_port(rest, 853)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            // Default SNI = the host string (IP or hostname)
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Tls { addr, port, sni })
    }

    #[cfg(not(feature = "encrypted"))]
    fn parse_tls(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::EncryptedFeatureDisabled)
    }

    #[cfg(feature = "encrypted")]
    fn parse_https(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        // Split path off the host[:port] portion. Path starts at first '/' after host.
        let (hostport, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/dns-query".to_string()),
        };
        // Ensure path starts with /
        let path = if path.is_empty() {
            "/dns-query".to_string()
        } else {
            path
        };

        let (addr, port) = parse_host_port(hostport, 443)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Https {
            addr,
            port,
            path,
            sni,
        })
    }

    #[cfg(not(feature = "encrypted"))]
    fn parse_https(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::EncryptedFeatureDisabled)
    }
}

fn parse_rcode(s: &str) -> Result<NameServerUrl, NameServerParseError> {
    let label = s.trim();
    let code = match label {
        "success" => ResponseCode::NoError,
        "format_error" => ResponseCode::FormErr,
        "server_failure" => ResponseCode::ServFail,
        "name_error" => ResponseCode::NXDomain,
        "not_implemented" => ResponseCode::NotImp,
        "refused" => ResponseCode::Refused,
        _ => return Err(NameServerParseError::UnsupportedRCode(label.to_string())),
    };
    Ok(NameServerUrl::RCode {
        code,
        label: label.to_string(),
    })
}

/// Parse `host:port` or `[ipv6]:port` or bare `host`, returning `(HostOrIp, port)`.
/// `default_port` is used when no port is present.
fn parse_host_port(s: &str, default_port: u16) -> Result<(HostOrIp, u16), NameServerParseError> {
    // IPv6 bracketed form: [::1]:853 or [::1]
    if s.starts_with('[') {
        let close = s
            .find(']')
            .ok_or_else(|| NameServerParseError::InvalidHost(s.to_string()))?;
        let ipv6_str = &s[1..close];
        let ip: IpAddr = ipv6_str
            .parse()
            .map_err(|_| NameServerParseError::InvalidHost(s.to_string()))?;
        let port = if close + 1 < s.len() {
            let port_str = s[close + 1..]
                .strip_prefix(':')
                .ok_or_else(|| NameServerParseError::InvalidHost(s.to_string()))?;
            parse_port(port_str)?
        } else {
            default_port
        };
        return Ok((HostOrIp::Ip(ip), port));
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((HostOrIp::Ip(ip), default_port));
    }

    if let Some(idx) = s.rfind(':') {
        let maybe_port = &s[idx + 1..];
        if maybe_port.chars().all(|c| c.is_ascii_digit()) {
            let port = parse_port(maybe_port)?;
            let host_str = &s[..idx];
            let addr = parse_host_or_ip(host_str)?;
            return Ok((addr, port));
        }
    }

    // No port — use default
    let addr = parse_host_or_ip(s)?;
    Ok((addr, default_port))
}

fn parse_host_or_ip(s: &str) -> Result<HostOrIp, NameServerParseError> {
    if s.is_empty() {
        return Err(NameServerParseError::InvalidHost(s.to_string()));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(HostOrIp::Ip(ip));
    }
    // Validate it looks like a hostname (not arbitrary junk). `?` and `&`
    // must never reach the hostname slot: a `?proxy=` tail that was not
    // stripped (e.g. `tls://h?x`, or `?x` on a scheme that does not take
    // parameters) would otherwise be swallowed into the host silently.
    if s.contains('/') || s.contains(' ') || s.contains('?') || s.contains('&') {
        return Err(NameServerParseError::InvalidHost(s.to_string()));
    }
    Ok(HostOrIp::Host(s.to_string()))
}

fn parse_port(s: &str) -> Result<u16, NameServerParseError> {
    s.parse::<u32>()
        .ok()
        .filter(|&p| p > 0 && p <= 65535)
        .map(|p| p as u16)
        .ok_or_else(|| NameServerParseError::InvalidPort(s.to_string()))
}

/// Parse error for `NameServerUrl::parse`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameServerParseError {
    #[error("nameserver string is empty")]
    EmptyInput,
    #[error(
        "nameserver uses the 'quic' scheme which is not yet supported; tracked as roadmap M1.E-6 / M2. Use 'tls://' or 'https://' for now."
    )]
    QuicNotSupported,
    #[error("nameserver uses unsupported scheme '{0}'")]
    UnsupportedScheme(String),
    #[error("invalid host in nameserver: '{0}'")]
    InvalidHost(String),
    #[error("invalid port in nameserver: '{0}'")]
    InvalidPort(String),
    #[error(
        "encrypted DNS (tls:// / https://) requires the 'encrypted' Cargo feature to be enabled"
    )]
    EncryptedFeatureDisabled,
    #[error("unsupported rcode nameserver type '{0}'")]
    UnsupportedRCode(String),
    #[error("invalid nameserver parameters: {0}")]
    InvalidParams(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> HostOrIp {
        HostOrIp::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }
    fn host(s: &str) -> HostOrIp {
        HostOrIp::Host(s.to_string())
    }

    // A1
    #[test]
    fn parse_plain_bare_ip() {
        let url = NameServerUrl::parse("8.8.8.8").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 53
            }
        );
    }

    #[test]
    fn parse_plain_bare_ipv6_preserves_address_and_default_port() {
        for literal in [
            "2402:4e00::",
            "::1",
            "2001:db8::8888",
            "2001:db8::abcd",
            "2001:db8::1:853",
            "::ffff:192.0.2.1",
        ] {
            let addr = HostOrIp::Ip(literal.parse().unwrap());
            for prefix in ["", "udp://", "tcp://"] {
                let input = format!("{prefix}{literal}");
                let expected = if prefix == "tcp://" {
                    NameServerUrl::Tcp {
                        addr: addr.clone(),
                        port: 53,
                    }
                } else {
                    NameServerUrl::Udp {
                        addr: addr.clone(),
                        port: 53,
                    }
                };
                assert_eq!(NameServerUrl::parse(&input).unwrap(), expected, "{input}");
            }
        }
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_encrypted_bare_ipv6_uses_transport_default_port() {
        for literal in ["2402:4e00::", "::1", "2001:db8::1:853"] {
            let addr = HostOrIp::Ip(literal.parse().unwrap());
            let sni = addr.to_string();
            assert_eq!(
                NameServerUrl::parse(&format!("tls://{literal}")).unwrap(),
                NameServerUrl::Tls {
                    addr: addr.clone(),
                    port: 853,
                    sni: sni.clone()
                },
            );
            assert_eq!(
                NameServerUrl::parse(&format!("https://{literal}/dns-query")).unwrap(),
                NameServerUrl::Https {
                    addr,
                    port: 443,
                    path: "/dns-query".into(),
                    sni
                },
            );
        }
    }

    #[test]
    fn parse_bracketed_ipv6_keeps_explicit_ports() {
        let addr = HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        for prefix in ["", "udp://", "tcp://"] {
            let input = format!("{prefix}[::1]:5353");
            let expected = if prefix == "tcp://" {
                NameServerUrl::Tcp {
                    addr: addr.clone(),
                    port: 5353,
                }
            } else {
                NameServerUrl::Udp {
                    addr: addr.clone(),
                    port: 5353,
                }
            };
            assert_eq!(NameServerUrl::parse(&input).unwrap(), expected, "{input}");
        }
        for port in ["0", "65536", "invalid"] {
            assert!(matches!(
                NameServerUrl::parse(&format!("[::1]:{port}")),
                Err(NameServerParseError::InvalidPort(_)),
            ));
        }
    }

    // A2
    #[test]
    fn parse_plain_bare_ip_with_port() {
        let url = NameServerUrl::parse("8.8.8.8:5353").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 5353
            }
        );
    }

    // A3
    #[test]
    fn parse_udp_scheme() {
        let url = NameServerUrl::parse("udp://1.1.1.1").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 53
            }
        );
    }

    // A4
    #[test]
    fn parse_udp_scheme_with_port() {
        let url = NameServerUrl::parse("udp://1.1.1.1:5353").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 5353
            }
        );
    }

    // A5
    #[test]
    fn parse_tcp_scheme() {
        let url = NameServerUrl::parse("tcp://1.1.1.1:53").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tcp {
                addr: ip4(1, 1, 1, 1),
                port: 53
            }
        );
    }

    // A6
    // Upstream: component/resolver/parser.go::parseNameServer case "tls" — defaults port to DoTPort (853) and uses host as SNI.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_default_port_and_sni() {
        let url = NameServerUrl::parse("tls://dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A7
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_explicit_port() {
        let url = NameServerUrl::parse("tls://dns.google:8853").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 8853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A8
    // Upstream: same function, u.Fragment branch.
    // NOT: the '#' fragment is not a standard URL anchor; extracted manually.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_explicit_sni() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A9
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_ip_literal_no_sni_uses_ip_string() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853").unwrap();
        match &url {
            NameServerUrl::Tls { addr, sni, .. } => {
                assert_eq!(addr, &ip4(8, 8, 8, 8));
                assert!(!sni.is_empty());
            }
            _ => panic!("expected Tls"),
        }
        assert_eq!(url.needs_bootstrap(), None);
    }

    // A10
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_default_path_and_port() {
        let url = NameServerUrl::parse("https://cloudflare-dns.com").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: host("cloudflare-dns.com"),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
            }
        );
    }

    // A11
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_explicit_path() {
        let url = NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/dns-query"),
            _ => panic!("expected Https"),
        }
    }

    // A12
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_explicit_port_and_path() {
        let url = NameServerUrl::parse("https://1.1.1.1:8443/custom-path").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 8443,
                path: "/custom-path".to_string(),
                sni: "1.1.1.1".to_string(),
            }
        );
    }

    // A13
    // Upstream: same u.Fragment branch for DoH.
    // NOT: sni must override cert validation even when dial target is the IP.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_explicit_sni_on_ip() {
        let url = NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
            }
        );
    }

    // A14
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_hostname_sni_override() {
        let url = NameServerUrl::parse("https://dns.google/dns-query#override.example").unwrap();
        match &url {
            NameServerUrl::Https { addr, sni, .. } => {
                assert_eq!(addr, &host("dns.google"));
                assert_eq!(sni, "override.example");
            }
            _ => panic!("expected Https"),
        }
    }

    // A15 — IPv6 trip-wire: a naive split(':') parser breaks here.
    // Upstream: uses net.SplitHostPort which handles brackets. NOT a split-on-colon path.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_ipv6_bracketed() {
        let url = NameServerUrl::parse("https://[2606:4700:4700::1111]/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { addr, .. } => {
                let expected: IpAddr = "2606:4700:4700::1111".parse().unwrap();
                assert_eq!(addr, &HostOrIp::Ip(expected));
            }
            _ => panic!("expected Https"),
        }
    }

    // A16
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_ipv6_with_port_bracketed() {
        let url = NameServerUrl::parse("https://[::1]:853/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { addr, port, .. } => {
                assert_eq!(addr, &HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
                assert_eq!(*port, 853);
            }
            _ => panic!("expected Https"),
        }
    }

    // A17 — Class A per ADR-0002: user assumes encrypted DNS, gets nothing.
    // Upstream: DoQ supported since Go mihomo ~1.15. NOT silent drop.
    #[test]
    fn parse_quic_rejected() {
        let err = NameServerUrl::parse("quic://dns.adguard.com").unwrap_err();
        assert!(matches!(err, NameServerParseError::QuicNotSupported));
        assert!(
            err.to_string().contains("M1.E-6"),
            "error message must cite M1.E-6 roadmap item"
        );
    }

    // A18 — Class A per ADR-0002: silent-drop bug in upstream.
    // Upstream: parseNameServer logs warn and drops entry. NOT a warn.
    #[test]
    fn parse_unknown_scheme() {
        let err = NameServerUrl::parse("sdns://something").unwrap_err();
        assert!(matches!(err, NameServerParseError::UnsupportedScheme(ref s) if s == "sdns"));
    }

    #[test]
    fn parse_rcode_success() {
        let url = NameServerUrl::parse("rcode://success").unwrap();
        assert_eq!(
            url,
            NameServerUrl::RCode {
                code: ResponseCode::NoError,
                label: "success".to_string(),
            }
        );
        assert_eq!(url.to_string(), "rcode://success");
        assert_eq!(url.needs_bootstrap(), None);
    }

    #[test]
    fn parse_rcode_unknown_errors() {
        let err = NameServerUrl::parse("rcode://unknown").unwrap_err();
        assert!(matches!(err, NameServerParseError::UnsupportedRCode(ref s) if s == "unknown"));
    }

    // A19
    #[test]
    fn parse_empty_string_errors() {
        assert!(matches!(
            NameServerUrl::parse("").unwrap_err(),
            NameServerParseError::EmptyInput
        ));
    }

    // A20
    #[test]
    fn parse_invalid_port_errors() {
        assert!(matches!(
            NameServerUrl::parse("1.1.1.1:99999").unwrap_err(),
            NameServerParseError::InvalidPort(_)
        ));
    }

    // A21
    // Upstream: parseNameServer defaults bare entries to UDP. We match.
    #[test]
    fn parse_bare_hostname_no_scheme() {
        let url = NameServerUrl::parse("dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: host("dns.google"),
                port: 53
            }
        );
        assert_eq!(url.needs_bootstrap(), Some("dns.google"));
    }

    // A22
    #[test]
    fn needs_bootstrap_ip_literal_returns_none() {
        let udp = NameServerUrl::parse("8.8.8.8").unwrap();
        assert_eq!(udp.needs_bootstrap(), None);
        #[cfg(feature = "encrypted")]
        {
            let tls = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
            assert_eq!(tls.needs_bootstrap(), None);
            let https =
                NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
            assert_eq!(https.needs_bootstrap(), None);
        }
    }

    // A23
    #[cfg(feature = "encrypted")]
    #[test]
    fn needs_bootstrap_hostname_returns_some() {
        let tls = NameServerUrl::parse("tls://dns.google").unwrap();
        assert_eq!(tls.needs_bootstrap(), Some("dns.google"));
        let https = NameServerUrl::parse("https://cloudflare-dns.com").unwrap();
        assert_eq!(https.needs_bootstrap(), Some("cloudflare-dns.com"));
    }

    // G1
    #[test]
    fn all_url_forms_display_contains_host() {
        let cases: &[&str] = if cfg!(feature = "encrypted") {
            &[
                "udp://8.8.8.8:53",
                "tcp://8.8.8.8:53",
                "tls://dns.google:853#dns.google",
                "https://cloudflare-dns.com:443/dns-query#cloudflare-dns.com",
            ]
        } else {
            &["udp://8.8.8.8:53", "tcp://8.8.8.8:53"]
        };
        for s in cases {
            let url = NameServerUrl::parse(s).unwrap();
            let display = url.to_string();
            assert!(!display.is_empty(), "display must not be empty for {s}");
        }
    }

    // G2
    #[test]
    fn parse_error_is_non_exhaustive_match() {
        let err = NameServerUrl::parse("").unwrap_err();
        // This match must compile — the wildcard arm ensures #[non_exhaustive] is respected.
        let _msg = match err {
            NameServerParseError::EmptyInput => "empty",
            NameServerParseError::QuicNotSupported => "quic",
            NameServerParseError::UnsupportedScheme(_) => "unsupported",
            NameServerParseError::InvalidHost(_) => "invalid host",
            NameServerParseError::InvalidPort(_) => "invalid port",
            NameServerParseError::UnsupportedRCode(_) => "rcode",
            _ => "other",
        };
    }

    // D4: without the `encrypted` feature, tls:// must hard-error mentioning the feature name.
    #[cfg(not(feature = "encrypted"))]
    #[test]
    fn parse_tls_without_encrypted_feature_hard_errors() {
        let result = NameServerUrl::parse("tls://8.8.8.8");
        assert!(
            result.is_err(),
            "tls:// without encrypted feature must error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("encrypted"),
            "error message must mention the 'encrypted' feature, got: {msg}"
        );
    }

    // ─── #PROXY suffix parsing (issue #67 phase 2, ADR-0012) ──────────────

    #[test]
    fn entry_no_proxy_default() {
        let e = NameServerEntry::parse("8.8.8.8").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 53,
            }
        );
    }

    #[test]
    fn entry_plain_udp_with_proxy_tag() {
        let e = NameServerEntry::parse("1.1.1.1#PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 53,
            }
        );
    }

    #[test]
    fn entry_tcp_scheme_with_proxy_tag() {
        let e = NameServerEntry::parse("tcp://1.1.1.1:53#PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert!(matches!(e.url, NameServerUrl::Tcp { .. }));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_fragment_is_sni_not_proxy() {
        // For tls:// the `#` is SNI per the existing parser; the
        // NameServerEntry layer must NOT steal that fragment as a proxy
        // name — the proxy slot for encrypted entries is the implemented
        // `?proxy=NAME` parameter section (ADR-0012).
        let e = NameServerEntry::parse("tls://1.1.1.1:853#dns.google").unwrap();
        assert!(e.proxy.is_none());
        assert!(matches!(e.url, NameServerUrl::Tls { .. }));
    }

    #[test]
    fn entry_empty_proxy_tag_errors() {
        // `1.1.1.1#` with nothing after the # is a typo, not "no proxy."
        let err = NameServerEntry::parse("1.1.1.1#").unwrap_err();
        assert!(matches!(err, NameServerParseError::InvalidHost(_)));
    }

    // ─── `?proxy=` parameter section (ADR-0012, issue #67 phase 2) ──────
    //
    // Canonical rule: a `?` parameter section is only legal on `tls://` /
    // `https://` entries. Using the entry's *last* `?` as the boundary:
    // when any `&`-separated segment of the tail is a `proxy=` key, that
    // `?` section is a parameter section — an `&`-separated `k=v` list
    // whose only currently-legal key is `proxy`. The `proxy` value must
    // be non-empty and must not contain `#`/`?`/`&`; any other key is a
    // hard `InvalidParams`. When no `&`-separated segment is a `proxy=`
    // key, the `?` section is not a parameter section and stays in the
    // URL (path) verbatim. Detection of the `proxy=` key is ASCII
    // case-insensitive; only exact lowercase `proxy` is legal —
    // `?Proxy=`/`?PROXY=` are hard `InvalidParams`, never path params.

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_query_proxy_with_sni() {
        let e = NameServerEntry::parse("tls://8.8.8.8#dns.google?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "dns.google".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_query_proxy_default_sni() {
        let e = NameServerEntry::parse("tls://8.8.8.8?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "8.8.8.8".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_hostname_upstream_with_proxy() {
        // The flagship form: the hostname is left to the proxy for remote
        // resolution — the entry itself parses to Host + proxy tag.
        let e = NameServerEntry::parse("tls://dns.google?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 853,
                sni: "dns.google".to_string(),
            }
        );
        assert_eq!(e.url.needs_bootstrap(), Some("dns.google"));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_https_sni_path_and_proxy() {
        let e =
            NameServerEntry::parse("https://1.1.1.1/dns-query#cloudflare-dns.com?proxy=PROXY-JP")
                .unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_https_path_and_proxy() {
        let e = NameServerEntry::parse("https://1.1.1.1/dns-query?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "1.1.1.1".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_https_non_proxy_query_stays_in_path() {
        // `?x=1` carries no `proxy=` key — the `?` section is part of the
        // DoH path and must pass through verbatim.
        let e = NameServerEntry::parse("https://h/dns-query?x=1").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Https {
                addr: host("h"),
                port: 443,
                path: "/dns-query?x=1".to_string(),
                sni: "h".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_in_later_key_is_params_section() {
        // A `proxy=` key anywhere in the `&`-separated tail marks the `?`
        // section as a parameter section — `?a=b&proxy=P` must hard-error
        // on the unknown `a` key, not silently keep the whole tail in the
        // path and lose the proxy intent (r15 review I1).
        for s in [
            "https://h/dns-query?a=b&proxy=P",
            "https://h/dns-query?a=b&proxy=P&c=d",
            "tls://h?x=1&proxy=P",
            "tls://h?x&proxy=P",
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
        // `proxy` is still the only legal key — including in first place.
        for s in ["https://h/p?proxy=P&x=1", "https://h/p?x=1&proxy="] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
        // Non-`proxy=` tails — including look-alikes — still stay in the
        // path verbatim.
        for s in ["https://h/p?proxi=P", "https://h/p?x=a=proxy=P"] {
            let e = NameServerEntry::parse(s).unwrap();
            assert!(e.proxy.is_none(), "{s} must not tag a proxy");
        }
        let e = NameServerEntry::parse("https://h/p?proxi=P").unwrap();
        match e.url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/p?proxi=P"),
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn entry_plain_with_query_params_errors() {
        // `?` on a plain entry used to be silently folded into the
        // hostname — now a hard `InvalidParams`.
        for s in [
            "8.8.8.8?proxy=P",
            "8.8.8.8?x=1",
            "udp://1.1.1.1?proxy=P",
            // Any `?` on a plain entry is a hard error regardless of
            // case — the `proxy=`-key case distinction is an
            // encrypted-forms-only concept.
            "udp://1.1.1.1?Proxy=P",
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_fragment_and_query_proxy_conflict_errors() {
        // `#P` next to `?proxy=` is a bare fragment — under `#`=SNI
        // semantics it is indistinguishable from a second proxy tag, so
        // it is a config bug, not an SNI.
        for s in [
            "tls://8.8.8.8#P?proxy=Q",
            "tls://8.8.8.8#PROXY?proxy=Q",
            "https://1.1.1.1/dns-query#P?proxy=Q",
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
        // A dotted SNI is unambiguous — stays legal.
        let e = NameServerEntry::parse("tls://8.8.8.8#dns.google?proxy=Q").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("Q"));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_hard_errors() {
        for s in [
            "tls://8.8.8.8?proxy=",            // empty proxy name
            "tls://8.8.8.8?proxy=P&h3=true",   // unknown key
            "tls://8.8.8.8?proxy=P&proxy=Q",   // duplicate key
            "tls://8.8.8.8?proxy=P#sni&x",     // & residue in fragment
            "tls://8.8.8.8#sni&proxy=P",       // mihomo-style params in fragment
            "https://h/p?proxy=P&ecs=1.2.3.4", // reserved-but-unimplemented key
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
    }

    /// Case hardening on the `?proxy=` key: detection of a `proxy=` segment
    /// is ASCII case-insensitive (closing the leak where `?Proxy=P` survived
    /// into the stored DoH request path), while validation stays exact —
    /// only the lowercase `proxy` spelling is legal, so a case-variant key
    /// is a hard `InvalidParams` that names the canonical spelling.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_case_variant_hard_errors() {
        // Variants that hit the canonical-spelling hint — the case-variant
        // key is the first failure the validation loop sees.
        for s in [
            "tls://8.8.8.8?Proxy=P",
            "tls://8.8.8.8?PROXY=P",
            "tls://8.8.8.8?pRoXy=P",
            "https://h/dns-query?Proxy=P", // was the silent path leak
            "tls://8.8.8.8#dns.google?Proxy=P", // SNI + variant
            "https://h?Proxy=P",           // pins the InvalidHost → InvalidParams flip
        ] {
            match NameServerEntry::parse(s) {
                Err(NameServerParseError::InvalidParams(msg)) => assert!(
                    msg.contains("lowercase 'proxy'"),
                    "{s} must hint the canonical spelling; got: {msg}"
                ),
                other => panic!("{s} must be InvalidParams, got {other:?}"),
            }
        }
        // A case-variant segment in a non-first `&` position still marks
        // the section — it errors as InvalidParams (here on the unknown
        // `x` key first; either way the proxy name never reaches a path).
        let s = "https://h/dns-query?x=1&PROXY=P";
        assert!(
            matches!(
                NameServerEntry::parse(s),
                Err(NameServerParseError::InvalidParams(_))
            ),
            "{s} must be InvalidParams"
        );
        // Look-alikes stay unchanged: `?Proxy` bare (no `=`, so nothing
        // leakable) keeps the whole `?` section in the path, as do the
        // `proxi=` / `x=a=proxy=` near-misses covered above.
        for s in [
            "https://h/p?Proxy",
            "https://h/p?proxi=P",
            "https://h/p?x=a=proxy=P",
        ] {
            let e = NameServerEntry::parse(s).unwrap();
            assert!(e.proxy.is_none(), "{s} must not tag a proxy");
        }
        let e = NameServerEntry::parse("https://h/p?Proxy").unwrap();
        match e.url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/p?Proxy"),
            _ => panic!("expected Https"),
        }
        // Batch-3 boundary: a case-variant segment stranded by a *later*
        // `?` section keeps the old case-sensitive treatment — it stays
        // in the path with no error (median widening is batch 3's scope;
        // the warn is deliberately not asserted here).
        let e = NameServerEntry::parse("https://h/p?Proxy=P?x=1").unwrap();
        assert!(e.proxy.is_none());
        match e.url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/p?Proxy=P?x=1"),
            _ => panic!("expected Https"),
        }
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_question_mark_in_hostname_errors() {
        // A non-`proxy=` `?` tail stays in the URL — for tls:// there is
        // no path to hold it, so it lands in the hostname, which must
        // hard-error rather than silently accept `h?x` / `h&x` as hosts.
        for s in ["tls://h?x", "tls://h&x", "tls://h?x&proxy=P"] {
            assert!(NameServerEntry::parse(s).is_err(), "{s} must error");
        }
        assert!(matches!(
            NameServerEntry::parse("tls://h?x"),
            Err(NameServerParseError::InvalidHost(_))
        ));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_fragment_sni_without_proxy_unchanged() {
        // `#dns.google` alone keeps its SNI meaning — the divergence from
        // mihomo (which reads it as a proxy name) is documented, not
        // silently flipped.
        let e = NameServerEntry::parse("tls://8.8.8.8#PROXY").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "PROXY".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_value_is_trimmed() {
        // Same contract as the `#PROXY` slot (`head[idx + 1..].trim()`):
        // `?proxy= P` tags the proxy named `P`, not ` P `.
        let e = NameServerEntry::parse("tls://8.8.8.8?proxy= P ").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("P"));
        // All-whitespace is still an empty (invalid) name.
        assert!(matches!(
            NameServerEntry::parse("tls://8.8.8.8?proxy= "),
            Err(NameServerParseError::InvalidParams(_))
        ));
    }

    /// `?proxy=P?x=1` — a `proxy=` segment stranded by a *later* `?`
    /// section is silently folded into the request path. That is not a
    /// hard error (a legitimate path can carry the substring), but it
    /// must warn so the likely-typo is visible. Scoped-subscriber
    /// capture, same pattern as meow-config's `capture_warns`.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_path_retained_proxy_segment_warns() {
        let ((), logs) = capture_warns(|| {
            // The double-`?` typo: last `?` tail `x=1` is not a
            // parameter section, so `?proxy=P` stays inside the path…
            let e = NameServerEntry::parse("https://h/dns-query?proxy=P?x=1").unwrap();
            assert!(e.proxy.is_none());
            match e.url {
                NameServerUrl::Https { path, .. } => {
                    assert_eq!(path, "/dns-query?proxy=P?x=1");
                }
                _ => panic!("expected Https"),
            }
            // …and an `&`-stranded segment warns the same way…
            let e = NameServerEntry::parse("https://h/p?x=1&proxy=P?y=2").unwrap();
            assert!(e.proxy.is_none());
            // …while these stay silent: a clean `?` tail, and a
            // `proxy=` substring that is not a `?`/`&` segment start.
            let e = NameServerEntry::parse("https://h/p?x=1").unwrap();
            assert!(e.proxy.is_none());
            let e = NameServerEntry::parse("https://h/p?a=proxy=1?x=1").unwrap();
            assert!(e.proxy.is_none());
        });
        assert_eq!(
            logs.matches("keeps a 'proxy=' segment").count(),
            2,
            "exactly the two stranded-proxy-segment entries must warn; got: {logs}"
        );
        assert!(
            logs.contains("Did you mean to move '?proxy=NAME' last?"),
            "the warn must name the likely fix; got: {logs}"
        );
    }

    /// `tracing` caches per-callsite `Interest` process-globally, and any
    /// `with_default` enter/exit rebuilds that cache. A `warn!` evaluated
    /// on a parallel test thread while no subscriber is active then
    /// caches `Interest::never` — and the event is dropped *even inside a
    /// later `with_default` scope*, which flakes the scoped warn-capture
    /// test. Installing a discarding GLOBAL default once makes bare
    /// threads register `always`/`never` under it instead. Mirrors
    /// meow-config `test_support::install_global_discard_subscriber`.
    #[cfg(feature = "encrypted")]
    fn install_global_discard_subscriber() {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(std::io::sink)
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .finish(),
        );
    }

    /// Scoped WARN capture — `with_default` is thread-local, so parallel
    /// tests in this binary don't see each other's lines. Mirrors
    /// meow-config `proxy_parser`'s `capture_warns`.
    #[cfg(feature = "encrypted")]
    fn capture_warns<R>(f: impl FnOnce() -> R) -> (R, String) {
        install_global_discard_subscriber();
        #[derive(Clone)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let captured = sink.0.lock().unwrap();
        (out, String::from_utf8_lossy(&captured).into_owned())
    }
}
