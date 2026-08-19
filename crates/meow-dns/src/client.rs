//! Internal DNS client transports — UDP, TCP, DoT, DoH.
//!
//! Sockets are created through a pluggable [`SocketFactory`] so the caller
//! (e.g. an Android VPN service) can intercept fd creation and call
//! `protect()` before the socket is used. This is the reason the project
//! ships its own DNS client instead of relying on `hickory-resolver`.

use crate::cache::QueryFamilies;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[cfg(feature = "encrypted")]
use {rustls::pki_types::ServerName, std::convert::TryFrom, tokio_rustls::TlsConnector};

/// Default per-query timeout (matches the hickory-resolver value previously
/// used in `Resolver::build_*`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Factory that creates the raw sockets the DNS client transports run on.
///
/// Implementations may call platform-specific hooks (Android `protect()`,
/// Linux `SO_MARK`, …) before returning the socket so DNS traffic bypasses
/// the local VPN tunnel.
pub trait SocketFactory: Send + Sync + 'static {
    /// Bind an unconnected UDP socket. Implementations typically bind to
    /// `0.0.0.0:0`.
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>>;

    /// Open an outbound TCP connection to `addr`.
    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
}

/// Tokio default factory: routes through [`meow_common::bind_udp`] /
/// [`meow_common::connect_tcp`] so the Android `VpnService.protect(fd)`
/// hook (when installed) covers DNS upstream sockets too.
struct DefaultSocketFactory;

impl SocketFactory for DefaultSocketFactory {
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async {
            // Bind to v4 unspecified; this is fine because we always
            // `connect()` the socket before sending, and connect() will
            // re-resolve the local address family.
            meow_common::bind_udp(SocketAddr::from(([0u8; 4], 0))).await
        })
    }

    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move { meow_common::connect_tcp(addr).await })
    }
}

static SOCKET_FACTORY: OnceLock<Arc<dyn SocketFactory>> = OnceLock::new();
static DEFAULT_FACTORY: DefaultSocketFactory = DefaultSocketFactory;

/// Install a custom [`SocketFactory`]. Can only be called once; subsequent
/// calls return the supplied factory unchanged so the caller can detect the
/// programming error.
pub fn set_socket_factory(factory: Arc<dyn SocketFactory>) -> Result<(), Arc<dyn SocketFactory>> {
    SOCKET_FACTORY.set(factory)
}

fn factory() -> &'static dyn SocketFactory {
    match SOCKET_FACTORY.get() {
        Some(f) => f.as_ref(),
        None => &DEFAULT_FACTORY,
    }
}

/// All errors produced by the internal DNS client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("dns proto: {0}")]
    Proto(#[from] hickory_proto::ProtoError),
    #[error("dns decode: {0}")]
    Decode(#[from] hickory_proto::serialize::binary::DecodeError),
    #[error("query timed out after {0:?}")]
    Timeout(Duration),
    #[error("invalid response: {0}")]
    Protocol(&'static str),
    #[error("tls: {0}")]
    Tls(String),
    #[error("upstream returned rcode {0:?}")]
    Rcode(hickory_proto::op::ResponseCode),
}

/// Optional proxy adapter for routing DNS queries through. When set, the
/// TCP exchange is performed via `proxy.dial_tcp` instead of
/// `factory().connect_tcp` — see ADR-0012 (issue #67 phase 2).
pub type DnsProxy = Arc<dyn meow_common::Proxy>;

/// A single DNS upstream the resolver can query.
pub struct DnsClient {
    transport: Transport,
    timeout: Duration,
    proxy: Option<DnsProxy>,
    label: Option<Arc<str>>,
}

pub(crate) struct IpLookupResult {
    pub(crate) ips: Vec<IpAddr>,
    pub(crate) ttl: Duration,
    /// Preserve the per-family result for the BOTH path. The aggregate IP list
    /// is sufficient for callers that only need addresses, but the resolver
    /// cache also needs to retain NXDOMAIN versus NODATA.
    pub(crate) v4: Option<FamilyAnswer>,
    pub(crate) v6: Option<FamilyAnswer>,
}

pub(crate) enum FamilyLookupResult {
    Response(IpLookupResult),
    /// Authoritative "name does not exist". Carries the RFC 2308 negative
    /// cache TTL — `min(SOA.TTL, SOA.MINIMUM)` from the authority section, or
    /// `0` when the upstream omitted the SOA (the resolver's clamp floor
    /// still gives it a short cache lifetime).
    NxDomain(Duration),
}

/// One family's answer within a [`FamilySet`]. The resolver/cache consume this
/// unified shape so the per-family and "all enabled families" lookup paths
/// share one pipeline (review issue J). TTLs are the raw upstream values; the
/// resolver clamps them once before use.
#[derive(Clone, Debug)]
pub(crate) enum FamilyAnswer {
    /// NOERROR with at least one address record of this family.
    Answer { ips: Vec<IpAddr>, ttl: Duration },
    /// NOERROR with zero address records of this family (NODATA). Carries the
    /// upstream TTL so the cache can expire the negative on its own schedule.
    NoData(Duration),
    /// The upstream authoritatively said the name does not exist. Carries the
    /// RFC 2308 negative cache TTL (SOA-derived) so the cache can serve the
    /// NXDOMAIN rcode from cache for that family until its own expiry fires,
    /// damping DGA/retry-loop load (aligns with mihomo `putMsgToCache`).
    NxDomain(Duration),
    /// A network/timeout failure for this family — not a definitive answer.
    Failed,
}

/// A client's resolution result across the requested family set. `None` for a
/// family means "not queried" (e.g. the prefer-IPv4 path skips AAAA once A has
/// addresses); the resolver treats that as a cache miss for the family and
/// re-queries on demand.
#[derive(Clone, Debug)]
pub(crate) struct FamilySet {
    pub(crate) v4: Option<FamilyAnswer>,
    pub(crate) v6: Option<FamilyAnswer>,
    pub(crate) source: String,
}

enum Transport {
    Udp {
        addr: SocketAddr,
    },
    Tcp {
        addr: SocketAddr,
    },
    #[cfg(feature = "encrypted")]
    Dot {
        addr: SocketAddr,
        sni: Arc<str>,
        tls: Arc<rustls::ClientConfig>,
    },
    #[cfg(feature = "encrypted")]
    Doh {
        addr: SocketAddr,
        sni: Arc<str>,
        path: Arc<str>,
        tls: Arc<rustls::ClientConfig>,
    },
    RCode {
        code: ResponseCode,
    },
}

impl DnsClient {
    /// Plain DNS over UDP.
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Udp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
        }
    }

    /// Plain DNS over TCP (RFC 7766 length-prefixed framing).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Tcp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
        }
    }

    /// Synthetic DNS response with a fixed response code and no answers.
    pub fn rcode(code: ResponseCode) -> Self {
        Self {
            transport: Transport::RCode { code },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
        }
    }

    /// DNS over TLS (RFC 7858).
    #[cfg(feature = "encrypted")]
    pub fn dot(addr: SocketAddr, sni: &str) -> Self {
        Self {
            transport: Transport::Dot {
                addr,
                sni: Arc::from(sni),
                tls: tls_client_config("dot"),
            },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
        }
    }

    /// DNS over HTTPS (RFC 8484) — HTTP/1.1 POST application/dns-message.
    #[cfg(feature = "encrypted")]
    pub fn doh(addr: SocketAddr, sni: &str, path: &str) -> Self {
        Self {
            transport: Transport::Doh {
                addr,
                sni: Arc::from(sni),
                path: Arc::from(path),
                tls: tls_client_config("doh"),
            },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
        }
    }

    /// Override the per-query timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Route this client's exchanges through `proxy` (issue #67 phase 2).
    ///
    /// When set:
    /// - TCP / DoT / DoH exchanges use `proxy.dial_tcp` instead of opening
    ///   a direct TCP connection.
    /// - UDP exchanges fall through to TCP-over-proxy, since most proxy
    ///   adapters can't relay arbitrary UDP. The fallback matches the
    ///   semantics in ADR-0012.
    pub fn with_proxy(mut self, proxy: DnsProxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Override the API/UI label used to report this upstream in DNS results.
    pub fn with_upstream_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(Arc::from(label.into()));
        self
    }

    /// Whether this client's exchanges are routed through a proxy adapter
    /// (`with_proxy`). Exposed so config-layer tests can assert that
    /// `#PROXY`-tagged nameserver entries actually got their adapter wired.
    pub fn is_proxied(&self) -> bool {
        self.proxy.is_some()
    }

    /// Human-readable upstream identifier for API/UI surfaces.
    pub fn upstream_label(&self) -> String {
        let mut label = if let Some(label) = &self.label {
            label.to_string()
        } else {
            match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => socket_label(*addr, 53),
                Transport::RCode { code } => format!("rcode:{code:?}"),
                #[cfg(feature = "encrypted")]
                Transport::Dot { addr, sni, .. } => {
                    if sni.is_empty() {
                        format!("tls://{}", socket_label(*addr, 853))
                    } else if addr.port() == 853 {
                        format!("tls://{sni}")
                    } else {
                        format!("tls://{sni}:{}", addr.port())
                    }
                }
                #[cfg(feature = "encrypted")]
                Transport::Doh {
                    addr, sni, path, ..
                } => {
                    if sni.is_empty() {
                        format!("https://{}", socket_label(*addr, 443))
                    } else if path.as_ref() == "/dns-query" {
                        if addr.port() == 443 {
                            format!("https://{sni}")
                        } else {
                            format!("https://{sni}:{}", addr.port())
                        }
                    } else if addr.port() == 443 {
                        format!("https://{sni}{path}")
                    } else {
                        format!("https://{sni}:{}{path}", addr.port())
                    }
                }
            }
        };
        if self.proxy.is_some() {
            label.push_str("#PROXY");
        }
        label
    }

    /// Send a query for `(name, record_type)` and return the parsed response
    /// `Message`. The response transaction ID, message type, opcode, and
    /// question must match the request before any response flags or records
    /// are used.
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Message, ClientError> {
        tokio::time::timeout(self.timeout, self.query_inner(name, record_type))
            .await
            .map_err(|_| ClientError::Timeout(self.timeout))?
    }

    async fn query_inner(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Message, ClientError> {
        let id: u16 = rand::random();
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let parsed: Name = name
            .parse()
            .map_err(|_| ClientError::Protocol("invalid query name"))?;
        let query = Query::query(parsed, record_type);
        if let Transport::RCode { code } = &self.transport {
            let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = *code;
            resp.add_query(query);
            return Ok(resp);
        }
        msg.add_query(query.clone());
        let wire = msg.to_bytes()?;
        let expected = ExpectedResponse { id, query };
        self.exchange(&wire, &expected).await
    }

    /// Convenience: query `A` first and fall back to `AAAA` when needed.
    /// Returns the addresses and minimum answer TTL.
    pub async fn lookup_ip(&self, name: &str) -> Result<(Vec<IpAddr>, Duration), ClientError> {
        let result = self.lookup_ip_with_ipv6(name, true).await?;
        Ok((result.ips, result.ttl))
    }

    pub(crate) async fn lookup_ip_with_ipv6(
        &self,
        name: &str,
        ipv6_enabled: bool,
    ) -> Result<IpLookupResult, ClientError> {
        tokio::time::timeout(
            self.timeout,
            self.lookup_ip_with_ipv6_inner(name, ipv6_enabled),
        )
        .await
        .map_err(|_| ClientError::Timeout(self.timeout))?
    }

    pub(crate) async fn lookup_family(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<FamilyLookupResult, ClientError> {
        let queried = QueryFamilies::from_record_type(record_type);
        if queried.is_empty() {
            return Err(ClientError::Protocol(
                "address family query must be A or AAAA",
            ));
        }
        let message = self.query(name, record_type).await?;
        match message.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => {
                // RFC 2308: a negative response's cache lifetime is
                // `min(SOA.TTL, SOA.MINIMUM)` from the authority section. Cache
                // it so repeat queries for a bogus name don't re-query upstream
                // on every attempt (DGA / retry loops). `0` when no SOA is
                // present; the resolver clamp floor still yields a short life.
                let ttl = negative_ttl(&message);
                return Ok(FamilyLookupResult::NxDomain(ttl));
            }
            code => return Err(ClientError::Rcode(code)),
        }
        let (ips, answer_ttl) = relevant_ip_answers(&message);
        let ttl = if ips.is_empty() {
            // RFC 2308: NODATA uses the SOA negative TTL, not a CNAME or
            // address-answer TTL accidentally found in the response.
            negative_ttl(&message)
        } else {
            Duration::from_secs(u64::from(answer_ttl.unwrap_or(0)))
        };
        Ok(FamilyLookupResult::Response(IpLookupResult {
            ips,
            ttl,
            v4: None,
            v6: None,
        }))
    }

    /// Unified entry point for the resolver pipeline (review issue J). For a
    /// single family (`IPV4`/`IPV6`) this is a per-family query that preserves
    /// the NXDOMAIN/NODATA distinction the DNS server needs; for `BOTH` it is
    /// the prefer-IPv4 A-then-AAAA path that returns every enabled address for
    /// `resolve_ips`. `Err` means the client could not produce *any* answer for
    /// the requested set (e.g. both families timed out); the resolver keeps
    /// racing the remaining clients.
    pub(crate) async fn lookup_set(
        &self,
        name: &str,
        want: QueryFamilies,
        ipv6_enabled: bool,
    ) -> Result<FamilySet, ClientError> {
        let source = self.upstream_label();
        if want == QueryFamilies::BOTH {
            let result = self.lookup_ip_with_ipv6(name, ipv6_enabled).await?;
            return Ok(family_set_from_ip_lookup(&result, source));
        }
        let family = if want == QueryFamilies::IPV4 {
            QueryFamilies::IPV4
        } else if want == QueryFamilies::IPV6 {
            QueryFamilies::IPV6
        } else {
            return Err(ClientError::Protocol(
                "lookup_set requires a single family or BOTH",
            ));
        };
        let record_type = match family {
            QueryFamilies::IPV4 => RecordType::A,
            _ => RecordType::AAAA,
        };
        let answer = match self.lookup_family(name, record_type).await {
            Ok(FamilyLookupResult::Response(r)) => {
                let ttl = r.ttl;
                if r.ips.is_empty() {
                    FamilyAnswer::NoData(ttl)
                } else {
                    FamilyAnswer::Answer { ips: r.ips, ttl }
                }
            }
            Ok(FamilyLookupResult::NxDomain(ttl)) => FamilyAnswer::NxDomain(ttl),
            Err(_) => FamilyAnswer::Failed,
        };
        let (v4, v6) = if family == QueryFamilies::IPV4 {
            (Some(answer), None)
        } else {
            (None, Some(answer))
        };
        Ok(FamilySet { v4, v6, source })
    }

    async fn lookup_ip_with_ipv6_inner(
        &self,
        name: &str,
        ipv6_enabled: bool,
    ) -> Result<IpLookupResult, ClientError> {
        // Prefer IPv4: query A first and fall back to AAAA only when A has no
        // address. Keep the per-family answer here because the aggregate IP
        // list alone cannot distinguish NODATA from NXDOMAIN when it is later
        // written to the shared cache.
        let mut addrs = Vec::new();
        let mut min_ttl: Option<Duration> = None;
        let mut first_err: Option<ClientError> = None;
        let mut v4 = None;
        let mut v6 = None;

        let got_v4 = match self.query_inner(name, RecordType::A).await {
            Ok(message) => {
                let answer = classify_family_message(&message);
                let got_address =
                    matches!(&answer, FamilyAnswer::Answer { ips, .. } if !ips.is_empty());
                if let FamilyAnswer::Answer { ips, ttl } = &answer {
                    addrs.extend_from_slice(ips);
                    min_ttl = Some(min_ttl.map_or(*ttl, |current| current.min(*ttl)));
                }
                v4 = Some(answer.clone());
                if let FamilyAnswer::NxDomain(ttl) = answer {
                    if ipv6_enabled {
                        v6 = Some(FamilyAnswer::NxDomain(ttl));
                    }
                    return Ok(IpLookupResult {
                        ips: addrs,
                        ttl,
                        v4,
                        v6,
                    });
                }
                got_address
            }
            Err(error) => {
                first_err = Some(error);
                false
            }
        };

        if !got_v4 && ipv6_enabled {
            match self.query_inner(name, RecordType::AAAA).await {
                Ok(message) => {
                    let answer = classify_family_message(&message);
                    if let FamilyAnswer::Answer { ips, ttl } = &answer {
                        addrs.extend_from_slice(ips);
                        min_ttl = Some(min_ttl.map_or(*ttl, |current| current.min(*ttl)));
                    }
                    v6 = Some(answer);
                }
                Err(error) => {
                    if first_err.is_none() {
                        first_err = Some(error);
                    }
                }
            }
        }

        if v4.is_none() && v6.is_none() {
            return Err(first_err.unwrap_or(ClientError::Protocol("no response")));
        }
        Ok(IpLookupResult {
            ips: addrs,
            ttl: min_ttl.unwrap_or(Duration::ZERO),
            v4,
            v6,
        })
    }

    async fn exchange(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        if let Some(proxy) = self.proxy.as_ref() {
            let addr = match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => *addr,
                Transport::RCode { .. } => {
                    return Err(ClientError::Protocol(
                        "rcode transport should not perform network exchange",
                    ));
                }
                #[cfg(feature = "encrypted")]
                Transport::Dot { .. } | Transport::Doh { .. } => {
                    // DoT/DoH-over-proxy needs TLS layered on a Box<dyn
                    // ProxyConn>; the upstream tokio_rustls TlsConnector
                    // is generic over the IO stream but the call sites
                    // here aren't wired yet. ADR-0012 marks it
                    // follow-up. Refuse so misconfiguration is loud.
                    return Err(ClientError::Tls(
                        "DoT/DoH routing through a proxy is not implemented yet \
                        (issue #67 phase 2 follow-up); use plain udp:// or tcp:// for \
                        a #PROXY-tagged nameserver"
                            .to_string(),
                    ));
                }
            };
            let response = proxy_tcp_exchange(proxy, addr, wire).await?;
            return decode_validated_response(&response, expected);
        }
        match &self.transport {
            Transport::Udp { addr } => udp_exchange(*addr, wire, expected).await,
            Transport::Tcp { addr } => {
                let response = tcp_exchange(*addr, wire).await?;
                decode_validated_response(&response, expected)
            }
            Transport::RCode { .. } => Err(ClientError::Protocol(
                "rcode transport should not perform network exchange",
            )),
            #[cfg(feature = "encrypted")]
            Transport::Dot { addr, sni, tls } => {
                let response = dot_exchange(*addr, sni, Arc::clone(tls), wire).await?;
                decode_validated_response(&response, expected)
            }
            #[cfg(feature = "encrypted")]
            Transport::Doh {
                addr,
                sni,
                path,
                tls,
            } => {
                let response = doh_exchange(*addr, sni, path, Arc::clone(tls), wire).await?;
                decode_validated_response(&response, expected)
            }
        }
    }
}

struct ExpectedResponse {
    id: u16,
    query: Query,
}

fn decode_validated_response(
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    let response = Message::from_bytes(wire)?;
    validate_response(&response, expected)?;
    Ok(response)
}

fn validate_response(response: &Message, expected: &ExpectedResponse) -> Result<(), ClientError> {
    if response.metadata.id != expected.id {
        return Err(ClientError::Protocol("response ID mismatch"));
    }
    if response.metadata.message_type != MessageType::Response {
        return Err(ClientError::Protocol("received DNS query as response"));
    }
    if response.metadata.op_code != OpCode::Query {
        return Err(ClientError::Protocol("response opcode mismatch"));
    }
    let [question] = response.queries.as_slice() else {
        return Err(ClientError::Protocol("response question count mismatch"));
    };
    if !question.name.eq_ignore_root(&expected.query.name) {
        return Err(ClientError::Protocol("response question name mismatch"));
    }
    if question.query_type != expected.query.query_type {
        return Err(ClientError::Protocol("response question type mismatch"));
    }
    if question.query_class != expected.query.query_class {
        return Err(ClientError::Protocol("response question class mismatch"));
    }
    Ok(())
}

fn socket_label(addr: SocketAddr, default_port: u16) -> String {
    if addr.port() == default_port {
        addr.ip().to_string()
    } else {
        addr.to_string()
    }
}

async fn proxy_tcp_exchange(
    proxy: &DnsProxy,
    addr: SocketAddr,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    use meow_common::{ConnType, Metadata, Network};
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        host: smol_str::SmolStr::from(addr.ip().to_string()),
        dst_ip: Some(addr.ip()),
        dst_port: addr.port(),
        ..Default::default()
    };
    let mut stream = proxy
        .dial_tcp(&metadata)
        .await
        .map_err(|e| io::Error::other(format!("dns-via-proxy dial: {e}")))?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

fn ip_from_record(rec: &Record) -> Option<IpAddr> {
    match &rec.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

fn canonical_name(name: &Name) -> Name {
    let mut canonical = name.to_lowercase();
    canonical.set_fqdn(true);
    canonical
}

/// RFC 2308 negative-cache TTL for an NXDOMAIN/NODATA response: the minimum of
/// the SOA record's own TTL and its MINIMUM field, taken from the authority
/// (`authorities`) section. Returns `0` when no SOA is present — the
/// resolver's clamp floor still gives such a negative a short cache life.
/// Mirrors mihomo's `minimalTTL(concat(Answer, Ns, Extra))` for negative
/// responses (the SOA lives in the authority section).
fn negative_ttl(message: &Message) -> Duration {
    let mut best: Option<u32> = None;
    for record in &message.authorities {
        let RData::SOA(soa) = &record.data else {
            continue;
        };
        let ttl = record.ttl.min(soa.minimum);
        best = Some(best.map_or(ttl, |b| b.min(ttl)));
    }
    Duration::from_secs(u64::from(best.unwrap_or(0)))
}

fn classify_family_message(message: &Message) -> FamilyAnswer {
    match message.metadata.response_code {
        ResponseCode::NoError => {
            let (ips, ttl) = relevant_ip_answers(message);
            if ips.is_empty() {
                // NODATA uses the SOA negative TTL even when the response
                // contains a CNAME with its own TTL but no terminal address.
                FamilyAnswer::NoData(negative_ttl(message))
            } else {
                FamilyAnswer::Answer {
                    ips,
                    ttl: Duration::from_secs(u64::from(ttl.unwrap_or(0))),
                }
            }
        }
        ResponseCode::NXDomain => FamilyAnswer::NxDomain(negative_ttl(message)),
        _ => FamilyAnswer::Failed,
    }
}

struct CnameLink {
    target: Name,
    ttl: u32,
    ambiguous: bool,
}

fn relevant_ip_answers(message: &Message) -> (Vec<IpAddr>, Option<u32>) {
    let Some(question) = message.queries.first() else {
        return (Vec::new(), None);
    };
    if !matches!(question.query_type, RecordType::A | RecordType::AAAA) {
        return (Vec::new(), None);
    }

    // Index CNAME links once, then walk the single chain from QNAME. Besides
    // making answer order irrelevant, this keeps hostile reverse-ordered
    // chains linear instead of repeatedly rescanning every answer.
    let mut cname_links = HashMap::new();
    for record in &message.answers {
        if record.dns_class != question.query_class {
            continue;
        }
        let RData::CNAME(target) = &record.data else {
            continue;
        };
        let owner = canonical_name(&record.name);
        let target = canonical_name(&target.0);
        match cname_links.entry(owner) {
            Entry::Vacant(entry) => {
                entry.insert(CnameLink {
                    target,
                    ttl: record.ttl,
                    ambiguous: false,
                });
            }
            Entry::Occupied(mut entry) => {
                let link = entry.get_mut();
                if link.target == target {
                    link.ttl = link.ttl.min(record.ttl);
                } else {
                    // Multiple canonical names for one owner violate the
                    // CNAME rules. Do not pick an attacker-controlled branch.
                    link.ambiguous = true;
                }
            }
        }
    }

    let mut reachable = HashSet::new();
    let mut current = canonical_name(&question.name);
    let mut cname_ttl: Option<u32> = None;
    loop {
        if !reachable.insert(current.clone()) {
            // A CNAME loop has no usable terminal address.
            return (Vec::new(), None);
        }
        let Some(link) = cname_links.get(&current) else {
            break;
        };
        if link.ambiguous {
            return (Vec::new(), None);
        }
        cname_ttl = Some(cname_ttl.map_or(link.ttl, |ttl| ttl.min(link.ttl)));
        current = link.target.clone();
    }

    let mut addrs = Vec::new();
    let mut min_ttl = cname_ttl;
    for record in &message.answers {
        if record.dns_class != question.query_class
            || !reachable.contains(&canonical_name(&record.name))
        {
            continue;
        }
        let matches_query = matches!(
            (&record.data, question.query_type),
            (RData::A(_), RecordType::A) | (RData::AAAA(_), RecordType::AAAA)
        );
        if matches_query {
            addrs.extend(ip_from_record(record));
            min_ttl = Some(min_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
        }
    }
    (addrs, min_ttl)
}

/// Convert the prefer-IPv4 A-then-AAAA result into a [`FamilySet`]. The
/// family answers retain NXDOMAIN versus NODATA so the shared cache cannot
/// downgrade the upstream RCODE.
fn family_set_from_ip_lookup(result: &IpLookupResult, source: String) -> FamilySet {
    FamilySet {
        v4: result.v4.clone(),
        v6: result.v6.clone(),
        source,
    }
}

async fn udp_exchange(
    addr: SocketAddr,
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    let sock = factory().bind_udp().await?;
    sock.connect(addr).await?;
    sock.send(wire).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        let Ok(response) = decode_validated_response(&buf[..n], expected) else {
            // A connected UDP socket only filters the peer tuple. Ignore
            // malformed or unrelated datagrams and keep waiting under the
            // query's original overall timeout.
            continue;
        };
        if response.metadata.truncation {
            let response = tcp_exchange(addr, wire).await?;
            return decode_validated_response(&response, expected);
        }
        return Ok(response);
    }
}

async fn tcp_exchange(addr: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut stream = factory().connect_tcp(addr).await?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

async fn write_lp<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len =
        u16::try_from(payload.len()).map_err(|_| io::Error::other("dns message too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

async fn read_lp<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(feature = "encrypted")]
async fn dot_exchange(
    addr: SocketAddr,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let tcp = factory().connect_tcp(addr).await?;
    let connector = TlsConnector::from(tls);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| ClientError::Tls(format!("invalid SNI: {e}")))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ClientError::Tls(e.to_string()))?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

#[cfg(feature = "encrypted")]
async fn doh_exchange(
    addr: SocketAddr,
    sni: &str,
    path: &str,
    tls: Arc<rustls::ClientConfig>,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let tcp = factory().connect_tcp(addr).await?;
    let connector = TlsConnector::from(tls);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| ClientError::Tls(format!("invalid SNI: {e}")))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ClientError::Tls(e.to_string()))?;

    // Minimal HTTP/1.1 POST. Connection: close so the server EOFs and we can
    // read-to-end without parsing chunked transfer-encoding.
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: meow-rs\r\n\
         Accept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        host = sni,
        len = wire.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(wire).await?;
    stream.flush().await?;

    let mut all = Vec::with_capacity(1024);
    stream.read_to_end(&mut all).await?;
    let split = find_subseq(&all, b"\r\n\r\n")
        .ok_or(ClientError::Protocol("doh: missing header terminator"))?;
    let head_bytes = &all[..split];
    let body = &all[split + 4..];
    let head_str =
        std::str::from_utf8(head_bytes).map_err(|_| ClientError::Protocol("doh: bad headers"))?;
    let status_line = head_str
        .lines()
        .next()
        .ok_or(ClientError::Protocol("doh: empty response"))?;
    // "HTTP/1.1 200 OK" — extract the status code.
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts.next().unwrap_or("");
    if status != "200" {
        return Err(ClientError::Protocol("doh: non-200 status"));
    }
    Ok(body.to_vec())
}

#[cfg(feature = "encrypted")]
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

#[cfg(feature = "encrypted")]
fn tls_client_config(alpn: &str) -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static DOT: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static DOH: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let slot = match alpn {
        "dot" => &DOT,
        _ => &DOH,
    };
    Arc::clone(slot.get_or_init(|| {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        // Be explicit about the provider — when both `ring` and `aws_lc_rs`
        // are linked (e.g. by meow-transport's `ech` feature), the default
        // `ClientConfig::builder()` panics on the auto-detect.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("rustls protocol versions are safe defaults")
            .with_root_certificates(root_store)
            .with_no_client_auth();
        cfg.alpn_protocols = match alpn {
            "dot" => vec![b"dot".to_vec()],
            // h2 first, but the client speaks http/1.1 so include it too.
            _ => vec![b"http/1.1".to_vec()],
        };
        Arc::new(cfg)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::DNSClass;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn expected(name: &str, record_type: RecordType, id: u16) -> ExpectedResponse {
        ExpectedResponse {
            id,
            query: Query::query(name.parse().unwrap(), record_type),
        }
    }

    fn response_for(request: &Message, id: u16) -> Message {
        let mut response = Message::new(id, MessageType::Response, OpCode::Query);
        response.add_queries(request.queries.iter().cloned());
        response
    }

    fn a_record(name: &str, ttl: u32, octets: [u8; 4]) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::from(octets))),
        )
    }

    fn cname_record(name: &str, ttl: u32, target: &str) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::CNAME(CNAME(target.parse().unwrap())),
        )
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn find_subseq_basic() {
        assert_eq!(find_subseq(b"abc\r\n\r\nbody", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subseq(b"abcdef", b"\r\n\r\n"), None);
        assert_eq!(find_subseq(b"", b"x"), None);
    }

    #[tokio::test]
    async fn udp_client_times_out_on_unroutable() {
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client =
            DnsClient::udp(sink.local_addr().unwrap()).with_timeout(Duration::from_millis(200));
        let r = client.query("example.test", RecordType::A).await;
        assert!(matches!(r, Err(ClientError::Timeout(_))));
    }

    #[tokio::test]
    async fn rcode_client_returns_noerror_empty_without_network() {
        let client = DnsClient::rcode(ResponseCode::NoError);
        let resp = client.query("example.test", RecordType::A).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
        assert_eq!(resp.queries.len(), 1);
    }

    #[test]
    fn response_validation_rejects_mismatched_metadata_and_question() {
        let expected = expected("victim.example", RecordType::A, 0x1234);
        let mut response = Message::new(0x1234, MessageType::Response, OpCode::Query);
        response.add_query(expected.query.clone());
        assert!(validate_response(&response, &expected).is_ok());

        response.metadata.id = 0x4321;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response ID mismatch"))
        ));
        response.metadata.id = expected.id;

        response.metadata.message_type = MessageType::Query;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("received DNS query as response"))
        ));
        response.metadata.message_type = MessageType::Response;

        response.metadata.op_code = OpCode::Status;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response opcode mismatch"))
        ));
        response.metadata.op_code = OpCode::Query;

        response.queries[0].name = "other.example".parse().unwrap();
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question name mismatch"))
        ));
        response.queries[0].name = expected.query.name.clone();

        response.queries[0].query_type = RecordType::AAAA;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question type mismatch"))
        ));
        response.queries[0].query_type = expected.query.query_type;

        response.queries[0].query_class = DNSClass::CH;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question class mismatch"))
        ));
    }

    #[test]
    fn address_answers_are_limited_to_the_valid_cname_chain() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        // Deliberately put the terminal address and second CNAME before the
        // first link to prove answer ordering is irrelevant.
        message.add_answer(a_record("target.example", 300, [192, 0, 2, 10]));
        message.add_answer(cname_record("alias.example", 120, "target.example"));
        message.add_answer(a_record("unrelated.example", 1, [6, 6, 6, 6]));
        message.add_answer(cname_record("victim.example", 60, "alias.example"));

        let (addrs, ttl) = relevant_ip_answers(&message);
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(ttl, Some(60));
    }

    #[test]
    fn unrelated_address_answer_is_not_returned() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(a_record("unrelated.example", 30, [6, 6, 6, 6]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[test]
    fn cname_loop_is_rejected() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(cname_record("victim.example", 60, "alias.example"));
        message.add_answer(cname_record("alias.example", 30, "victim.example"));
        message.add_answer(a_record("alias.example", 300, [192, 0, 2, 10]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[test]
    fn conflicting_cname_targets_are_rejected() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(cname_record("victim.example", 60, "first.example"));
        message.add_answer(cname_record("victim.example", 30, "second.example"));
        message.add_answer(a_record("first.example", 300, [192, 0, 2, 10]));
        message.add_answer(a_record("second.example", 300, [192, 0, 2, 11]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[tokio::test]
    async fn udp_ignores_wrong_id_before_valid_response() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();

            let wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            server
                .send_to(&wrong.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            let valid = response_for(&request, request.metadata.id);
            server
                .send_to(&valid.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        let response = DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(response.queries[0].query_type, RecordType::A);
    }

    #[tokio::test]
    async fn wrong_id_truncated_udp_response_does_not_trigger_tcp_fallback() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();

            let mut wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            wrong.metadata.truncation = true;
            server
                .send_to(&wrong.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            let valid = response_for(&request, request.metadata.id);
            server
                .send_to(&valid.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await
            .expect("the valid UDP response must win without a TCP connection");
    }

    #[tokio::test]
    async fn tcp_rejects_mismatched_framed_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_lp(&mut stream).await.unwrap();
            let request = Message::from_bytes(&request).unwrap();
            let wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            write_lp(&mut stream, &wrong.to_bytes().unwrap())
                .await
                .unwrap();
        });

        let result = DnsClient::tcp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await;
        assert!(matches!(
            result,
            Err(ClientError::Protocol("response ID mismatch"))
        ));
    }

    #[tokio::test]
    async fn lookup_ip_shares_one_timeout_across_a_and_aaaa() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&requests);
        tokio::spawn(async move {
            // A and AAAA ride separate connections (no pooling here), so the
            // server accepts twice. The point under test is that the *client*
            // covers both sequential queries with one overall timeout, not
            // that they share a socket.
            for expected in [RecordType::A, RecordType::AAAA] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_lp(&mut stream).await.unwrap();
                let request = Message::from_bytes(&request).unwrap();
                assert_eq!(request.queries[0].query_type, expected);
                server_requests.fetch_add(1, Ordering::SeqCst);
                if expected == RecordType::A {
                    // Empty NOERROR (no address records) after 250 ms, so the
                    // prefer-IPv4 path falls back to AAAA.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let response = response_for(&request, request.metadata.id);
                    write_lp(&mut stream, &response.to_bytes().unwrap())
                        .await
                        .unwrap();
                } else {
                    // AAAA never answers within the client budget.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        });

        let client = DnsClient::tcp(addr).with_timeout(Duration::from_millis(400));
        let result = tokio::time::timeout(
            Duration::from_millis(550),
            client.lookup_ip_with_ipv6("dual.example", true),
        )
        .await
        .expect("A and AAAA must share the client's overall timeout");
        assert!(matches!(result, Err(ClientError::Timeout(_))));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn encrypted_upstream_labels_include_scheme() {
        let dot = DnsClient::dot("8.8.8.8:853".parse().unwrap(), "dns.google");
        assert_eq!(dot.upstream_label(), "tls://dns.google");

        let doh = DnsClient::doh(
            "1.1.1.1:443".parse().unwrap(),
            "cloudflare-dns.com",
            "/dns-query",
        );
        assert_eq!(doh.upstream_label(), "https://cloudflare-dns.com");
    }

    #[test]
    fn explicit_upstream_label_overrides_default_label() {
        let client = DnsClient::udp("8.8.8.8:53".parse().unwrap())
            .with_upstream_label("tls://dns.google:853");
        assert_eq!(client.upstream_label(), "tls://dns.google:853");
    }

    /// RFC 2308: the negative cache TTL of an NXDOMAIN/NODATA response is
    /// `min(SOA.TTL, SOA.MINIMUM)` from the authority section. Verifies the
    /// helper used by the NXDOMAIN-cache path picks the smaller of the record
    /// TTL and the SOA MINIMUM field, and falls back to 0 when no SOA is
    /// present (the resolver clamp floor still gives it a short life).
    fn soa_record(name: &str, ttl: u32, minimum: u32) -> Record {
        use hickory_proto::rr::rdata::SOA;
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::SOA(SOA::new(
                "ns.example".parse().unwrap(),
                "hostmaster.example".parse().unwrap(),
                1,
                3600,
                900,
                1209600,
                minimum,
            )),
        )
    }

    #[test]
    fn negative_ttl_uses_min_of_soa_ttl_and_minimum() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        // SOA TTL 600, MINIMUM 300 → negative TTL 300.
        msg.add_authority(soa_record("example.", 600, 300));
        assert_eq!(negative_ttl(&msg), Duration::from_secs(300));
    }

    #[test]
    fn negative_ttl_picks_the_soa_record_ttl_when_smaller_than_minimum() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        // SOA TTL 120, MINIMUM 3600 → negative TTL 120.
        msg.add_authority(soa_record("example.", 120, 3600));
        assert_eq!(negative_ttl(&msg), Duration::from_secs(120));
    }

    #[test]
    fn negative_ttl_is_zero_when_no_soa_in_authority() {
        let msg = Message::new(1, MessageType::Response, OpCode::Query);
        assert_eq!(negative_ttl(&msg), Duration::ZERO);
    }

    /// `classify_family_message` is the BOTH-path classifier. Verify its four
    /// branches: NoError+addresses → Answer, NoError+empty → NoData(SOA TTL),
    /// NXDOMAIN → NxDomain(SOA TTL), other rcode → Failed.
    #[test]
    fn classify_family_message_branches() {
        use hickory_proto::op::ResponseCode;

        // NoError with an A record → Answer.
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query("a.example".parse().unwrap(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            "a.example".parse().unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let ans = classify_family_message(&msg);
        assert!(matches!(
            ans,
            FamilyAnswer::Answer { ips, ttl } if ips == vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))] && ttl == Duration::from_secs(60)
        ));

        // NoError with zero address records → NoData(SOA TTL).
        let mut msg = Message::new(2, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query(
            "empty.example".parse().unwrap(),
            RecordType::A,
        ));
        msg.add_authority(soa_record("example.", 600, 300));
        let ans = classify_family_message(&msg);
        assert!(matches!(ans, FamilyAnswer::NoData(t) if t == Duration::from_secs(300)));

        // NXDOMAIN → NxDomain(SOA TTL).
        let mut msg = Message::new(3, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_query(Query::query("gone.example".parse().unwrap(), RecordType::A));
        msg.add_authority(soa_record("example.", 600, 300));
        let ans = classify_family_message(&msg);
        assert!(matches!(ans, FamilyAnswer::NxDomain(t) if t == Duration::from_secs(300)));

        // SERVFAIL → Failed.
        let mut msg = Message::new(4, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        msg.add_query(Query::query("fail.example".parse().unwrap(), RecordType::A));
        let ans = classify_family_message(&msg);
        assert!(matches!(ans, FamilyAnswer::Failed));
    }
}
