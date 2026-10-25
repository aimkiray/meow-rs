//! Integration test for DNS-via-proxy (issue #67 phase 2, ADR-0012).
//!
//! Sets up tiny in-process upstreams — a plain RFC-7766 TCP DNS stub, a
//! DoT stub (boring `SslAcceptor` + `rcgen` chain) and a DoH stub —
//! and plugs a mock [`Proxy`] adapter in front of them. The mock records
//! the [`Metadata`] it was asked to dial and then connects onward, so
//! each test proves the DNS exchange actually went through
//! `proxy.dial_tcp` and not through the global socket factory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use meow_common::{
    AdapterType, ConnType, DelayHistory, Metadata, Network, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result as MeowResult,
};
use meow_dns::client::DnsClient;
#[cfg(feature = "encrypted")]
use meow_dns::HostEntry;
use meow_dns::{NameServerEntry, Resolver};
#[cfg(feature = "encrypted")]
use meow_trie::DomainTrie;
use parking_lot::Mutex;
#[cfg(feature = "encrypted")]
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const T: Duration = Duration::from_secs(5);

/// Build the canned `A example.com.` → `203.0.113.7` response for a
/// decoded request message.
fn answer_for(req_msg: &Message) -> Message {
    let mut resp = Message::new(req_msg.id, MessageType::Response, OpCode::Query);
    resp.metadata.response_code = ResponseCode::NoError;
    resp.metadata.recursion_available = true;
    for q in &req_msg.queries {
        resp.add_query(q.clone());
        if q.query_type == RecordType::A {
            let name: Name = "example.com.".parse().unwrap();
            let rec = Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(203, 0, 113, 7))));
            resp.add_answer(rec);
        }
    }
    resp
}

/// Read one RFC-7766 length-prefixed DNS message off `sock` and write the
/// canned response back, same framing.
async fn serve_one_dns_frame<S>(sock: &mut S)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    if sock.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut req = vec![0u8; len];
    if sock.read_exact(&mut req).await.is_err() {
        return;
    }
    let Ok(req_msg) = Message::from_bytes(&req) else {
        return;
    };
    let wire = answer_for(&req_msg).to_bytes().unwrap();
    let lenb = (wire.len() as u16).to_be_bytes();
    if sock.write_all(&lenb).await.is_err() {
        return;
    }
    let _ = sock.write_all(&wire).await;
}

/// Start a stub DNS-over-TCP server that always answers `A example.com.` →
/// `203.0.113.7`. Returns the bound address.
async fn start_dns_tcp_stub() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                serve_one_dns_frame(&mut sock).await;
            });
        }
    });
    addr
}

/// A `boring` TLS acceptor for `sans` plus the DER bytes the client's
/// `with_tls_additional_roots` hook must trust (the cert is self-signed,
/// so the leaf doubles as its own root). The hook exists only in test /
/// debug builds, so the callers that use it are `debug_assertions`-gated
/// too — under `cargo test --release` both sides disappear together.
#[cfg(feature = "encrypted")]
fn tls_acceptor(sans: &[&str]) -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(
        sans.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>(),
    )
    .expect("rcgen cert generation failed");
    let cert = boring::x509::X509::from_der(ck.cert.der()).unwrap();
    let key = boring::pkey::PKey::private_key_from_der(&ck.key_pair.serialize_der()).unwrap();
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    builder.set_certificate(&cert).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.check_private_key().unwrap();
    (builder.build(), ck.cert.der().to_vec())
}

/// Start a DoT stub: TLS, then the same length-prefixed exchange as the
/// plain TCP stub. Returns `(bound addr, DER root for the client)`.
#[cfg(feature = "encrypted")]
async fn start_dot_stub() -> (SocketAddr, Vec<u8>) {
    let (acceptor, root) = tls_acceptor(&["dot-stub.test"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
                    return;
                };
                serve_one_dns_frame(&mut stream).await;
            });
        }
    });
    (addr, root)
}

/// Start a DoH stub: TLS, then a minimal HTTP/1.1 POST read
/// (`application/dns-message`) and a `200` reply carrying the canned
/// response with `Connection: close`. Returns `(bound addr, DER root)`.
/// Only the `debug_assertions`-gated DoH test consumes the DER root, so
/// the stub is gated with it (dead code otherwise under `--release`).
#[cfg(all(feature = "encrypted", debug_assertions))]
async fn start_doh_stub() -> (SocketAddr, Vec<u8>) {
    let (acceptor, root) = tls_acceptor(&["doh-stub.test"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
                    return;
                };
                // Headers up to the first blank line, then the
                // Content-Length body.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }
                let head_str = String::from_utf8_lossy(&head);
                let len: usize = head_str
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let Ok(req_msg) = Message::from_bytes(&body) else {
                    return;
                };
                let wire = answer_for(&req_msg).to_bytes().unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/dns-message\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n",
                    wire.len()
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                let _ = stream.write_all(&wire).await;
            });
        }
    });
    (addr, root)
}

/// What the mock proxy was asked to dial — the canonical DNS-via-proxy
/// metadata shape (issue #67 phase 2): `host` is the IP string for IP
/// targets and the domain for hostname targets, `dst_ip` is `None`
/// exactly when the proxy must resolve the domain remotely, `conn_type`
/// is `Inner` housekeeping traffic on `network: Tcp` (never a proxied
/// UDP flow masquerading as the DNS exchange), and `internal` is set so
/// lazy groups don't count it as use.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DialRecord {
    host: String,
    dst_ip: Option<IpAddr>,
    dst_port: u16,
    conn_type: ConnType,
    network: Network,
    internal: bool,
}

/// Mock proxy adapter: records the destination metadata of every dial,
/// then opens the TCP connection itself so the exchange really completes.
/// For a *domain* target (`dst_ip: None`) it connects to `forward_to` —
/// simulating a remote proxy that resolves the domain on its own side,
/// which is the whole point of the `?proxy=` hostname path.
struct MockProxy {
    name: String,
    dialed: Arc<Mutex<Vec<DialRecord>>>,
    forward_to: SocketAddr,
}

#[async_trait]
impl ProxyAdapter for MockProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
        self.dialed.lock().push(DialRecord {
            host: metadata.host.to_string(),
            dst_ip: metadata.dst_ip,
            dst_port: metadata.dst_port,
            conn_type: metadata.conn_type,
            network: metadata.network,
            internal: metadata.internal,
        });
        let target = match metadata.dst_ip {
            Some(ip) => SocketAddr::new(ip, metadata.dst_port),
            None => self.forward_to,
        };
        let stream = TcpStream::connect(target)
            .await
            .map_err(meow_common::MeowError::Io)?;
        Ok(Box::new(stream))
    }
    async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
        unimplemented!("test mock has no UDP")
    }
    fn health(&self) -> &ProxyHealth {
        static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
        H.get_or_init(ProxyHealth::new)
    }
}

impl Proxy for MockProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

fn mock_proxy(dialed: &Arc<Mutex<Vec<DialRecord>>>, forward_to: SocketAddr) -> Arc<dyn Proxy> {
    Arc::new(MockProxy {
        name: "PROXY-A".to_string(),
        dialed: Arc::clone(dialed),
        forward_to,
    })
}

fn assert_example_answer(msg: &Message) {
    let mut got: Option<IpAddr> = None;
    for ans in &msg.answers {
        if let RData::A(a) = &ans.data {
            got = Some(IpAddr::V4(a.0));
        }
    }
    assert_eq!(got, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
}

#[tokio::test]
async fn dns_client_routes_tcp_query_through_proxy() {
    let dns_addr = start_dns_tcp_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, dns_addr);

    let client = DnsClient::tcp(dns_addr).with_proxy(proxy);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: dns_addr.ip().to_string(),
            dst_ip: Some(dns_addr.ip()),
            dst_port: dns_addr.port(),
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "proxy must have been the dialer for the DNS exchange"
    );
}

#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_query_routes_through_proxy() {
    let (dot_addr, root) = start_dot_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, dot_addr);

    let client = DnsClient::dot(dot_addr, "dot-stub.test")
        .with_proxy(proxy)
        .with_tls_additional_roots(root);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("DoT query through the proxy must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: dot_addr.ip().to_string(),
            dst_ip: Some(dot_addr.ip()),
            dst_port: dot_addr.port(),
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "DoT exchange must dial through proxy.dial_tcp"
    );
}

#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_query_routes_through_proxy() {
    let (doh_addr, root) = start_doh_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, doh_addr);

    let client = DnsClient::doh(doh_addr, "doh-stub.test", "/dns-query")
        .with_proxy(proxy)
        .with_tls_additional_roots(root);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("DoH query through the proxy must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: doh_addr.ip().to_string(),
            dst_ip: Some(doh_addr.ip()),
            dst_port: doh_addr.port(),
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "DoH exchange must dial through proxy.dial_tcp"
    );
}

/// The flagship `?proxy=` property: a *hostname* upstream whose name is
/// locally unresolvable still builds and routes — the adapter is asked to
/// dial the **domain** (`dst_ip: None`), which it resolves on the remote
/// side (the mock's `forward_to`). No bootstrap lookup runs.
#[tokio::test]
async fn proxied_hostname_tcp_upstream_needs_no_bootstrap() {
    let dns_addr = start_dns_tcp_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, dns_addr);

    // `unresolvable.invalid` cannot bootstrap-resolve anywhere — RFC
    // 2606 reserves the TLD as always-NXDOMAIN. `build_single_…` still
    // produces a client, because the proxy gets the name remotely.
    let entry = NameServerEntry::parse("tcp://unresolvable.invalid#PROXY-A").unwrap();
    assert_eq!(entry.proxy.as_deref(), Some("PROXY-A"));
    let resolved = HashMap::new();
    let client = Resolver::build_single_resolver_with_proxy(&entry.url, &resolved, Some(proxy));

    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query through remote-resolved domain must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: "unresolvable.invalid".to_string(),
            dst_ip: None,
            dst_port: 53,
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "proxy must be asked to dial the domain, not a resolved IP"
    );
}

/// Same property for an encrypted upstream: `tls://<unresolvable>` +
/// `?proxy=` builds with no bootstrap and hands the domain to
/// `proxy.dial_tcp`. TLS then fails — the stub cert doesn't cover the
/// bogus SNI — but the recorded metadata proves the whole
/// `dial_tcp → connect_typed` chain ran.
#[cfg(feature = "encrypted")]
#[tokio::test]
async fn proxied_hostname_tls_upstream_dials_domain() {
    let (dot_addr, _root) = start_dot_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, dot_addr);

    let entry = NameServerEntry::parse("tls://unresolvable.invalid?proxy=PROXY-A").unwrap();
    assert_eq!(entry.proxy.as_deref(), Some("PROXY-A"));
    let resolved = HashMap::new();
    let client = Resolver::build_single_resolver_with_proxy(&entry.url, &resolved, Some(proxy));

    let err = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect_err("TLS must reject the stub cert for 'unresolvable.invalid'");
    assert!(
        matches!(err, meow_dns::client::ClientError::Tls(_)),
        "expected the TLS layer to be reached (dial → handshake); got {err:?}"
    );

    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: "unresolvable.invalid".to_string(),
            dst_ip: None,
            dst_port: 853,
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "proxy must be asked to dial the domain, not a resolved IP"
    );
}

/// End-to-end resolver build: a `?proxy=` hostname main nameserver skips
/// bootstrap entirely — the `.invalid` TLD would make a real bootstrap
/// lookup fail, so a successful build is itself the assertion. Then a
/// resolve hands the domain to `dial_tcp` (the mock's `forward_to` is a
/// closed port, so the query itself dies at connect — the dial record is
/// the evidence).
#[cfg(feature = "encrypted")]
#[tokio::test]
async fn resolver_build_skips_bootstrap_for_proxied_hostnames() {
    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, "127.0.0.1:9".parse().unwrap());

    let entry =
        NameServerEntry::parse("https://unresolvable.invalid/dns-query?proxy=PROXY-A").unwrap();
    let mut registry: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
    registry.insert(SmolStr::from("PROXY-A"), proxy);

    let resolver = Resolver::new_with_bootstrap_with_proxies(
        vec![entry],
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        DomainTrie::<HostEntry>::new(),
        false,
        false,
        None,
        None,
        &registry,
        false,
    )
    .await
    .expect("proxied hostname upstream must build without bootstrap");

    let _ = timeout(T, resolver.resolve_ip("example.com")).await;
    assert!(
        dialed.lock().iter().any(|d| {
            d.host == "unresolvable.invalid"
                && d.dst_ip.is_none()
                && d.conn_type == ConnType::Inner
                && d.network == Network::Tcp
                && d.internal
        }),
        "resolve must dial the upstream *domain* through the proxy; got {:?}",
        dialed.lock()
    );
}

/// `?proxy=` is parsed before the feature gate: without `encrypted` the
/// scheme itself is already the error, and the chain must name it
/// (`EncryptedFeatureDisabled`), not a params error.
#[cfg(not(feature = "encrypted"))]
#[test]
fn query_proxy_requires_encrypted_feature() {
    let err = NameServerEntry::parse("tls://1.1.1.1?proxy=P").unwrap_err();
    assert!(matches!(
        err,
        meow_dns::NameServerParseError::EncryptedFeatureDisabled
    ));
}
