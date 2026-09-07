//! A node's `dialer-proxy` must survive being reached through a proxy group,
//! and a dialer must be able to name a group (issue #513).
//!
//! Proxy groups clone their members eagerly, so applying the chain after the
//! group build left every group holding the pre-dialer adapter: selecting the
//! node through the group dialled its own server directly and silently bypassed
//! the chain the user configured for policy reasons. The dialer pass now runs
//! before groups are built and binds the front hop *by name* (mihomo
//! `component/proxydialer/byname.go`), so both paths chain identically and a
//! group that does not exist yet at build time is still a valid dialer.
//!
//! The observable is which mock server each dial physically contacts. Every TLS
//! handshake fails fast against the plain listeners — the accept counts, not the
//! dial result, are what these tests assert on.

use meow_common::{Metadata, Network};
use meow_config::raw::RawConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

/// TCP listener that counts accepts and drops each connection immediately, so
/// the client-side TLS handshake errors out instead of hanging on a ServerHello
/// that never arrives.
async fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (addr, count)
}

/// `A` chains through the leaf proxy `B`; `C` chains through the group `G2`
/// (which holds `B`); `G` is a select group over `A`.
fn config(port_a: u16, port_b: u16, port_c: u16) -> RawConfig {
    serde_yaml::from_str(&format!(
        r#"
mixed-port: 17890
mode: rule
proxies:
  - name: A
    type: trojan
    server: 127.0.0.1
    port: {port_a}
    password: issue-513
    dialer-proxy: B
  - name: B
    type: trojan
    server: 127.0.0.1
    port: {port_b}
    password: issue-513
  - name: C
    type: trojan
    server: 127.0.0.1
    port: {port_c}
    password: issue-513
    dialer-proxy: G2
proxy-groups:
  - name: G
    type: select
    proxies: [A]
  - name: G2
    type: select
    proxies: [B]
rules:
  - MATCH,DIRECT
"#
    ))
    .unwrap()
}

/// Registry plus the three mock servers, with per-server accept counters.
struct Harness {
    proxies: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    accepts: HashMap<&'static str, Arc<AtomicUsize>>,
}

impl Harness {
    fn accepts(&self, server: &str) -> usize {
        self.accepts[server].load(Ordering::SeqCst)
    }

    /// Dial `name` and discard the outcome — the handshakes are expected to
    /// fail, only the physical contact matters.
    async fn dial(&self, name: &str) {
        let metadata = Metadata {
            network: Network::Tcp,
            host: "127.0.0.1".into(),
            dst_ip: Some("127.0.0.1".parse().unwrap()),
            dst_port: 9,
            ..Default::default()
        };
        let proxy = self
            .proxies
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be in the registry"));
        let _ = proxy.dial_tcp(&metadata).await;
    }
}

async fn harness() -> Harness {
    let (server_a, a_accepts) = counting_listener().await;
    let (server_b, b_accepts) = counting_listener().await;
    let (server_c, c_accepts) = counting_listener().await;

    let raw = config(server_a.port(), server_b.port(), server_c.port());
    let (proxies, _rules) = meow_config::rebuild_from_raw(&raw).expect("rebuild ok");

    Harness {
        proxies,
        accepts: HashMap::from([("A", a_accepts), ("B", b_accepts), ("C", c_accepts)]),
    }
}

/// The regression: `G` selects `A`, and `A` declares `dialer-proxy: B`. Both
/// the direct registry dial and the dial through the group must contact B's
/// server first. Before the fix the group held the pre-dialer `A` and contacted
/// A's server directly, bypassing the chain.
#[tokio::test]
async fn group_member_honours_its_dialer_proxy() {
    let h = harness().await;

    h.dial("A").await;
    assert_eq!(h.accepts("B"), 1, "registry A must chain through dialer B");
    assert_eq!(
        h.accepts("A"),
        0,
        "registry A must not contact its own server directly"
    );

    h.dial("G").await;
    assert_eq!(
        h.accepts("B"),
        2,
        "the group must reach the chained A, not a stale pre-dialer copy"
    );
    assert_eq!(
        h.accepts("A"),
        0,
        "dialer-proxy bypassed when the node is reached via a group"
    );
}

/// A `dialer-proxy` may name a group. The group is built *after* the dialer
/// pass, so only by-name resolution can find it; capturing an `Arc` at build
/// time would have nothing to capture.
#[tokio::test]
async fn dialer_may_name_a_group_built_later() {
    let h = harness().await;

    h.dial("C").await;
    assert_eq!(
        h.accepts("B"),
        1,
        "C must chain through group G2, whose only member is B"
    );
    assert_eq!(
        h.accepts("C"),
        0,
        "C must not contact its own server directly"
    );
}
