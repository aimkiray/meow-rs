//! Pluggable TCP dialer for proxy chaining (mihomo `dialer-proxy` model).
//!
//! Each proxy adapter holds an `Arc<dyn TcpDialer>` and calls `dial()` to
//! obtain the raw underlying stream to its server.  The default
//! [`DirectDialer`] uses `meow_common::connect_tcp_host` (resolver-aware,
//! SocketProtector-aware).  When `dialer-proxy` is configured, a
//! [`ProxyDialer`] is injected instead — it tunnels through another proxy,
//! making chaining transparent to the adapter's TLS + protocol handshake.
//!
//! upstream: mihomo `component/proxydialer` + `BasicOption.NewDialer`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::{Metadata, Proxy, ProxyConn};
use meow_transport::Stream;

/// A pluggable dialer for the underlying connection to a proxy server.
///
/// Mirrors mihomo's `C.Dialer` interface.  Adapters call `dial()` instead of
/// `meow_common::connect_tcp_host()` directly so that `dialer-proxy` can
/// inject a proxied connection transparently.
#[async_trait]
pub trait TcpDialer: Send + Sync {
    /// Dial `host:port` and return a duplex stream.
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>>;

    /// Dial an already-resolved [`SocketAddr`].
    ///
    /// Callers holding a literal address should prefer this over
    /// `dial(&addr.ip().to_string(), addr.port())`, which allocates a `String`
    /// only for the callee to parse it straight back into an `IpAddr`.
    /// The default implementation does exactly that round-trip, so
    /// implementors that can dial an address directly should override it.
    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        self.dial(&addr.ip().to_string(), addr.port()).await
    }

    /// Whether this dialer tunnels through another proxy (vs. direct).
    ///
    /// Adapters whose UDP path uses a raw socket that bypasses `dial()`
    /// (e.g. Shadowsocks UDP relay) should check this and disable UDP when a
    /// proxy dialer is installed, so UDP traffic does not leak past the
    /// `dialer-proxy` chain.
    fn is_proxy(&self) -> bool {
        false
    }
}

/// Direct TCP dialer — the default, equivalent to mihomo's `dialer.NewDialer()`.
///
/// Uses `meow_common::connect_tcp_host` which is resolver-aware and
/// SocketProtector-aware (Android `VpnService.protect(fd)` etc.).
pub struct DirectDialer;

#[async_trait]
impl TcpDialer for DirectDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        let tcp = meow_common::connect_tcp_host(host, port).await?;
        // Preserve TCP_NODELAY (disable Nagle) — all call sites that
        // previously called `tcp.set_nodelay(true)` on the raw
        // `TcpStream` now rely on the dialer to do it once here.
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }

    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        // Skip the default's `to_string()` + re-parse: `connect_tcp` takes the
        // `SocketAddr` as-is and keeps the SocketProtector hook.
        let tcp = meow_common::connect_tcp(addr).await?;
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }
}

/// Proxy dialer — tunnels through another proxy.  Equivalent to mihomo's
/// `proxyDialer.DialContext()`.
///
/// Calls `proxy.dial_tcp()` with metadata targeting `host:port`, then adapts
/// the returned `ProxyConn` into a `Stream` for the caller's transport chain.
pub struct ProxyDialer {
    proxy: Arc<dyn Proxy>,
}

impl ProxyDialer {
    pub fn new(proxy: Arc<dyn Proxy>) -> Self {
        Self { proxy }
    }

    /// Dial the front proxy with a fully-formed [`Metadata`] target.
    async fn dial_metadata(&self, meta: Metadata) -> io::Result<Box<dyn Stream>> {
        let conn = self
            .proxy
            .dial_tcp(&meta)
            .await
            .map_err(|e| io::Error::other(format!("dialer-proxy: {e}")))?;
        // `Box<dyn ProxyConn>` is unsized (!Sized), so it cannot satisfy
        // the `Any` bound required by the blanket `Stream` impl.  `ConnStream`
        // is a sized newtype that forwards `AsyncRead`/`AsyncWrite` through
        // the boxed conn, bridging `ProxyConn` → `Stream`.
        Ok(Box::new(ConnStream(conn)))
    }
}

#[async_trait]
impl TcpDialer for ProxyDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        // An IP-literal `host` becomes a typed `dst_ip` so the front proxy
        // encodes an IP address rather than a domain name that happens to look
        // like one.
        let meta = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => Metadata {
                dst_ip: Some(ip),
                dst_port: port,
                ..Default::default()
            },
            Err(_) => Metadata {
                host: host.into(),
                dst_port: port,
                ..Default::default()
            },
        };
        self.dial_metadata(meta).await
    }

    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        // Carry the literal address in `dst_ip` instead of rendering it into
        // `host`: adapters that encode the target for the front proxy then emit
        // an IP-typed address rather than a domain-typed one holding a
        // dotted-quad, which is what mihomo does and what SOCKS5/Trojan/VLESS
        // address encoding expects.
        let meta = Metadata {
            dst_ip: Some(addr.ip()),
            dst_port: addr.port(),
            ..Default::default()
        };
        self.dial_metadata(meta).await
    }

    fn is_proxy(&self) -> bool {
        true
    }
}

/// Wrap a `Box<dyn ProxyConn>` as a `meow_transport::Stream`.
///
/// `Stream` requires `Sized + Any`; `Box<dyn ProxyConn>` is `!Sized`, so it
/// cannot use the blanket `Stream` impl.  This newtype forwards
/// `AsyncRead`/`AsyncWrite` through the boxed conn.
///
/// Downcast-based optimizations are unaffected: the transport layers wrap
/// whatever they are handed in their own concrete type (e.g.
/// `RealityTlsStream` holds its inner stream as a `Box<dyn Stream>`), so
/// `as_any_mut()` still sees that outer type and the Reality raw-passthrough
/// shortcut fires the same whether the bottom of the stack is a `TcpStream` or
/// a `ConnStream`.
pub struct ConnStream(pub Box<dyn ProxyConn>);

impl tokio::io::AsyncRead for ConnStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ConnStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Unpin for ConnStream {}
