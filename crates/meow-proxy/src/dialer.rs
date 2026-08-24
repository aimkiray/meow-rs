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
}

#[async_trait]
impl TcpDialer for ProxyDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        let meta = Metadata {
            host: host.into(),
            dst_port: port,
            ..Default::default()
        };
        let conn = self
            .proxy
            .dial_tcp(&meta)
            .await
            .map_err(|e| io::Error::other(format!("dialer-proxy: {e}")))?;
        // ProxyConn → StreamConn(Box<dyn Stream>) — StreamConn wraps a
        // Stream, but here we have a ProxyConn.  We need the reverse: wrap
        // the ProxyConn so it satisfies the Stream trait (AsyncRead +
        // AsyncWrite + Unpin + Send + Sync + Any).  Box<dyn ProxyConn> is
        // unsized so it cannot directly satisfy `Any`; ConnStream bridges
        // that.
        Ok(Box::new(ConnStream(conn)))
    }
}

/// Wrap a `Box<dyn ProxyConn>` as a `meow_transport::Stream`.
///
/// `Stream` requires `Sized + Any`; `Box<dyn ProxyConn>` is `!Sized`, so it
/// cannot use the blanket `Stream` impl.  This newtype forwards
/// `AsyncRead`/`AsyncWrite` through the boxed conn.
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

