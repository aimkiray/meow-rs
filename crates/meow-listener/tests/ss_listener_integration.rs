#![cfg(feature = "listener-shadowsocks")]
//! Integration tests for the shadowsocks encrypted-server inbound listener.
//!
//! Drives the real `ShadowsocksListener` → `route_inbound_tcp` → DIRECT
//! relay path with an in-process `shadowsocks` crate *client* and a local
//! echo server. No external binary (`sslocal`/`ssserver`) required.
//!
//! Cipher decryption is exercised end-to-end: the client encrypts with the
//! same `aes-256-gcm` key the listener expects; a wrong password fails at
//! `ProxyServerStream::handshake` and the connection is dropped without
//! leaking the target.

mod common;

use common::{direct_tunnel, spawn_echo_server};
use meow_listener::{ShadowsocksListener, SsObfsMode};
use meow_transport::simple_obfs::client::{HttpObfs, TlsObfs};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use shadowsocks::ProxySocket;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CIPHER: &str = "aes-256-gcm";
const PASSWORD: &str = "test-ss-listener-password";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Build a shadowsocks *client* `ServerConfig` pointing at the listener.
fn client_cfg(ss_addr: std::net::SocketAddr) -> ServerConfig {
    let method = CIPHER.parse::<CipherKind>().unwrap();
    ServerConfig::new(ss_addr, PASSWORD, method).unwrap()
}

/// Bind a `ShadowsocksListener` (TCP, no obfs, no UDP) on an ephemeral port
/// and return its address. The accept loop is spawned in the background.
async fn bind_ss_listener() -> std::net::SocketAddr {
    bind_ss_listener_with(false).await
}

/// Like [`bind_ss_listener`] but with `udp: true` so the listener also starts
/// the SS UDP relay on the same resolved port.
async fn bind_ss_listener_udp() -> std::net::SocketAddr {
    bind_ss_listener_with(true).await
}

async fn bind_ss_listener_with(udp: bool) -> std::net::SocketAddr {
    bind_ss_listener_cfg(udp, None).await
}

/// Bind a `ShadowsocksListener` with a simple-obfs mode (TCP only; UDP is
/// auto-disabled by the listener when obfs is set).
async fn bind_ss_listener_obfs(obfs: SsObfsMode) -> std::net::SocketAddr {
    bind_ss_listener_cfg(false, Some(obfs)).await
}

async fn bind_ss_listener_cfg(udp: bool, obfs: Option<SsObfsMode>) -> std::net::SocketAddr {
    let tunnel = direct_tunnel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ss = ShadowsocksListener::new(tunnel, addr, "ss-test".into(), CIPHER, PASSWORD, udp, obfs)
        .unwrap();
    tokio::spawn(async move {
        let _ = ss.run_on(listener).await;
    });
    // The TCP socket is already bound, so the kernel backlog accepts
    // connections before the accept loop runs. For UDP tests, the relay
    // socket is bound inside `run_on`; a brief yield gives the spawned
    // task time to start. 50ms is conservative — the ProxySocket::bind is
    // a single syscall.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Spawn a UDP echo server on an ephemeral port; returns its address.
async fn spawn_udp_echo_server() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if sock.send_to(&buf[..n], src).await.is_err() {
                break;
            }
        }
    });
    addr
}

#[tokio::test]
async fn ss_tcp_listener_relays_to_direct_echo() {
    let echo = spawn_echo_server().await;
    let ss_addr = bind_ss_listener().await;

    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let mut stream = tokio::time::timeout(TIMEOUT, ProxyClientStream::connect(ctx, &cfg, echo))
        .await
        .expect("client connect timed out")
        .expect("client connect failed");

    let payload = b"hello through ss listener";
    stream.write_all(payload).await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("echo read timed out")
        .expect("echo read failed");
    assert_eq!(&buf[..n], payload, "echoed payload must match");
}

#[tokio::test]
async fn ss_tcp_listener_rejects_wrong_password() {
    let echo = spawn_echo_server().await;
    let ss_addr = bind_ss_listener().await;

    // Client with a wrong password. The SS AEAD handshake (first block
    // decrypt) fails on the server side; the connection is dropped. The
    // client's write/read then surfaces an error or EOF — never the echo.
    // The rejection is fast (sub-millisecond AEAD tag check); 2s is a
    // generous safety net, not the expected latency.
    let method = CIPHER.parse::<CipherKind>().unwrap();
    let bad_cfg = ServerConfig::new(ss_addr, "wrong-password", method).unwrap();
    let ctx = Context::new_shared(ServerType::Local);

    // `connect` only opens the TCP link; the AEAD tag is checked on the first
    // read/write of payload, so we drive a write + read and assert no echo.
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        ProxyClientStream::connect(ctx, &bad_cfg, echo),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    let _ = stream.write_all(b"should-not-relay").await;
    let mut buf = [0u8; 64];
    let res = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    // Either a clean EOF (0 bytes) or an error — never the echoed payload.
    // (clippy: collapse the two empty arms into one pattern.)
    match res {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("wrong-password connection relayed {n} bytes (should be rejected)"),
        Err(_) => panic!("read timed out"),
    }
}

#[tokio::test]
async fn ss_udp_listener_relays_to_direct_echo() {
    let echo = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp().await;

    let payload = b"hello ss udp";
    // Client-side SS UDP socket: a bound (non-connected) socket so we can use
    // `send_to`/`recv_from` (the connected-socket `send`/`recv` pair would also
    // work, but `send_to` keeps the server endpoint explicit and inspectable).
    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let raw =
        shadowsocks::net::UdpSocket::bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .await
            .unwrap();
    let client = ProxySocket::from_socket(
        shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Client,
        ctx,
        &cfg,
        raw,
    );
    client
        .send_to(ss_addr, &Address::SocketAddress(echo), payload)
        .await
        .unwrap();

    let mut buf = [0u8; 128];
    let (n, _server_peer, _reply_addr, _recv_total) =
        tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
            .await
            .expect("udp echo timed out")
            .expect("udp recv failed");
    assert_eq!(&buf[..n], payload, "echoed UDP payload must match");
}

// ── simple-obfs TCP relay (HTTP + TLS) ──────────────────────────────────────
//
// The client wraps its TcpStream in the obfs *client* codec, then hands it to
// `ProxyClientStream::from_stream` for SS encryption. The listener wraps the
// accepted stream in the obfs *server* codec before `ProxyServerStream`
// decrypts — exercising the full obfs↔SS layering end-to-end.

async fn ss_obfs_tcp_round_trip(obfs: SsObfsMode) {
    let echo = spawn_echo_server().await;
    let ss_addr = bind_ss_listener_obfs(obfs).await;

    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let raw = TcpStream::connect(ss_addr).await.unwrap();
    // The obfs client needs a host/port (HTTP) or server name (TLS). Use the
    // listener's address — the value is only embedded in fake headers/SNI and
    // is never validated by the server codec.
    match obfs {
        SsObfsMode::Http => {
            let obfs = HttpObfs::new(raw, "example.com".to_string(), ss_addr.port());
            relay_echo(ProxyClientStream::from_stream(ctx, obfs, &cfg, echo)).await;
        }
        SsObfsMode::Tls => {
            let obfs = TlsObfs::new(raw, "example.com".to_string());
            relay_echo(ProxyClientStream::from_stream(ctx, obfs, &cfg, echo)).await;
        }
    }
}

/// Drive a `ProxyClientStream` echo round-trip and assert the payload matches.
async fn relay_echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: ProxyClientStream<S>,
) {
    let payload = b"hello through ss obfs";
    stream.write_all(payload).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("obfs echo timed out")
        .expect("obfs echo read failed");
    assert_eq!(&buf[..n], payload, "echoed obfs payload must match");
}

#[tokio::test]
async fn ss_tcp_listener_with_http_obfs_relays() {
    ss_obfs_tcp_round_trip(SsObfsMode::Http).await;
}

#[tokio::test]
async fn ss_tcp_listener_with_tls_obfs_relays() {
    ss_obfs_tcp_round_trip(SsObfsMode::Tls).await;
}
