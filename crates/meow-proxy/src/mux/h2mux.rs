//! h2mux protocol (mihomo default), client side.
//!
//! Mirrors metacubex/sing-mux h2mux.go: the physical connection runs an
//! HTTP/2 client after the mux request header; each logical stream is one
//! CONNECT request to `https://localhost`.  The request body carries
//! client→server bytes as h2 DATA frames, the response body carries
//! server→client bytes.  No gun/grpc framing — raw passthrough.
//!
//! The response is resolved lazily on the first read, mirroring sing-mux's
//! lateHTTPConn: sing-box's h2mux server defers flushing the 200 headers
//! until its first response-body write, so awaiting the response before
//! returning the stream would deadlock (the server waits for our data
//! before it ever writes).

use bytes::Bytes;
use http::{Method, Request, StatusCode, Version};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// Setup timeout for the CONNECT request/response round trip; mirrors
/// sing-mux's `TCPTimeout` (5 s).  On expiry the read side fails with
/// TimedOut (the caller tears the stream down).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// h2mux session over one physical connection (client role).  The concrete
/// IO type is erased — the driver task owns the h2 connection.
pub struct Session {
    send_request: h2::client::SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    _task: tokio::task::JoinHandle<()>,
}

impl Session {
    pub async fn client<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send_request, connection) =
            h2::client::handshake(io).await.map_err(io::Error::other)?;
        let dead = Arc::new(AtomicBool::new(false));
        let driver_dead = Arc::clone(&dead);
        // Drive SETTINGS / WINDOW_UPDATE / PING frames; the future resolves
        // when the physical connection dies.
        let task = tokio::spawn(async move {
            let _ = connection.await;
            driver_dead.store(true, Ordering::SeqCst);
        });
        Ok(Self {
            send_request,
            dead,
            _task: task,
        })
    }

    /// Open one h2mux stream: a CONNECT request whose body/response body
    /// form the duplex channel.  Returns immediately — the server may not
    /// flush its 200 until the first response-body write (see module docs).
    pub async fn open_stream(&self) -> io::Result<Stream> {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://localhost")
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (response_future, send_stream) = self
            .send_request
            .clone()
            .send_request(request, false)
            .map_err(io::Error::other)?;
        let (setup_tx, setup_rx) = oneshot::channel();
        // Resolve the response in the background, bounded by TCPTimeout —
        // sing-mux spawns the same RoundTrip + timeout goroutine.
        tokio::spawn(async move {
            tokio::select! {
                result = response_future => {
                    let result = result
                        .map_err(io::Error::other)
                        .and_then(|response| {
                            if response.status() == StatusCode::OK {
                                Ok(response.into_body())
                            } else {
                                Err(io::Error::other(format!(
                                    "h2mux: unexpected status {}",
                                    response.status()
                                )))
                            }
                        });
                    let _ = setup_tx.send(result);
                }
                _ = tokio::time::sleep(RESPONSE_TIMEOUT) => {
                    let _ = setup_tx.send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "h2mux: response timeout",
                    )));
                }
            }
        });
        Ok(Stream::new(send_stream, setup_rx))
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
}

/// Response body, delivered by the setup task and resolved lazily on the
/// first read.
enum RecvState {
    Pending(oneshot::Receiver<io::Result<h2::RecvStream>>),
    Ready(h2::RecvStream),
}

impl RecvState {
    /// Resolve the response once; afterwards yields the body stream.
    fn poll_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut h2::RecvStream>> {
        loop {
            match self {
                RecvState::Pending(rx) => match Pin::new(rx).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "h2mux: setup task dropped",
                        )))
                    }
                    Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(Ok(stream))) => {
                        *self = RecvState::Ready(stream);
                    }
                },
                RecvState::Ready(stream) => return Poll::Ready(Ok(stream)),
            }
        }
    }
}

/// One h2mux stream (a CONNECT request/response pair), exposed with tokio
/// IO traits.
pub struct Stream {
    send: h2::SendStream<Bytes>,
    recv: RecvState,
    /// Buffered payload bytes from the most recently received DATA frame.
    read_buf: Bytes,
    /// Payload stashed while waiting for h2 send-window capacity; set on the
    /// first poll of a logical write so `reserve_capacity` runs exactly
    /// once per write.
    pending_write: Option<Bytes>,
    eos_sent: bool,
}

impl Stream {
    fn new(
        send: h2::SendStream<Bytes>,
        setup: oneshot::Receiver<io::Result<h2::RecvStream>>,
    ) -> Self {
        Self {
            send,
            recv: RecvState::Pending(setup),
            read_buf: Bytes::new(),
            pending_write: None,
            eos_sent: false,
        }
    }

    /// Half-close the request body with an empty DATA + EOS frame, exactly
    /// once.
    fn best_effort_eos(&mut self) {
        if !self.eos_sent {
            self.eos_sent = true;
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Let the server see EOF on this stream even when shutdown() was
        // never called explicitly (mirrors sing-mux's request cancel).
        self.best_effort_eos();
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Drain buffered bytes from the last DATA frame first.
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                let _ = this.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }
            // Resolve the response lazily on first read.
            let recv = match this.recv.poll_stream(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(recv)) => recv,
            };
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // clean EOF
                Poll::Ready(Some(Err(e))) => {
                    // sing-box closes finished mux streams with a remote
                    // RST_STREAM(NO_ERROR); treat it as clean EOF (Go's
                    // http2 client maps it to io.EOF the same way).
                    if e.is_reset() && e.is_remote() && e.reason() == Some(h2::Reason::NO_ERROR) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    // Release flow-control window back to the sender.
                    let _ = recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                    // loop → drain read_buf
                }
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // Stash the payload exactly once per logical write: if pending_write
        // is set, a previous poll returned Pending and capacity has been
        // reserved — do not encode or reserve again.  This relies on the
        // AsyncWrite contract that a Pending poll is retried with the same
        // buffer (tokio's write/write_all always do); same pattern as
        // meow-transport's h2 transport.
        if this.pending_write.is_none() {
            let data = Bytes::copy_from_slice(buf);
            this.send.reserve_capacity(data.len());
            this.pending_write = Some(data);
        }
        // Wait for the h2 send window to open.
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2mux: send stream closed",
                )))
            }
            Poll::Ready(Some(Err(e))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(Some(Ok(_capacity))) => {
                let data = this.pending_write.take().expect("set above");
                this.send.send_data(data, false).map_err(io::Error::other)?;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // DATA frames are pushed into the h2 connection immediately on
        // send_data; there is no write-side buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().best_effort_eos();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// h2mux echo server over a duplex pipe, mirroring sing-mux's
    /// h2MuxServerSession: answer every request with 200 and pipe the
    /// request body into the response body until the request half closes.
    async fn run_echo_server<S>(io: S) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let mut connection = match h2::server::handshake(io).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            // Keep polling accept(): only the connection's poll drives the
            // codec, so the buffered response frames need it to keep being
            // polled while per-stream handlers await request data.
            while let Some(result) = connection.accept().await {
                let (request, mut respond) = match result {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let response = http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("static response");
                    let mut send = match respond.send_response(response, false) {
                        Ok(send) => send,
                        Err(_) => return,
                    };
                    while let Some(chunk) = body.data().await {
                        let chunk = match chunk {
                            Ok(chunk) => chunk,
                            Err(_) => break,
                        };
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if send.send_data(chunk, false).is_err() {
                            break;
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                });
            }
        })
    }

    #[tokio::test]
    async fn open_stream_echo_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).await.unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"hello h2mux").await.unwrap();
        let mut resp = [0u8; 11];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello h2mux");
    }

    #[tokio::test]
    async fn two_streams_multiplex_independently() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).await.unwrap());

        let mut a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();

        a.write_all(b"AAA").await.unwrap();
        b.write_all(b"BBB").await.unwrap();
        let mut buf = [0u8; 3];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"AAA");
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"BBB");
    }

    #[tokio::test]
    async fn concurrent_opens_all_succeed() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).await.unwrap());

        let opens = (0..8)
            .map(|i| {
                let session = Arc::clone(&session);
                async move { (i, session.open_stream().await.unwrap()) }
            })
            .collect::<Vec<_>>();
        let streams = futures::future::join_all(opens).await;
        assert_eq!(streams.len(), 8);
        for (i, mut stream) in streams {
            let payload = format!("stream-{i}").into_bytes();
            stream.write_all(&payload).await.unwrap();
            let mut resp = vec![0u8; payload.len()];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, payload);
        }
    }

    /// Live interop probe against a running sing-box VLESS mux inbound
    /// (127.0.0.1:4411, see target/e2e/mux-interop/).  Run with
    /// `--ignored` — requires the server and the local web server
    /// (target/e2e/websrv.py on :18081) to be up.  Exercises the full client
    /// path: VLESS handshake → mux request header → CONNECT stream →
    /// stream-request flags + Socksaddr → response status byte → relay.
    #[tokio::test]
    #[ignore]
    async fn live_singbox_vless_probe() {
        use crate::mux::{DialFn, MuxClient, MuxOptions, Protocol};
        use crate::vless::header::{Cmd, VlessAddr};
        use crate::vless::VlessConn;
        use crate::StreamConn;
        use meow_common::{MeowError, ProxyConn};

        // b831381d-6324-4d53-ad4f-8cda48b30811
        const UUID: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let dial: DialFn = Arc::new(move || {
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(("127.0.0.1", 4411))
                    .await
                    .map_err(MeowError::Io)?;
                let addr = VlessAddr::domain(super::super::MUX_DESTINATION_FQDN).unwrap();
                let conn = VlessConn::new(
                    Box::new(tcp),
                    &UUID,
                    None,
                    Cmd::Tcp,
                    super::super::MUX_DESTINATION_PORT,
                    &addr,
                )
                .await?;
                Ok(Box::new(StreamConn(Box::new(conn))) as Box<dyn ProxyConn>)
            })
        });
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::H2Mux,
                ..MuxOptions::default()
            },
        );
        let mut stream = client.open_stream("127.0.0.1", 18081).await.unwrap();
        stream
            .write_all(
                b"GET /page1.html HTTP/1.1
Host: 127.0.0.1
Connection: close

",
            )
            .await
            .unwrap();
        let mut resp = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp)
            .await
            .unwrap();
        assert!(
            resp.starts_with(b"HTTP/1.1 200"),
            "unexpected response: {}",
            String::from_utf8_lossy(&resp[..resp.len().min(120)])
        );
    }
}
