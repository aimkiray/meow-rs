//! smux protocol (sagernet/smux fork wire format — protocol version 1),
//! client side.
//!
//! This is NOT the upstream xtaci layout: sing-mux/sing-box use the
//! sagernet fork whose frames are: ver=1, cmd, len u16 LE, stream_id u32 LE, data
//! (8-byte header, little-endian) and whose version 1 has no window-update
//! (UPD) flow control — a v1 write just splits into MaxFrameSize frames.
//! Commands: SYN=0, FIN=1, PSH=2, NOP=3; client stream IDs are odd
//! (1, 3, 5, ...).  Matches sing-mux's smux usage (DefaultConfig +
//! KeepAliveDisabled): Version=1, MaxFrameSize=32768, MaxStreamBuffer=64 KiB,
//! MaxReceiveBuffer=4 MiB.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::{CancellationToken, PollSender};

const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const SMUX_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 8;

/// Largest frame payload — sagernet smux MaxFrameSize default (u16 length).
const MAX_FRAME_SIZE: usize = 32768;
/// Sagernet's default per-stream receive buffer (two maximum-sized frames).
const MAX_STREAM_BUFFER: usize = 64 * 1024;
const STREAM_QUEUE: usize = MAX_STREAM_BUFFER / MAX_FRAME_SIZE;
/// Sagernet's default session-wide receive budget.
const MAX_RECEIVE_BUFFER: usize = 4 * 1024 * 1024;
/// Bounded outbound queue; stream writes wait when the physical writer lags.
const OUTBOUND_QUEUE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    cmd: u8,
    stream_id: u32,
    data: Bytes,
}

impl Frame {
    #[cfg(test)]
    fn encode(&self) -> Bytes {
        encode_frame(self.cmd, self.stream_id, &self.data)
    }

    fn decode_header(buf: &[u8]) -> io::Result<(u8, usize, u32)> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "smux frame header too short",
            ));
        }
        if buf[0] != SMUX_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported smux version: {}", buf[0]),
            ));
        }
        let cmd = buf[1];
        let length = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok((cmd, length, stream_id))
    }
}

fn encode_frame(cmd: u8, stream_id: u32, data: &[u8]) -> Bytes {
    // The u16 length field caps single frames; poll_write limits writes to
    // MAX_FRAME_SIZE, so this only guards future call sites.
    debug_assert!(
        data.len() <= u16::MAX as usize,
        "smux frame payload exceeds u16 length"
    );
    let mut out = BytesMut::with_capacity(FRAME_HEADER_LEN + data.len());
    out.put_u8(SMUX_VERSION);
    out.put_u8(cmd);
    out.put_u16_le(data.len() as u16);
    out.put_u32_le(stream_id);
    out.put_slice(data);
    out.freeze()
}

struct InboundChunk {
    data: Bytes,
    /// Releases session receive capacity when the stream consumes or drops
    /// this chunk.
    _permit: Option<OwnedSemaphorePermit>,
}

struct SessionState {
    /// Streams keyed by stream ID; dropping the sender EOFs the stream.
    streams: Mutex<HashMap<u32, mpsc::Sender<InboundChunk>>>,
    dead: AtomicBool,
}

/// smux session over one physical connection (client role).
pub struct Session {
    state: Arc<SessionState>,
    writer_tx: mpsc::Sender<Bytes>,
    cancel: CancellationToken,
    next_stream_id: AtomicU32,
}

impl Session {
    /// True once the session is dead (reader/writer task ended or the
    /// physical connection failed).
    pub fn is_dead(&self) -> bool {
        self.state.dead.load(Ordering::SeqCst)
    }

    /// Start an smux client session over the IO.  A reader task owns the
    /// read half; a writer task serialises outbound frames.
    pub fn client<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(io);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(OUTBOUND_QUEUE);
        let state = Arc::new(SessionState {
            streams: Mutex::new(HashMap::new()),
            dead: AtomicBool::new(false),
        });
        let receive_budget = Arc::new(Semaphore::new(MAX_RECEIVE_BUFFER));
        let cancel = CancellationToken::new();

        // Writer task: outbound frames are already encoded, so the hot path
        // performs no second allocation or payload copy.
        let writer_state = Arc::clone(&state);
        let writer_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = writer_cancel.cancelled() => break,
                    frame = writer_rx.recv() => match frame {
                        Some(frame) => frame,
                        None => break,
                    },
                };
                let result = tokio::select! {
                    _ = writer_cancel.cancelled() => break,
                    result = writer.write_all(&frame) => result,
                };
                if result.is_err() {
                    break;
                }
            }
            writer_state.mark_dead().await;
            writer_cancel.cancel();
        });

        // Reader task: parse frames, route PSH/FIN to streams.
        let reader_state = Arc::clone(&state);
        let reader_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut header = [0u8; FRAME_HEADER_LEN];
            loop {
                let header_result = tokio::select! {
                    _ = reader_cancel.cancelled() => break,
                    result = reader.read_exact(&mut header) => result,
                };
                if header_result.is_err() {
                    break;
                }
                let Ok((cmd, length, stream_id)) = Frame::decode_header(&header) else {
                    break;
                };
                let permit = if cmd == CMD_PSH && length > 0 {
                    let permits = length as u32;
                    match tokio::select! {
                        _ = reader_cancel.cancelled() => break,
                        result = Arc::clone(&receive_budget).acquire_many_owned(permits) => result,
                    } {
                        Ok(permit) => Some(permit),
                        Err(_) => break,
                    }
                } else {
                    None
                };
                let mut payload = vec![0u8; length];
                if !payload.is_empty() {
                    let payload_result = tokio::select! {
                        _ = reader_cancel.cancelled() => break,
                        result = reader.read_exact(&mut payload) => result,
                    };
                    if payload_result.is_err() {
                        break;
                    }
                }
                if reader_state
                    .handle_frame(
                        cmd,
                        stream_id,
                        InboundChunk {
                            data: Bytes::from(payload),
                            _permit: permit,
                        },
                        &reader_cancel,
                    )
                    .await
                    .is_err()
                {
                    break;
                }
            }
            reader_state.mark_dead().await;
            reader_cancel.cancel();
        });

        Ok(Self {
            state,
            writer_tx,
            cancel,
            next_stream_id: AtomicU32::new(1),
        })
    }

    /// Open a new stream.  Client IDs count up by 2 from 1.
    pub async fn open_stream(self: &Arc<Self>) -> io::Result<SmuxStream> {
        if self.is_dead() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session is closed",
            ));
        }
        let id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        self.state.streams.lock().await.insert(id, tx);
        if self
            .writer_tx
            .send(encode_frame(CMD_SYN, id, &[]))
            .await
            .is_err()
        {
            self.state.streams.lock().await.remove(&id);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux writer gone",
            ));
        }
        Ok(SmuxStream {
            id,
            session: Arc::clone(self),
            poll_sender: PollSender::new(self.writer_tx.clone()),
            rx,
            pending: None,
            eof: false,
            fin_sent: false,
            shutdown_frame: None,
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.state.dead.store(true, Ordering::SeqCst);
        self.cancel.cancel();
    }
}

impl SessionState {
    async fn mark_dead(&self) {
        if !self.dead.swap(true, Ordering::SeqCst) {
            // Close every stream.  The read side distinguishes this physical
            // failure from a peer FIN by consulting `Session::is_dead`.
            self.streams.lock().await.clear();
        }
    }

    async fn handle_frame(
        &self,
        cmd: u8,
        stream_id: u32,
        chunk: InboundChunk,
        cancel: &CancellationToken,
    ) -> io::Result<()> {
        match cmd {
            CMD_PSH => {
                // Data for an unknown stream is dropped rather than killing
                // the session — an intentional divergence from xtaci (which
                // closes the connection on protocol violation): the server
                // may legitimately race a FIN (peer closed, stream removed)
                // against in-flight PSH frames.
                let tx = self.streams.lock().await.get(&stream_id).cloned();
                if let Some(tx) = tx {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "smux session closed",
                            ));
                        }
                        result = tx.send(chunk) => {
                            let _ = result;
                        }
                    }
                }
                Ok(())
            }
            CMD_FIN => {
                // Peer half-closed: EOF the read side by dropping the sender.
                self.streams.lock().await.remove(&stream_id);
                Ok(())
            }
            CMD_NOP => Ok(()),
            // v1 has no UPD; a server-initiated SYN is unexpected in
            // client-only usage and unsupported commands are protocol errors.
            CMD_SYN => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "smux: unexpected SYN from server (client-only usage)",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("smux: unknown command {other}"),
            )),
        }
    }
}

/// One multiplexed stream (AsyncRead + AsyncWrite).
pub struct SmuxStream {
    id: u32,
    session: Arc<Session>,
    poll_sender: PollSender<Bytes>,
    rx: mpsc::Receiver<InboundChunk>,
    /// Unread remainder of the last chunk handed to poll_read.
    pending: Option<InboundChunk>,
    eof: bool,
    fin_sent: bool,
    shutdown_frame: Option<Bytes>,
}

impl SmuxStream {
    fn best_effort_fin(&mut self) {
        if !self.fin_sent {
            self.fin_sent = true;
            let _ = self
                .session
                .writer_tx
                .try_send(encode_frame(CMD_FIN, self.id, &[]));
        }
    }
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        self.best_effort_fin();
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Every progress path returns Ready immediately: returning Pending
        // after writing into the caller's ReadBuf would lose those bytes
        // (the buffer is recreated on the next poll), violating the
        // AsyncRead contract.
        if buf.remaining() == 0 {
            return Poll::Pending;
        }
        if let Some(mut chunk) = this.pending.take() {
            let n = chunk.data.len().min(buf.remaining());
            buf.put_slice(&chunk.data[..n]);
            chunk.data.advance(n);
            if !chunk.data.is_empty() {
                this.pending = Some(chunk);
            }
            Poll::Ready(Ok(()))
        } else if this.eof {
            Poll::Ready(Ok(()))
        } else {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(mut chunk)) => {
                    let n = chunk.data.len().min(buf.remaining());
                    buf.put_slice(&chunk.data[..n]);
                    chunk.data.advance(n);
                    if !chunk.data.is_empty() {
                        this.pending = Some(chunk);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => {
                    this.eof = true;
                    if this.session.is_dead() {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "smux session closed",
                        )))
                    } else {
                        Poll::Ready(Ok(()))
                    }
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.session.is_dead() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session closed",
            )));
        }
        let written = buf.len().min(MAX_FRAME_SIZE);
        match this.poll_sender.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Ready(Ok(())) => {
                let frame = encode_frame(CMD_PSH, this.id, &buf[..written]);
                this.poll_sender
                    .send_item(frame)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Poll::Ready(Ok(written))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Frames are written by the writer task as soon as they are enqueued;
        // there is no additional local buffering to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fin_sent {
            return Poll::Ready(Ok(()));
        }
        let frame = this
            .shutdown_frame
            .take()
            .unwrap_or_else(|| encode_frame(CMD_FIN, this.id, &[]));
        match this.poll_sender.poll_reserve(cx) {
            Poll::Pending => {
                this.shutdown_frame = Some(frame);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Ready(Ok(())) => {
                this.poll_sender
                    .send_item(frame)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                this.fin_sent = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn frame_wire_layout_matches_sagernet_smux() {
        // SYN on stream 1: [ver=1][cmd=SYN][len=0 u16 LE][sid=1 u32 LE].
        let frame = Frame {
            cmd: CMD_SYN,
            stream_id: 1,
            data: Bytes::new(),
        };
        let buf = frame.encode();
        assert_eq!(&buf[..], &[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);

        // PSH with 3 bytes on stream 3.
        let frame = Frame {
            cmd: CMD_PSH,
            stream_id: 3,
            data: Bytes::from_static(b"abc"),
        };
        let buf = frame.encode();
        assert_eq!(
            &buf[..],
            &[0x01, 0x02, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, b'a', b'b', b'c']
        );

        let (cmd, length, sid) = Frame::decode_header(&buf[..FRAME_HEADER_LEN]).unwrap();
        assert_eq!(cmd, CMD_PSH);
        assert_eq!(length, 3);
        assert_eq!(sid, 3);
    }

    /// Minimal smux server over a duplex pipe (same sagernet v1 codec):
    /// echoes PSH payloads back on the same stream and answers FIN with FIN.
    async fn run_echo_server<S>(mut io: S) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let mut header = [0u8; FRAME_HEADER_LEN];
            loop {
                if io.read_exact(&mut header).await.is_err() {
                    return;
                }
                let Ok((cmd, length, stream_id)) = Frame::decode_header(&header) else {
                    return;
                };
                let mut payload = vec![0u8; length];
                if !payload.is_empty() && io.read_exact(&mut payload).await.is_err() {
                    return;
                }
                match cmd {
                    CMD_PSH => {
                        let echoed = payload.clone();
                        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + echoed.len());
                        buf.put_u8(SMUX_VERSION);
                        buf.put_u8(CMD_PSH);
                        buf.put_u16_le(echoed.len() as u16);
                        buf.put_u32_le(stream_id);
                        buf.put_slice(&echoed);
                        if io.write_all(&buf).await.is_err() {
                            return;
                        }
                    }
                    CMD_FIN => {
                        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN);
                        buf.put_u8(SMUX_VERSION);
                        buf.put_u8(CMD_FIN);
                        buf.put_u16_le(0);
                        buf.put_u32_le(stream_id);
                        if io.write_all(&buf).await.is_err() {
                            return;
                        }
                    }
                    _ => {}
                }
            }
        })
    }

    #[tokio::test]
    async fn open_stream_echo_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"hello smux").await.unwrap();
        let mut resp = [0u8; 10];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello smux");
    }

    #[tokio::test]
    async fn two_streams_multiplex_independently() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());

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
    async fn large_write_splits_into_max_frame_chunks() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        // 2.5 × MaxFrameSize — must arrive as 3 PSH frames and echo back
        // byte-identical.
        let payload = vec![0x5au8; MAX_FRAME_SIZE * 2 + MAX_FRAME_SIZE / 2];
        stream.write_all(&payload).await.unwrap();
        let mut resp = vec![0u8; payload.len()];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, payload);
    }

    #[tokio::test]
    async fn half_close_sends_fin_and_eofs_peer() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        assert_eq!(&resp[..], b"ping");
    }

    #[tokio::test]
    async fn physical_eof_is_reported_as_an_error() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();
        let server = tokio::spawn(async move {
            let mut syn = [0u8; FRAME_HEADER_LEN];
            server_io.read_exact(&mut syn).await.unwrap();
        });
        server.await.unwrap();

        let mut buf = [0u8; 1];
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("physical EOF must wake the stream")
            .expect_err("physical EOF must not look like a clean FIN");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn outbound_queue_applies_backpressure() {
        let (client_io, _server_io) = tokio::io::duplex(1);
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();
        let payload = vec![0x5a; MAX_FRAME_SIZE * (OUTBOUND_QUEUE + 2)];

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.write_all(&payload),
        )
        .await;
        assert!(
            result.is_err(),
            "a blocked physical writer must backpressure streams"
        );
    }

    struct DropTrackedIo {
        inner: tokio::io::DuplexStream,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropTrackedIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for DropTrackedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DropTrackedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn dropping_idle_session_releases_physical_io() {
        let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let session = Session::client(DropTrackedIo {
            inner: client_io,
            dropped: Arc::clone(&dropped),
        })
        .unwrap();
        drop(session);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping an idle session must stop its tasks and release the fd");
    }
}
