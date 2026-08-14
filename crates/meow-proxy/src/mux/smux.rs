//! smux protocol (sagernet/smux fork wire format — protocol version 1),
//! client side.
//!
//! This is NOT the upstream xtaci layout: sing-mux/sing-box use the
//! sagernet fork whose frames are [ver=1][cmd][len u16 LE][stream_id u32 LE][data]
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
use tokio::sync::{mpsc, Mutex};

const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const SMUX_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 8;

/// Largest frame payload — sagernet smux MaxFrameSize default (u16 length).
const MAX_FRAME_SIZE: usize = 32768;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    cmd: u8,
    stream_id: u32,
    data: Bytes,
}

impl Frame {
    fn encode_into(&self, out: &mut BytesMut) {
        // The u16 length field caps single frames; send_push splits writes at
        // MAX_FRAME_SIZE, so this only guards future call sites.
        debug_assert!(
            self.data.len() <= u16::MAX as usize,
            "smux frame payload exceeds u16 length"
        );
        out.put_u8(SMUX_VERSION);
        out.put_u8(self.cmd);
        out.put_u16_le(self.data.len() as u16);
        out.put_u32_le(self.stream_id);
        out.put_slice(&self.data);
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

struct SessionInner {
    writer_tx: mpsc::UnboundedSender<Frame>,
    /// Streams keyed by stream ID; dropping the sender EOFs the stream.
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>,
    dead: AtomicBool,
}

/// smux session over one physical connection (client role).
pub struct Session {
    inner: Arc<SessionInner>,
    next_stream_id: AtomicU32,
}

impl Session {
    /// True once the session is dead (reader/writer task ended or the
    /// physical connection failed).
    pub fn is_dead(&self) -> bool {
        self.inner.dead.load(Ordering::SeqCst)
    }

    /// Start an smux client session over the IO.  A reader task owns the
    /// read half; a writer task serialises outbound frames.
    pub fn client<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(io);
        let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<Frame>();

        let inner = Arc::new(SessionInner {
            writer_tx,
            streams: Mutex::new(HashMap::new()),
            dead: AtomicBool::new(false),
        });

        // Writer task: drain frames, write full wire frames in order.
        let writer_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            while let Some(frame) = writer_rx.recv().await {
                let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + frame.data.len());
                frame.encode_into(&mut buf);
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
            writer_inner.mark_dead().await;
        });

        // Reader task: parse frames, route PSH/FIN to streams.
        let reader_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            let mut header = [0u8; FRAME_HEADER_LEN];
            loop {
                if reader.read_exact(&mut header).await.is_err() {
                    break;
                }
                let Ok((cmd, length, stream_id)) = Frame::decode_header(&header) else {
                    break;
                };
                let mut payload = vec![0u8; length];
                if !payload.is_empty() && reader.read_exact(&mut payload).await.is_err() {
                    break;
                }
                let frame = Frame {
                    cmd,
                    stream_id,
                    data: Bytes::from(payload),
                };
                if reader_inner.handle_frame(&frame).await.is_err() {
                    break;
                }
            }
            reader_inner.mark_dead().await;
        });

        Ok(Self {
            inner,
            next_stream_id: AtomicU32::new(1),
        })
    }

    /// Open a new stream.  Client IDs count up by 2 from 1.
    pub async fn open_stream(self: &Arc<Self>) -> io::Result<SmuxStream> {
        if self.inner.dead.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session is closed",
            ));
        }
        let id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.streams.lock().await.insert(id, tx);
        self.inner
            .writer_tx
            .send(Frame {
                cmd: CMD_SYN,
                stream_id: id,
                data: Bytes::new(),
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "smux writer gone"))?;
        Ok(SmuxStream {
            id,
            session: Arc::clone(&self.inner),
            rx,
            pending: Bytes::new(),
            eof: AtomicBool::new(false),
            fin_sent: AtomicBool::new(false),
        })
    }
}

impl SessionInner {
    async fn mark_dead(&self) {
        self.dead.store(true, Ordering::SeqCst);
        // EOF every stream: dropping the senders closes each receiver.
        self.streams.lock().await.clear();
    }

    async fn handle_frame(&self, frame: &Frame) -> io::Result<()> {
        match frame.cmd {
            CMD_PSH => {
                // Data for an unknown stream is dropped rather than killing
                // the session — an intentional divergence from xtaci (which
                // closes the connection on protocol violation): the server
                // may legitimately race a FIN (peer closed, stream removed)
                // against in-flight PSH frames.
                if let Some(tx) = self.streams.lock().await.get(&frame.stream_id) {
                    let _ = tx.send(frame.data.clone());
                }
                Ok(())
            }
            CMD_FIN => {
                // Peer half-closed: EOF the read side by dropping the sender.
                self.streams.lock().await.remove(&frame.stream_id);
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
    session: Arc<SessionInner>,
    rx: mpsc::UnboundedReceiver<Bytes>,
    /// Unread remainder of the last chunk handed to poll_read.
    pending: Bytes,
    eof: AtomicBool,
    fin_sent: AtomicBool,
}

impl SmuxStream {
    fn send_frame(&self, cmd: u8, data: Bytes) -> io::Result<()> {
        if self.session.dead.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session is closed",
            ));
        }
        self.session
            .writer_tx
            .send(Frame {
                cmd,
                stream_id: self.id,
                data,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "smux writer gone"))
    }

    /// Queue the payload as one or more PSH frames, split at MaxFrameSize
    /// (the u16 length field caps single frames at 65535; the peer's
    /// default MaxFrameSize is 32768).
    fn send_push(&self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(MAX_FRAME_SIZE) {
            self.send_frame(CMD_PSH, Bytes::copy_from_slice(chunk))?;
        }
        Ok(())
    }

    fn best_effort_fin(&self) {
        if !self.fin_sent.swap(true, Ordering::SeqCst) {
            let _ = self.send_frame(CMD_FIN, Bytes::new());
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
        if !this.pending.is_empty() {
            let n = this.pending.len().min(buf.remaining());
            buf.put_slice(&this.pending[..n]);
            this.pending.advance(n);
            Poll::Ready(Ok(()))
        } else if this.eof.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if n < chunk.len() {
                        this.pending = chunk.slice(n..);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => {
                    this.eof.store(true, Ordering::SeqCst);
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        this.send_push(buf)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Frames are written by the writer task as soon as they are enqueued;
        // there is no additional local buffering to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().best_effort_fin();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn frame_wire_layout_matches_sagernet_smux() {
        // SYN on stream 1: [ver=1][cmd=SYN][len=0 u16 LE][sid=1 u32 LE].
        let frame = Frame {
            cmd: CMD_SYN,
            stream_id: 1,
            data: Bytes::new(),
        };
        let mut buf = BytesMut::new();
        frame.encode_into(&mut buf);
        assert_eq!(&buf[..], &[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);

        // PSH with 3 bytes on stream 3.
        let frame = Frame {
            cmd: CMD_PSH,
            stream_id: 3,
            data: Bytes::from_static(b"abc"),
        };
        let mut buf = BytesMut::new();
        frame.encode_into(&mut buf);
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
                    CMD_SYN => {}
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
}
