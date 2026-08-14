//! Xray Mux.Cool client (mux config: protocol muxcool, VLESS-only).
//!
//! Mux.Cool multiplexes logical streams over one physical VLESS connection:
//! the session connection's VLESS request carries command 0x03
//! (CommandMux) and no address, then every stream exchanges
//! [meta][payload] frames that carry the real per-stream destination.
//!
//! # Wire format
//!
//! upstream: xray common/mux/frame.go (FrameMetadata / frame format comment),
//!           xray common/mux/writer.go (WriteMultiBuffer / Close);
//!           sagernet/sing-vmess mux.go::HandleMuxConnection (server side).
//!
//!   meta_len   u16 BE    length of the meta block
//!   meta:
//!     session_id u16 BE  stream id - client-allocated, echoed by the server
//!     status     u8      1=New 2=Keep 3=End 4=KeepAlive
//!     option     u8      bit 1 = Data, bit 2 = Error
//!     (New frames, and Keep frames carrying a UDP destination:)
//!       network u8       1=TCP 2=UDP
//!       port    u16 BE
//!       atype   u8       0x01 IPv4 | 0x02 domain | 0x03 IPv6
//!       address ...      VMess address layout - port BEFORE address
//!   payload_len u16 BE   present iff option&Data
//!   payload             payload_len bytes
//!
//! End frames carry no payload length.  The server never opens streams: it
//! answers on the session id from the client's New frame.  Extra meta bytes
//! are tolerated (Xray appends optional fullcone/GlobalID metadata we do not
//! send; both Xray and sing-vmess servers discard unknown meta bytes).
//!
//! Compatible servers: Xray-core (VLESS inbound) and sing-box/sing-vmess
//! (vmess.HandleMuxConnection behind VLESS CommandMux), plus mihomo's
//! sing-vmess VLESS listener.

use super::client::MuxSession;
use bytes::{BufMut, Bytes, BytesMut};
use meow_common::{MeowError, ProxyConn, ProxyPacketConn, Result};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::PollSender;

// --- Wire constants (xray common/mux/frame.go) ------------------------------

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;

const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;

const ATYPE_IPV4: u8 = 0x01;
const ATYPE_DOMAIN: u8 = 0x02;
const ATYPE_IPV6: u8 = 0x03;

/// Session id used on keepalive frames (not bound to any stream).
const KEEPALIVE_SESSION_ID: u16 = 0;

/// Payload cap per data frame - xray splits stream writes at 8 KiB
/// (common/mux/writer.go::WriteMultiBuffer), keeping frame latency bounded.
const MAX_PAYLOAD: usize = 8 * 1024;

/// Per-stream inbound queue depth (frames, not bytes); a stalled consumer
/// applies backpressure to the reader task, mirroring xray's blocking
/// per-session buffer (common/mux/session.go).
const STREAM_QUEUE: usize = 32;

/// Client keepalive cadence - keeps NAT bindings alive on idle sessions;
/// servers drop status-4 frames silently on both sides.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Meta length cap — xray FrameMetadata::Unmarshal rejects meta_len > 512;
/// capping also bounds the per-frame allocation on garbage input.
const MAX_META: usize = 512;

// --- Frame codec (pure, no I/O - byte-tested below) -------------------------

/// Append [port u16 BE][atype u8][address] (VMess layout: port first).
fn put_address(out: &mut BytesMut, host: &str, port: u16) -> io::Result<()> {
    out.put_u16(port);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.put_u8(ATYPE_IPV4);
            out.put_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.put_u8(ATYPE_IPV6);
            out.put_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("mux.cool: domain '{host}' exceeds 255 bytes"),
                ));
            }
            out.put_u8(ATYPE_DOMAIN);
            out.put_u8(host.len() as u8);
            out.put_slice(host.as_bytes());
        }
    }
    Ok(())
}

/// Encode a New frame (option = no payload): opens the stream and declares
/// its destination.  The first data chunk follows in a Keep frame.
pub(crate) fn encode_new_frame(sid: u16, udp: bool, host: &str, port: u16) -> io::Result<Bytes> {
    let mut out = BytesMut::with_capacity(64);
    out.put_u16(0); // meta_len placeholder, patched below
    out.put_u16(sid);
    out.put_u8(STATUS_NEW);
    out.put_u8(0); // no payload
    out.put_u8(if udp { NETWORK_UDP } else { NETWORK_TCP });
    put_address(&mut out, host, port)?;
    let meta_len = out.len() - 2;
    out[0..2].copy_from_slice(&(meta_len as u16).to_be_bytes());
    Ok(out.freeze())
}

/// Encode a Keep+Data frame.  dest adds a per-datagram destination (UDP);
/// TCP data frames carry none (meta_len = 4).
fn encode_data_frame(sid: u16, data: &[u8], dest: Option<(&str, u16)>) -> io::Result<Bytes> {
    let mut out = BytesMut::with_capacity(16 + data.len());
    out.put_u16(0); // meta_len placeholder
    out.put_u16(sid);
    out.put_u8(STATUS_KEEP);
    out.put_u8(OPTION_DATA);
    if let Some((host, port)) = dest {
        out.put_u8(NETWORK_UDP);
        put_address(&mut out, host, port)?;
    }
    let meta_len = out.len() - 2;
    out[0..2].copy_from_slice(&(meta_len as u16).to_be_bytes());
    out.put_u16(data.len() as u16);
    out.put_slice(data);
    Ok(out.freeze())
}

/// Encode an End frame (no payload length field follows).
pub(crate) fn encode_end_frame(sid: u16, has_error: bool) -> Bytes {
    let mut out = BytesMut::with_capacity(6);
    out.put_u16(4);
    out.put_u16(sid);
    out.put_u8(STATUS_END);
    out.put_u8(if has_error { OPTION_ERROR } else { 0 });
    out.freeze()
}

/// Encode a KeepAlive frame with the unbound session id 0.
pub(crate) fn encode_keepalive_frame() -> Bytes {
    let mut out = BytesMut::with_capacity(6);
    out.put_u16(4);
    out.put_u16(KEEPALIVE_SESSION_ID);
    out.put_u8(STATUS_KEEPALIVE);
    out.put_u8(0);
    out.freeze()
}

/// Decoded meta block of a frame.
#[derive(Debug)]
pub(crate) struct FrameMeta {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    /// Per-frame destination (New frames and UDP Keep frames).
    pub dest: Option<(Vec<u8>, u16)>,
}

/// Parse a meta block (the bytes between meta_len and the payload).
///
/// Mirrors xray FrameMetadata::UnmarshalFromBuffer: the destination is read
/// for New frames and for Keep frames whose extra byte announces UDP; other
/// trailing meta bytes are ignored.
pub(crate) fn decode_meta(meta: &[u8]) -> io::Result<FrameMeta> {
    if meta.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mux.cool: meta shorter than 4 bytes",
        ));
    }
    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    let rest = &meta[4..];
    let has_dest = status == STATUS_NEW
        || (status == STATUS_KEEP && !rest.is_empty() && rest[0] == NETWORK_UDP);
    let dest = if has_dest {
        // New frames MUST carry a destination (xray: insufficient buffer) —
        // guard before indexing rest[0] so a malformed frame errors instead
        // of panicking the reader task.
        if rest.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mux.cool: New frame without destination",
            ));
        }
        let network = rest[0];
        if network != NETWORK_TCP && network != NETWORK_UDP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("mux.cool: unknown network type {network}"),
            ));
        }
        Some(parse_address(&rest[1..])?)
    } else {
        None
    };
    Ok(FrameMeta {
        session_id,
        status,
        option,
        dest,
    })
}

/// Parse [port u16 BE][atype][address] into raw host bytes + port.
fn parse_address(b: &[u8]) -> io::Result<(Vec<u8>, u16)> {
    if b.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "mux.cool: truncated address",
        ));
    }
    let port = u16::from_be_bytes([b[0], b[1]]);
    let host = match b[2] {
        ATYPE_IPV4 => {
            if b.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux.cool: truncated IPv4 address",
                ));
            }
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(b[3], b[4], b[5], b[6]));
            ip.to_string().into_bytes()
        }
        ATYPE_IPV6 => {
            if b.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux.cool: truncated IPv6 address",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[3..19]);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
                .to_string()
                .into_bytes()
        }
        ATYPE_DOMAIN => {
            // Guard b[3] before reading it: a 3-byte block (port + atype
            // only) must error, not panic the reader task.
            if b.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux.cool: truncated domain address",
                ));
            }
            let len = b[3] as usize;
            if b.len() < 4 + len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux.cool: truncated domain address",
                ));
            }
            b[4..4 + len].to_vec()
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("mux.cool: unknown address type {other}"),
            ));
        }
    };
    Ok((host, port))
}

// --- Events on a stream's inbound channel -----------------------------------

pub(crate) enum Event {
    Data {
        bytes: Bytes,
        dest: Option<(Vec<u8>, u16)>,
    },
    /// Server sent End for this stream: deliver a clean EOF.
    Eof,
    Error(io::Error),
}

// --- Session ----------------------------------------------------------------

/// Outbound frame queue depth per session (frames, not bytes); a slow
/// server applies backpressure to stream writes via the bounded channel.
const OUTBOUND_QUEUE: usize = 64;

/// One Mux.Cool session multiplexing streams over one VLESS connection.
///
/// A single driver task owns the connection and polls BOTH directions —
/// the same single-task discipline h2mux uses.  Splitting a layered
/// conn (VlessConn / Vision / TLS) into concurrent read and write pollers
/// corrupted the stream state under parallel streams, so outbound frames
/// are handed to the driver over a bounded channel (backpressure via
/// PollSender) and inbound frames are demuxed by the driver itself.
///
/// Dropping the last external Arc (pool eviction of a zero-stream session)
/// tears the session down: Drop fires the Notify, the driver exits.
pub(crate) struct MuxCoolSession {
    driver_tx: mpsc::Sender<Bytes>,
    streams: Arc<Mutex<HashMap<u16, mpsc::Sender<Event>>>>,
    next_sid: AtomicU32,
    closed: Arc<AtomicBool>,
    done: Arc<Notify>,
}

impl MuxCoolSession {
    /// Start a session over conn - a VLESS connection whose request carried
    /// CommandMux.  The VLESS response header is consumed lazily by the
    /// driver's first read (VlessConn semantics).
    pub(crate) async fn client(conn: Box<dyn ProxyConn>) -> io::Result<Arc<Self>> {
        let (driver_tx, out_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let done = Arc::new(Notify::new());
        let session = Arc::new(Self {
            driver_tx,
            streams: Arc::clone(&streams),
            next_sid: AtomicU32::new(1),
            closed: Arc::clone(&closed),
            done: Arc::clone(&done),
        });
        tokio::spawn(driver_loop(
            conn,
            out_rx,
            Arc::clone(&streams),
            Arc::clone(&closed),
            Arc::clone(&done),
        ));
        tokio::spawn(keepalive_loop(
            Arc::downgrade(&session),
            Arc::clone(&closed),
        ));
        Ok(session)
    }

    /// True once the session is unusable (driver died).
    pub(crate) fn aborted(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Queue one outbound frame to the driver task (async contexts).
    async fn send_frame(&self, frame: Bytes) -> io::Result<()> {
        if self.aborted() {
            return Err(io::Error::other("mux.cool session closed"));
        }
        self.driver_tx
            .send(frame)
            .await
            .map_err(|_| io::Error::other("mux.cool session closed"))
    }

    /// Open one stream and write its New frame carrying host:port.
    /// Returns the raw parts; callers wrap them (Stream for TCP, PacketConn
    /// for UDP).
    async fn open_stream_parts(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> io::Result<StreamParts> {
        if self.aborted() {
            return Err(io::Error::other("mux.cool session closed"));
        }
        let sid = self.alloc_sid()?;
        let frame = encode_new_frame(sid, udp, host, port)?;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        self.streams.lock().await.insert(sid, tx);
        if let Err(e) = self.send_frame(frame).await {
            self.streams.lock().await.remove(&sid);
            return Err(e);
        }
        Ok(StreamParts {
            sid,
            session: Arc::clone(self),
            rx,
            guard: EndGuard::new(sid, Arc::clone(self)),
        })
    }

    /// Open a TCP stream (see open_stream_parts).
    pub(crate) async fn open_stream(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> io::Result<Stream> {
        let parts = self.open_stream_parts(host, port, udp).await?;
        Ok(Stream::from_parts(parts))
    }

    /// Client-assigned ids start at 1 and increase by 1
    /// (xray common/mux/session.go::Allocate); 0 marks an exhausted space.
    fn alloc_sid(&self) -> io::Result<u16> {
        let sid = self.next_sid.fetch_add(1, Ordering::SeqCst) as u16;
        if sid == 0 {
            return Err(io::Error::other("mux.cool session id space exhausted"));
        }
        Ok(sid)
    }
}

impl Drop for MuxCoolSession {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.done.notify_waiters();
    }
}

/// Owns one stream's shared parts.  Dropping the EndGuard inside sends the
/// stream's End frame (best effort) unless shutdown already claimed it.
pub(crate) struct StreamParts {
    pub(crate) sid: u16,
    pub(crate) session: Arc<MuxCoolSession>,
    pub(crate) rx: mpsc::Receiver<Event>,
    pub(crate) guard: EndGuard,
}

/// Sends the stream's End frame exactly once: either when shutdown claims
/// it, or when the last holder (Stream / PacketConn) drops.
pub(crate) struct EndGuard {
    sid: u16,
    session: Arc<MuxCoolSession>,
    ended: Arc<AtomicBool>,
}

impl EndGuard {
    fn new(sid: u16, session: Arc<MuxCoolSession>) -> Self {
        Self {
            sid,
            session,
            ended: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        if !self.ended.swap(true, Ordering::SeqCst) && !self.session.aborted() {
            let session = Arc::clone(&self.session);
            let sid = self.sid;
            // Detached: the End frame queues behind any in-flight data
            // frames in the driver's channel; drop cannot await the send.
            tokio::spawn(async move {
                let _ = session.send_frame(encode_end_frame(sid, false)).await;
            });
        }
    }
}

// --- Driver task -------------------------------------------------------------

/// Frame read phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    MetaLen,
    Meta,
    DataLen,
    Data,
}

/// Frame read state machine.  It lives in the driver task (not inside a
/// recreated future), so a select! cancellation — an outbound frame
/// arriving mid-read — loses nothing: partial bytes persist in the buffer
/// and the read resumes exactly where it left off.
struct ReadState {
    phase: ReadPhase,
    buf: BytesMut,
    pos: usize,
    sid: u16,
    option: u8,
    dest: Option<(Vec<u8>, u16)>,
}

impl ReadState {
    fn fresh() -> Self {
        Self {
            phase: ReadPhase::MetaLen,
            buf: BytesMut::zeroed(2),
            pos: 0,
            sid: 0,
            option: 0,
            dest: None,
        }
    }

    /// Start reading a fresh frame header.
    fn reset_header(&mut self) {
        self.phase = ReadPhase::MetaLen;
        self.buf = BytesMut::zeroed(2);
        self.pos = 0;
    }
}

/// Read until the current phase holds the requested byte count.
async fn read_into(
    conn: &mut Box<dyn ProxyConn>,
    state: &mut ReadState,
    need: usize,
) -> io::Result<()> {
    while state.pos < need {
        let n = conn.read(&mut state.buf[state.pos..need]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mux.cool session closed",
            ));
        }
        state.pos += n;
    }
    Ok(())
}

/// Advance the read state machine by one phase: the phase changes only on
/// completion, so cancellation mid-phase is safe.
async fn read_step(
    conn: &mut Box<dyn ProxyConn>,
    state: &mut ReadState,
    streams: &Arc<Mutex<HashMap<u16, mpsc::Sender<Event>>>>,
) -> io::Result<()> {
    match state.phase {
        ReadPhase::MetaLen => {
            read_into(conn, state, 2).await?;
            let meta_len = u16::from_be_bytes([state.buf[0], state.buf[1]]);
            if meta_len as usize > MAX_META {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mux.cool: meta length {meta_len} exceeds {MAX_META}"),
                ));
            }
            state.buf = BytesMut::zeroed(meta_len as usize);
            state.pos = 0;
            state.phase = ReadPhase::Meta;
            Ok(())
        }
        ReadPhase::Meta => {
            let need = state.buf.len();
            read_into(conn, state, need).await?;
            let frame = decode_meta(&state.buf)?;
            state.sid = frame.session_id;
            state.option = frame.option;
            state.dest = frame.dest;
            match frame.status {
                STATUS_NEW => {
                    // The server never opens streams on a client session.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "mux.cool: server-initiated stream",
                    ));
                }
                STATUS_KEEPALIVE => state.reset_header(),
                STATUS_END => {
                    let event = if state.option & OPTION_ERROR != 0 {
                        Event::Error(io::Error::other(
                            "mux.cool: remote stream closed with error",
                        ))
                    } else {
                        Event::Eof
                    };
                    let tx = {
                        let map = streams.lock().await;
                        map.get(&state.sid).cloned()
                    };
                    if let Some(tx) = tx {
                        // Ordered behind any queued data; fails fast once
                        // the consumer is gone.
                        let _ = tx.send(event).await;
                        streams.lock().await.remove(&state.sid);
                    }
                    state.reset_header();
                }
                STATUS_KEEP if state.option & OPTION_DATA != 0 => {
                    state.buf = BytesMut::zeroed(2);
                    state.pos = 0;
                    state.phase = ReadPhase::DataLen;
                }
                STATUS_KEEP => {
                    if state.option & OPTION_ERROR != 0 {
                        let tx = {
                            let map = streams.lock().await;
                            map.get(&state.sid).cloned()
                        };
                        if let Some(tx) = tx {
                            let _ = tx
                                .send(Event::Error(io::Error::other(
                                    "mux.cool: remote stream error",
                                )))
                                .await;
                        }
                    }
                    state.reset_header();
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("mux.cool: unknown frame status {other}"),
                    ));
                }
            }
            Ok(())
        }
        ReadPhase::DataLen => {
            read_into(conn, state, 2).await?;
            let data_len = u16::from_be_bytes([state.buf[0], state.buf[1]]) as usize;
            state.buf = BytesMut::zeroed(data_len);
            state.pos = 0;
            state.phase = ReadPhase::Data;
            Ok(())
        }
        ReadPhase::Data => {
            let need = state.buf.len();
            read_into(conn, state, need).await?;
            // Read the payload before delivering an error: an Error|Data
            // frame still carries data_len + payload, and skipping it would
            // desync the frame stream.
            let tx = {
                let map = streams.lock().await;
                map.get(&state.sid).cloned()
            };
            if state.option & OPTION_ERROR != 0 {
                if let Some(tx) = tx {
                    let _ = tx
                        .send(Event::Error(io::Error::other(
                            "mux.cool: remote stream error",
                        )))
                        .await;
                }
            } else if let Some(tx) = tx {
                let bytes = std::mem::take(&mut state.buf).freeze();
                let _ = tx
                    .send(Event::Data {
                        bytes,
                        dest: state.dest.clone(),
                    })
                    .await;
            }
            state.reset_header();
            Ok(())
        }
    }
}

#[cfg(test)]
async fn read_u16(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<u16> {
    let mut b = [0u8; 2];
    reader.read_exact(&mut b).await?;
    Ok(u16::from_be_bytes(b))
}

/// Owns the connection and polls BOTH directions from this single task —
/// the same discipline h2mux's h2 driver uses.  Concurrent read/write
/// polling of a layered conn (VlessConn / Vision / TLS) corrupted the
/// stream state under parallel streams, so writes arrive via the outbound
/// channel instead.
async fn driver_loop(
    mut conn: Box<dyn ProxyConn>,
    mut out_rx: mpsc::Receiver<Bytes>,
    streams: Arc<Mutex<HashMap<u16, mpsc::Sender<Event>>>>,
    closed: Arc<AtomicBool>,
    done: Arc<Notify>,
) {
    let mut state = ReadState::fresh();

    let result: io::Result<()> = async {
        loop {
            tokio::select! {
                _ = done.notified() => {
                    return Err(io::Error::other("mux.cool session closed"));
                }
                frame = out_rx.recv() => {
                    let Some(frame) = frame else {
                        return Err(io::Error::other("mux.cool outbound channel closed"));
                    };
                    conn.write_all(&frame).await?;
                    conn.flush().await?;
                }
                step = read_step(&mut conn, &mut state, &streams) => {
                    step?;
                }
            }
        }
    }
    .await;

    // Mark the abort before delivery: consumers observing a closed channel
    // must see aborted() == true so they surface an error, not a clean EOF.
    closed.store(true, Ordering::SeqCst);
    if let Err(e) = &result {
        // Push the failure to every live stream, then clear the map —
        // dropping every sender closes the channels, so consumers parked on
        // a full queue observe the abort instead of hanging forever (the
        // session itself keeps the map alive).
        let mut map = streams.lock().await;
        for (_, tx) in map.iter() {
            let _ = tx.try_send(Event::Error(io::Error::new(
                e.kind(),
                format!("mux.cool session aborted: {e}"),
            )));
        }
        map.clear();
    }
}

async fn keepalive_loop(session: Weak<MuxCoolSession>, closed: Arc<AtomicBool>) {
    loop {
        tokio::time::sleep(KEEPALIVE_INTERVAL).await;
        let Some(session) = session.upgrade() else {
            return;
        };
        if closed.load(Ordering::SeqCst) {
            return;
        }
        // The driver detects physical write failures; a send error here
        // just means the session is already going away.
        if session.send_frame(encode_keepalive_frame()).await.is_err() {
            return;
        }
    }
}

// --- TCP stream -------------------------------------------------------------

/// One multiplexed TCP stream.  Writes are framed Keep frames and queued
/// to the session driver over a bounded channel — PollSender applies real
/// backpressure when the driver falls behind; reads come from the stream's
/// demux channel.
///
/// Dropping it sends the stream's End frame via the EndGuard.
pub(crate) struct Stream {
    pub(crate) parts: StreamParts,
    poll_sender: PollSender<Bytes>,
    pending: Option<(Bytes, usize)>,
    eof: bool,
    /// End frame waiting for outbound channel capacity (shutdown is poll
    /// based; the frame survives Pending instead of being rebuilt).
    shutdown_frame: Option<Bytes>,
}

impl Stream {
    pub(crate) fn from_parts(parts: StreamParts) -> Self {
        let poll_sender = PollSender::new(parts.session.driver_tx.clone());
        Self {
            parts,
            poll_sender,
            pending: None,
            eof: false,
            shutdown_frame: None,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // AsyncRead contract: a full buffer must yield Pending — returning
        // Ready(Ok(())) here would busy-loop generic consumers.
        if buf.remaining() == 0 {
            return Poll::Pending;
        }
        if this.eof {
            return Poll::Ready(Ok(()));
        }
        if let Some((bytes, pos)) = &mut this.pending {
            let remaining = &bytes[*pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            *pos += n;
            if *pos >= bytes.len() {
                this.pending = None;
            }
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.parts.rx.poll_recv(cx) {
                Poll::Ready(Some(Event::Data { bytes, .. })) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    let n = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        this.pending = Some((bytes, n));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Event::Eof)) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Event::Error(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => {
                    this.eof = true;
                    if this.parts.session.aborted() {
                        return Poll::Ready(Err(io::Error::other("mux.cool session closed")));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
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
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.parts.guard.ended.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux.cool: stream closed",
            )));
        }
        let n = buf.len().min(MAX_PAYLOAD);
        let frame = match encode_data_frame(this.parts.sid, &buf[..n], None) {
            Ok(frame) => frame,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match this.poll_sender.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Ready(Ok(())) => {
                if let Err(e) = this.poll_sender.send_item(frame) {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The driver flushes the connection after every frame, so there is
        // nothing buffered at the stream layer.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.parts.guard.ended.swap(true, Ordering::SeqCst) {
            this.shutdown_frame = Some(encode_end_frame(this.parts.sid, false));
        }
        if let Some(frame) = this.shutdown_frame.take() {
            match this.poll_sender.poll_reserve(cx) {
                Poll::Pending => {
                    this.shutdown_frame = Some(frame);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(Ok(())) => {
                    // The End frame queues behind any data frames already
                    // in the driver channel (FIFO order preserved).
                    let _ = this.poll_sender.send_item(frame);
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

// --- UDP packet stream ------------------------------------------------------

/// One UDP flow multiplexed over a Mux.Cool session.  Datagrams carry
/// per-packet destinations in the frame meta (both directions, matching
/// sing-vmess serverMuxPacketConn / xray UDP keep frames).
pub(crate) struct PacketConn {
    sid: u16,
    session: Arc<MuxCoolSession>,
    rx: Mutex<mpsc::Receiver<Event>>,
    /// Held purely for its Drop (sends the End frame); never read.
    #[allow(dead_code, reason = "EndGuard acts through Drop, not reads")]
    guard: EndGuard,
    /// Stream's declared destination - fallback source for datagrams whose
    /// frame carries no per-packet address (e.g. domain targets).
    bound: SocketAddr,
    pool_session: Arc<MuxSession>,
}

impl PacketConn {
    pub(crate) fn new(
        parts: StreamParts,
        pool_session: Arc<MuxSession>,
        bound: SocketAddr,
    ) -> Self {
        let StreamParts {
            sid,
            session,
            rx,
            guard,
        } = parts;
        Self {
            sid,
            session,
            rx: Mutex::new(rx),
            guard,
            bound,
            pool_session,
        }
    }
}

impl Drop for PacketConn {
    fn drop(&mut self) {
        self.pool_session.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Resolve a frame destination to a SocketAddr; domains (rare on the UDP
/// path) fall back to the stream's bound destination.
fn dest_to_socket(host: &[u8], port: u16, fallback: SocketAddr) -> SocketAddr {
    std::str::from_utf8(host)
        .ok()
        .and_then(|h| h.parse::<IpAddr>().ok())
        .map_or(fallback, |ip| SocketAddr::new(ip, port))
}

#[async_trait::async_trait]
impl ProxyPacketConn for PacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(Event::Data { bytes, dest }) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    if bytes.len() > buf.len() {
                        return Err(MeowError::Proxy(format!(
                            "mux.cool: UDP packet ({} bytes) exceeds read buffer ({} bytes)",
                            bytes.len(),
                            buf.len()
                        )));
                    }
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    let src = dest.map_or(self.bound, |(host, port)| {
                        dest_to_socket(&host, port, self.bound)
                    });
                    return Ok((bytes.len(), src));
                }
                Some(Event::Eof) | None => {
                    return Err(MeowError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mux.cool: UDP stream closed",
                    )));
                }
                Some(Event::Error(e)) => return Err(MeowError::Io(e)),
            }
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        if buf.len() > u16::MAX as usize {
            return Err(MeowError::Proxy(format!(
                "mux.cool: UDP packet ({} bytes) exceeds u16 framing",
                buf.len()
            )));
        }
        // The destination rides the Keep frame meta (the address encoding
        // round-trips the IP through its string form - one small copy per
        // datagram, consistent with the rest of the UDP path).
        let frame = encode_data_frame(self.sid, buf, Some((&addr.ip().to_string(), addr.port())))
            .map_err(MeowError::Io)?;
        self.session
            .send_frame(frame)
            .await
            .map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Err(MeowError::NotSupported(
            "mux.cool PacketConn has no local UDP addr (UDP-over-mux)".into(),
        ))
    }

    fn close(&self) -> Result<()> {
        // The End frame goes out when the PacketConn drops (EndGuard).
        Ok(())
    }
}

// --- Unit tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;
    use std::task::Poll as TaskPoll;
    use tokio::io::DuplexStream;

    /// Minimal AsyncRead+AsyncWrite+ProxyConn newtype over a duplex half.
    struct TestConn(DuplexStream);

    impl ProxyConn for TestConn {}

    impl AsyncRead for TestConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> TaskPoll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> TaskPoll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> TaskPoll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> TaskPoll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    /// (session id, network, destination) of an observed New frame.
    type NewFrameLog = (u16, u8, Option<(Vec<u8>, u16)>);

    /// What the mock server observed, for assertions.
    #[derive(Default)]
    struct ServerLog {
        new_frames: Vec<NewFrameLog>,
        end_frames: Vec<u16>,
        data_frames: usize,
        keepalives: usize,
    }

    /// Minimal Mux.Cool server: parses frames with the production decoder,
    /// echoes every data frame back on the same session id (UDP frames keep
    /// their destination), and records New/End frames.  prefix bytes are
    /// written first (e.g. a VLESS response header for integration tests).
    async fn run_mock_server(mut io: DuplexStream, log: Arc<StdMutex<ServerLog>>, prefix: Vec<u8>) {
        if !prefix.is_empty() {
            io.write_all(&prefix).await.unwrap();
        }
        loop {
            let Ok(meta_len) = read_u16(&mut io).await else {
                return;
            };
            let mut meta = vec![0u8; meta_len as usize];
            if io.read_exact(&mut meta).await.is_err() {
                return;
            }
            let frame = decode_meta(&meta).unwrap();
            match frame.status {
                STATUS_NEW => {
                    log.lock()
                        .unwrap()
                        .new_frames
                        .push((frame.session_id, meta[4], frame.dest));
                }
                STATUS_END => {
                    log.lock().unwrap().end_frames.push(frame.session_id);
                }
                STATUS_KEEPALIVE => {
                    log.lock().unwrap().keepalives += 1;
                }
                STATUS_KEEP => {
                    if frame.option & OPTION_DATA == 0 {
                        continue;
                    }
                    let data_len = read_u16(&mut io).await.unwrap();
                    let mut data = vec![0u8; data_len as usize];
                    io.read_exact(&mut data).await.unwrap();
                    log.lock().unwrap().data_frames += 1;
                    let dest = frame
                        .dest
                        .as_ref()
                        .map(|(h, p)| (String::from_utf8(h.clone()).unwrap(), *p));
                    let echo = encode_data_frame(
                        frame.session_id,
                        &data,
                        dest.as_ref().map(|(h, p)| (h.as_str(), *p)),
                    )
                    .unwrap();
                    if io.write_all(&echo).await.is_err() {
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    /// Run a client session + mock server over a duplex pair.
    async fn session_pair(prefix: Vec<u8>) -> (Arc<MuxCoolSession>, Arc<StdMutex<ServerLog>>) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let log = Arc::new(StdMutex::new(ServerLog::default()));
        tokio::spawn(run_mock_server(server_io, Arc::clone(&log), prefix));
        let session = MuxCoolSession::client(Box::new(TestConn(client_io)))
            .await
            .unwrap();
        (session, log)
    }

    /// Poll a predicate against the server log until it holds or the
    /// timeout expires.
    async fn wait_for(
        log: &Arc<StdMutex<ServerLog>>,
        what: &str,
        pred: impl Fn(&ServerLog) -> bool,
    ) {
        for _ in 0..100 {
            if pred(&log.lock().unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("mock server never observed: {what}");
    }

    // --- Codec byte-level assertions -----------------------------------------

    #[test]
    fn new_frame_ipv4_matches_xray_layout() {
        let frame = encode_new_frame(1, false, "10.0.2.2", 18081).unwrap();
        // meta_len = sid(2)+status(1)+option(1)+network(1)+port(2)+atype(1)+ipv4(4)
        assert_eq!(
            &frame[..],
            &[
                0x00, 0x0C, // meta_len = 12
                0x00, 0x01, // sid = 1
                0x01, // status New
                0x00, // option none
                0x01, // network TCP
                0x46, 0xA1, // port 18081
                0x01, 10, 0, 2, 2, // atype IPv4 + bytes
            ][..]
        );
    }

    #[test]
    fn new_frame_domain_layout() {
        let frame = encode_new_frame(5, false, "example.com", 80).unwrap();
        // meta_len = 4 + 1 + 2 + 1 + 1 + 11 = 20
        assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), 20);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 5);
        assert_eq!(frame[4], STATUS_NEW);
        assert_eq!(frame[6], NETWORK_TCP);
        assert_eq!(u16::from_be_bytes([frame[7], frame[8]]), 80);
        assert_eq!(frame[9], ATYPE_DOMAIN);
        assert_eq!(frame[10] as usize, "example.com".len());
        assert_eq!(&frame[11..], b"example.com");
    }

    #[test]
    fn new_frame_udp_marks_network_udp() {
        let frame = encode_new_frame(3, true, "8.8.8.8", 53).unwrap();
        assert_eq!(frame[4], STATUS_NEW);
        assert_eq!(frame[6], NETWORK_UDP);
    }

    #[test]
    fn new_frame_ipv6_layout_and_decode() {
        let frame = encode_new_frame(2, false, "2001:db8::1", 443).unwrap();
        // meta_len = 4 + network(1) + port(2) + atype(1) + ipv6(16) = 24
        assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), 24);
        assert_eq!(frame[4], STATUS_NEW);
        assert_eq!(frame[6], NETWORK_TCP);
        assert_eq!(u16::from_be_bytes([frame[7], frame[8]]), 443);
        assert_eq!(frame[9], ATYPE_IPV6);
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(&frame[10..26], &ip.octets());
        let decoded = decode_meta(&frame[2..]).unwrap();
        let (host, port) = decoded.dest.expect("New frame must carry a destination");
        assert_eq!(host, b"2001:db8::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn data_frame_tcp_meta_len_4() {
        let frame = encode_data_frame(7, b"hello", None).unwrap();
        assert_eq!(
            &frame[..],
            &[
                0x00, 0x04, // meta_len = 4
                0x00, 0x07, // sid = 7
                0x02, // status Keep
                0x01, // option Data
                0x00, 0x05, b'h', b'e', b'l', b'l', b'o', // dataLen + payload
            ][..]
        );
    }

    #[test]
    fn data_frame_udp_carries_destination() {
        let frame = encode_data_frame(9, b"hi", Some(("10.0.2.2", 18082))).unwrap();
        // meta_len = 4 + 1 + 2 + 1 + 4 = 12
        assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), 12);
        assert_eq!(frame[6], NETWORK_UDP);
        assert_eq!(u16::from_be_bytes([frame[7], frame[8]]), 18082);
        assert_eq!(frame[9], ATYPE_IPV4);
        assert_eq!(&frame[10..14], &[10, 0, 2, 2]);
        assert_eq!(u16::from_be_bytes([frame[14], frame[15]]), 2);
        assert_eq!(&frame[16..], b"hi");
    }

    #[test]
    fn end_frame_has_no_payload_length() {
        let frame = encode_end_frame(11, false);
        assert_eq!(&frame[..], &[0x00, 0x04, 0x00, 0x0B, 0x03, 0x00][..]);
    }

    #[test]
    fn keepalive_frame_uses_session_id_zero() {
        let frame = encode_keepalive_frame();
        assert_eq!(&frame[..], &[0x00, 0x04, 0x00, 0x00, 0x04, 0x00][..]);
    }

    #[test]
    fn decode_meta_round_trips() {
        for (meta, sid, status, has_dest) in [
            (
                encode_new_frame(1, false, "10.0.2.2", 18081).unwrap(),
                1u16,
                STATUS_NEW,
                true,
            ),
            (
                encode_data_frame(7, b"x", None).unwrap(),
                7u16,
                STATUS_KEEP,
                false,
            ),
            (encode_end_frame(3, false), 3u16, STATUS_END, false),
            (encode_keepalive_frame(), 0u16, STATUS_KEEPALIVE, false),
        ] {
            let decoded = decode_meta(&meta[2..]).unwrap();
            assert_eq!(decoded.session_id, sid);
            assert_eq!(decoded.status, status);
            assert_eq!(decoded.dest.is_some(), has_dest, "meta={meta:?}");
        }
    }

    #[test]
    fn decode_meta_rejects_short_meta() {
        assert!(decode_meta(&[0x00, 0x01, 0x01]).is_err());
    }

    #[test]
    fn decode_meta_rejects_new_without_destination() {
        // New frame with meta_len 4 (no network/address) — must error, not
        // panic the reader task on rest[0].
        assert!(decode_meta(&[0x00, 0x01, 0x01, 0x00]).is_err());
    }

    /// Deterministic pseudo-random garbage through the decoder: it is the
    /// untrusted-input surface, and must error — never panic — on any input.
    #[test]
    fn decode_meta_never_panics_on_garbage() {
        let mut state = 0x9E37_79B9u32;
        for len in 0..64 {
            for _ in 0..256 {
                let mut meta = Vec::with_capacity(len);
                for _ in 0..len {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    meta.push((state >> 24) as u8);
                }
                let _ = decode_meta(&meta);
            }
        }
    }

    #[test]
    fn decode_meta_rejects_truncated_domain_address() {
        // New frame whose address block stops after the atype byte
        // (port + atype, no length byte) — must error, not panic on the
        // missing b[3] in the domain arm.
        let meta = [
            0x00,
            0x01, // sid 1
            STATUS_NEW,
            0x00, // option none
            NETWORK_TCP,
            0x00,
            0x50,         // port 80
            ATYPE_DOMAIN, // ...and nothing else
        ];
        assert!(decode_meta(&meta).is_err());
    }

    #[test]
    fn decode_meta_ignores_trailing_meta_bytes() {
        // xray may append optional fullcone/GlobalID metadata after the
        // address - trailing bytes must be ignored, not misparsed.
        let frame = encode_new_frame(1, false, "10.0.2.2", 80).unwrap();
        let mut extended = BytesMut::new();
        extended.extend_from_slice(&frame);
        let meta_len = extended.len() - 2;
        extended[0..2].copy_from_slice(&((meta_len + 8) as u16).to_be_bytes());
        extended.extend_from_slice(&[0xAA; 8]);
        let decoded = decode_meta(&extended[2..]).unwrap();
        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.status, STATUS_NEW);
        assert_eq!(decoded.dest.as_ref().unwrap().1, 80);
    }

    // --- Session round trips -------------------------------------------------

    /// AsyncRead contract: polling with a full buffer must yield Pending
    /// (Ready would busy-loop generic consumers), and the pending bytes must
    /// survive for the next read.
    #[tokio::test]
    async fn poll_read_with_full_buffer_returns_pending() {
        let (session, _log) = session_pair(vec![]).await;
        let mut stream = session.open_stream("a.example", 80, false).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        // Consume one byte so the demux channel holds pending data.
        let mut one = [0u8; 1];
        let n = stream.read(&mut one).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(one[0], b'h');

        let poll = std::future::poll_fn(|cx| {
            let mut empty = [0u8; 0];
            let mut rb = ReadBuf::new(&mut empty);
            Pin::new(&mut stream).poll_read(cx, &mut rb)
        });
        let res = tokio::time::timeout(Duration::from_millis(100), poll).await;
        assert!(
            res.is_err(),
            "poll_read with a full buffer must stay Pending"
        );

        // The pending bytes survive intact.
        let mut rest = [0u8; 8];
        let n = stream.read(&mut rest).await.unwrap();
        assert_eq!(&rest[..n], b"ello");
    }

    #[tokio::test]
    async fn tcp_stream_echo_round_trip() {
        let (session, log) = session_pair(vec![]).await;
        let mut stream = session.open_stream("10.0.2.2", 18081, false).await.unwrap();
        stream.write_all(b"hello-mux").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-mux");
        stream.shutdown().await.unwrap();
        wait_for(&log, "New frame", |l| !l.new_frames.is_empty()).await;
        wait_for(&log, "End frame", |l| !l.end_frames.is_empty()).await;
        assert_eq!(
            log.lock().unwrap().new_frames[0],
            (1, NETWORK_TCP, Some((b"10.0.2.2".to_vec(), 18081)))
        );
        assert_eq!(log.lock().unwrap().end_frames[0], 1);
    }

    #[tokio::test]
    async fn two_streams_demux_by_session_id() {
        let (session, log) = session_pair(vec![]).await;
        let mut a = session.open_stream("a.example", 80, false).await.unwrap();
        let mut b = session.open_stream("b.example", 81, false).await.unwrap();
        a.write_all(b"stream-a").await.unwrap();
        b.write_all(b"stream-b").await.unwrap();
        let mut bufa = [0u8; 16];
        let mut bufb = [0u8; 16];
        let na = a.read(&mut bufa).await.unwrap();
        let nb = b.read(&mut bufb).await.unwrap();
        assert_eq!(&bufa[..na], b"stream-a");
        assert_eq!(&bufb[..nb], b"stream-b");
        assert_eq!(log.lock().unwrap().new_frames.len(), 2);
        // Distinct session ids, assigned in open order from 1.
        assert_eq!(log.lock().unwrap().new_frames[0].0, 1);
        assert_eq!(log.lock().unwrap().new_frames[1].0, 2);
    }

    #[tokio::test]
    async fn end_frame_sent_on_drop() {
        let (session, log) = session_pair(vec![]).await;
        let stream = session.open_stream("a.example", 80, false).await.unwrap();
        drop(stream);
        wait_for(&log, "End frame after drop", |l| !l.end_frames.is_empty()).await;
    }

    /// The client must emit KeepAlive frames (sid 0) while a session sits
    /// idle so NAT bindings stay alive — verified with paused virtual time.
    #[tokio::test(start_paused = true)]
    async fn client_sends_keepalive_frames_while_idle() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let log = Arc::new(StdMutex::new(ServerLog::default()));
        tokio::spawn(run_mock_server(server_io, Arc::clone(&log), vec![]));
        let session = MuxCoolSession::client(Box::new(TestConn(client_io)))
            .await
            .unwrap();
        let stream = session.open_stream("a.example", 80, false).await.unwrap();
        drop(stream); // zero-stream idle session: keepalive must still run
        for _ in 0..200 {
            if log.lock().unwrap().keepalives > 0 {
                break;
            }
            tokio::time::advance(Duration::from_millis(200)).await;
        }
        assert!(
            log.lock().unwrap().keepalives > 0,
            "expected at least one keepalive frame after {}s of idle",
            KEEPALIVE_INTERVAL.as_secs()
        );
    }

    #[tokio::test]
    async fn server_keepalive_is_ignored() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut io = server_io;
            // KeepAlive frame first, then wait for the client's New frame
            // before answering.
            io.write_all(&encode_keepalive_frame()).await.unwrap();
            let meta_len = read_u16(&mut io).await.unwrap();
            let mut meta = vec![0u8; meta_len as usize];
            io.read_exact(&mut meta).await.unwrap();
            let sid = u16::from_be_bytes([meta[0], meta[1]]);
            let echo = encode_data_frame(sid, b"still-here", None).unwrap();
            io.write_all(&echo).await.unwrap();
        });
        let session = MuxCoolSession::client(Box::new(TestConn(client_io)))
            .await
            .unwrap();
        let mut stream = session.open_stream("a.example", 80, false).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"still-here");
    }

    #[tokio::test]
    async fn large_write_is_chunked_at_8k() {
        let (session, log) = session_pair(vec![]).await;
        let mut stream = session.open_stream("a.example", 80, false).await.unwrap();
        let payload = vec![0x5A; 20 * 1024];
        stream.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        // 20 KiB at 8 KiB per frame = 3 data frames.
        assert_eq!(log.lock().unwrap().data_frames, 3);
    }

    #[tokio::test]
    async fn keep_error_frame_drains_payload_and_keeps_framing() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut io = server_io;
            // Consume the two New frames.
            let mut sids = Vec::new();
            for _ in 0..2 {
                let meta_len = read_u16(&mut io).await.unwrap();
                let mut meta = vec![0u8; meta_len as usize];
                io.read_exact(&mut meta).await.unwrap();
                sids.push(u16::from_be_bytes([meta[0], meta[1]]));
            }
            // Error|Data keep frame for stream 1: the payload must be
            // drained (framing), and the stream must see an error.
            let mut err = BytesMut::new();
            err.put_u16(4);
            err.put_u16(sids[0]);
            err.put_u8(STATUS_KEEP);
            err.put_u8(OPTION_DATA | OPTION_ERROR);
            err.put_u16(1);
            err.put_u8(0xAA);
            io.write_all(&err).await.unwrap();
            // ...followed by a normal data frame for stream 2.
            let echo = encode_data_frame(sids[1], b"ok", None).unwrap();
            io.write_all(&echo).await.unwrap();
        });
        let session = MuxCoolSession::client(Box::new(TestConn(client_io)))
            .await
            .unwrap();
        let mut s1 = session.open_stream("a.example", 80, false).await.unwrap();
        let mut s2 = session.open_stream("b.example", 81, false).await.unwrap();
        let mut buf = [0u8; 8];
        let n = s2.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"ok",
            "stream 2 framing must survive the error frame"
        );
        let result = s1.read(&mut buf).await;
        assert!(result.is_err(), "stream 1 must surface the remote error");
    }

    #[tokio::test]
    async fn oversized_meta_aborts_session_with_error() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut io = server_io;
            // Consume the New frame, then send an oversized meta length.
            let meta_len = read_u16(&mut io).await.unwrap();
            let mut meta = vec![0u8; meta_len as usize];
            io.read_exact(&mut meta).await.unwrap();
            let mut bad = BytesMut::with_capacity(2);
            bad.put_u16(MAX_META as u16 + 1);
            io.write_all(&bad).await.unwrap();
        });
        let session = MuxCoolSession::client(Box::new(TestConn(client_io)))
            .await
            .unwrap();
        let mut stream = session.open_stream("a.example", 80, false).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 8];
        let result = stream.read(&mut buf).await;
        assert!(
            result.is_err(),
            "oversized meta must abort the session with an error"
        );
    }

    #[tokio::test]
    async fn session_abort_surfaces_error_on_streams() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        // Server sends nothing and dies: the reader errors, streams must
        // surface an error (not a clean EOF) once the session aborts.
        tokio::spawn(async move {
            drop(server_io);
        });
        let session = MuxCoolSession::client(Box::new(TestConn(client_io)))
            .await
            .unwrap();
        let mut stream = session.open_stream("a.example", 80, false).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 8];
        let result = stream.read(&mut buf).await;
        assert!(
            result.is_err(),
            "aborted session must error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn udp_packet_round_trip_with_destination() {
        let (session, _log) = session_pair(vec![]).await;
        let pool_session = Arc::new(MuxSession {
            kind: super::super::client::SessionKind::MuxCool(Arc::clone(&session)),
            streams: AtomicUsize::new(1),
            last_used_ms: std::sync::atomic::AtomicU64::new(0),
        });
        let parts = session
            .open_stream_parts("127.0.0.1", 18082, true)
            .await
            .unwrap();
        let conn = PacketConn::new(parts, pool_session, "127.0.0.1:18082".parse().unwrap());
        let dst = "127.0.0.1:18082".parse().unwrap();
        conn.write_packet(b"ping-udp", &dst).await.unwrap();
        let mut buf = [0u8; 32];
        let (n, src) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping-udp");
        assert_eq!(src, dst);
    }

    // --- VLESS integration (request header + response consumption) -----------

    /// Full VLESS Mux.Cool handshake over a duplex pair: the mock server
    /// validates the CommandMux request header, answers the 2-byte VLESS
    /// response, then speaks Mux.Cool frames.  Exercises the lazy response
    /// consumption inside the session reader task.
    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn vless_mux_session_round_trip() {
        use crate::vless::VlessConn;

        const UUID: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let log = Arc::new(StdMutex::new(ServerLog::default()));
        let server_log = Arc::clone(&log);
        tokio::spawn(async move {
            let mut io = server_io;
            // VLESS request: version + uuid + addon_len + cmd = 19 bytes.
            let mut req = [0u8; 19];
            io.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x00);
            assert_eq!(&req[1..17], &UUID);
            assert_eq!(req[17], 0x00);
            assert_eq!(req[18], 0x03, "command must be CommandMux");
            // VLESS response header, then Mux.Cool frames.
            io.write_all(&[0x00, 0x00]).await.unwrap();
            loop {
                let Ok(meta_len) = read_u16(&mut io).await else {
                    return;
                };
                let mut meta = vec![0u8; meta_len as usize];
                if io.read_exact(&mut meta).await.is_err() {
                    return;
                }
                let frame = decode_meta(&meta).unwrap();
                if frame.status == STATUS_KEEP && frame.option & OPTION_DATA != 0 {
                    let data_len = read_u16(&mut io).await.unwrap();
                    let mut data = vec![0u8; data_len as usize];
                    io.read_exact(&mut data).await.unwrap();
                    server_log.lock().unwrap().data_frames += 1;
                    let echo = encode_data_frame(frame.session_id, &data, None).unwrap();
                    if io.write_all(&echo).await.is_err() {
                        return;
                    }
                }
            }
        });
        let vless = VlessConn::new_mux(Box::new(TestConn(client_io)), &UUID, None)
            .await
            .unwrap();
        let session = MuxCoolSession::client(Box::new(vless)).await.unwrap();
        let mut stream = session.open_stream("10.0.2.2", 18081, false).await.unwrap();
        stream.write_all(b"via-vless").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"via-vless");
        assert_eq!(log.lock().unwrap().data_frames, 1);
    }

    // --- Live interop probe (repeatable regression, #[ignore]) ---------------

    /// Live probe against a running sing-box VLESS inbound
    /// (127.0.0.1:4411) and the host UDP echo server
    /// (target/e2e/udp_echo.py on :18082).  Run with --ignored — requires
    /// sing-box (target/e2e/mux-interop/sb.json) and udp_echo up.  Exercises
    /// the full Mux.Cool path: VLESS CommandMux handshake -> New frame ->
    /// Keep frames -> sing-vmess HandleMuxConnection -> direct relay -> echo.
    #[tokio::test]
    #[ignore]
    #[cfg(feature = "vless")]
    async fn live_singbox_vless_muxcool_probe() {
        use crate::mux::{DialFn, MuxClient, MuxOptions, Protocol};
        use crate::vless::VlessConn;
        use crate::StreamConn;
        use meow_common::{MeowError, ProxyConn};

        // b831381d-6324-4d53-ad4f-8cda48b30811 (sb.json vless-mux-in)
        const UUID: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let dial: DialFn = Arc::new(move || {
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(("127.0.0.1", 4411))
                    .await
                    .map_err(MeowError::Io)?;
                let conn = VlessConn::new_mux(Box::new(tcp), &UUID, None).await?;
                Ok(Box::new(StreamConn(Box::new(conn))) as Box<dyn ProxyConn>)
            })
        });
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::MuxCool,
                ..MuxOptions::default()
            },
        );

        // TCP: GET the local websrv through the mux session.
        let mut conn = client.open_stream("127.0.0.1", 18081).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        conn.write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("200"),
            "websrv must answer 200 via muxcool; got {:?}",
            &buf[..n]
        );

        // UDP: datagram echo with per-packet destination.
        let packet = client.open_packet_stream("127.0.0.1", 18082).await.unwrap();
        packet
            .write_packet(b"muxcool-udp", &"127.0.0.1:18082".parse().unwrap())
            .await
            .unwrap();
        let mut pbuf = [0u8; 64];
        let (pn, src) = packet.read_packet(&mut pbuf).await.unwrap();
        assert_eq!(&pbuf[..pn], b"muxcool-udp");
        assert_eq!(
            src,
            "127.0.0.1:18082".parse::<std::net::SocketAddr>().unwrap()
        );
    }
}
