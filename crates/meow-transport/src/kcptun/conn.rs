//! `KcpStream` — a kcp-go `UDPSession`-equivalent `AsyncRead+AsyncWrite`
//! byte stream over a connected `UdpSocket`.
//!
//! Packet pipeline (outbound): `kcp.send` → KCP `output` sink → per-datagram
//! `fec.encode` → `crypt.seal` → `socket.poll_send`. Inbound runs the
//! reverse demultiplexer (`kcpInput` upstream): `crypt.open` → FEC flag
//! dispatch → `kcp.input` → `kcp.recv`.
//!
//! There is no background updater task: every poll drives `kcp.update`
//! and the `timer` is armed to `kcp.check(now)` so retransmits/ACKs still
//! fire while the stream is parked. KCP's `WaitSnd >= snd_wnd` send-window
//! bound is the only backpressure point, mirroring `UDPSession.WriteBuffers`.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::time::Sleep;

use super::crypt::Crypt;
use super::fec::{FecDecoder, FecEncoder, FEC_HEADER_SIZE_PLUS2, TYPE_DATA, TYPE_PARITY};
use super::{KcpConfig, MTU_LIMIT};

/// KCP output sink — `kcp::Kcp` owns the `Write` impl, so queued datagrams
/// travel through a channel to the poll context that owns the socket.
/// `Mutex<Receiver>` keeps `KcpStream` `Sync` (the `Stream` blanket impl
/// requires it); the lock is only held across `try_recv` drains.
struct PacketSink {
    tx: SyncSender<Vec<u8>>,
}

impl Write for PacketSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // `Kcp::flush` write_all()s MTU-bounded runs of KCP segments; each
        // call here is one wire datagram. try_send is bounded — a full
        // channel drops like upstream's non-blocking `chPostProcessing`
        // (KCP retransmits, so the drop is recoverable, not corruption).
        let _ = self.tx.try_send(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Milliseconds on a monotonic epoch — the `kcp` crate's u32 clock.
fn now_ms() -> u32 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_millis() as u32
}

/// A connected datagram endpoint: `poll_send`/`poll_recv` exchange datagrams
/// with one fixed peer, mirroring `UdpSocket`'s connected-mode surface.
///
/// `UdpSocket` itself covers the direct path; proxy-tunneled endpoints
/// (`dialer-proxy` chains, where a raw UDP socket would leak the real source
/// path) implement this over `ProxyPacketConn` inside `meow-proxy` — the
/// transport crate stays free of proxy-layer types.
pub trait SocketIo: Send + Sync {
    /// `UdpSocket::poll_send` semantics: one call = one datagram.
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;
    /// `UdpSocket::poll_recv` semantics: fills `buf` with one datagram.
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;
    /// Upstream `SetReadBuffer`/`SetWriteBuffer`/`SetDSCP`. A no-op default —
    /// tunneled endpoints have no kernel socket to tune. `dscp` is the raw
    /// TOS byte value, matching kcp-go's `SetTOS` verbatim.
    fn apply_socket_options(&self, _sock_buf: usize, _dscp: u8) {}
}

impl SocketIo for UdpSocket {
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send(self, cx, buf)
    }
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        UdpSocket::poll_recv(self, cx, buf)
    }
    fn apply_socket_options(&self, sock_buf: usize, dscp: u8) {
        let sock = socket2::SockRef::from(self);
        if sock_buf > 0 {
            let _ = sock.set_recv_buffer_size(sock_buf);
            let _ = sock.set_send_buffer_size(sock_buf);
        }
        if dscp > 0 {
            // Upstream `UDPSession.SetDSCP`: IPv4 carries the 6-bit DSCP
            // field inside the TOS byte (`dscp << 2` | ECN); IPv6 sets the
            // traffic class raw. `& 0xff` mirrors the kernel's u8 TOS store
            // for a >63 value.
            let _ = sock.set_tos(((dscp as u32) << 2) & 0xff);
            // `set_tclass_v6` is unix-only in socket2 — on Windows the
            // IPv6 DSCP is simply not applied (best-effort like the rest).
            #[cfg(unix)]
            let _ = sock.set_tclass_v6(dscp as u32);
        }
    }
}

/// Inbound packets drained per poll pass — bounds the work a burst of
/// datagrams can force inside one `poll_read`.
const RX_BUDGET: usize = 64;

/// Progress passes one poll call may take before yielding cooperatively.
/// A sustained datagram flood (or an always-due timer) could otherwise
/// keep `poll_read`/`poll_flush` looping inside a single call forever —
/// the peer controls how many datagrams arrive.
const MAX_POLL_PASSES: usize = 16;

/// A kcp-go-compatible KCP stream over UDP.
///
/// Construct with [`KcpStream::connect`]; the returned stream is the layer
/// kcptun wraps with snappy (`CompStream`) + smux — it must NOT be used
/// directly as the SS stream.
///
/// **Drive model**: unlike upstream kcp-go (which runs a dedicated update
/// goroutine per session), the KCP clock — retransmits, ACK flushes,
/// dead-link detection — advances only while the stream is being polled.
/// Every parking path registers both the socket and the maintenance-timer
/// wakers, so a stream held in a pending `poll_read`/`poll_write` keeps
/// making progress; a stream nobody polls is frozen. The kcptun plugin
/// satisfies this via the smux session reader task, which parks in
/// `poll_read` for the session's whole lifetime.
pub struct KcpStream {
    socket: Box<dyn SocketIo>,
    kcp: kcp::Kcp<PacketSink>,
    tx: Mutex<Receiver<Vec<u8>>>,
    crypt: Crypt,
    fec_enc: Option<FecEncoder>,
    fec_dec: FecDecoder,
    /// Datagrams encoded and awaiting the socket.
    outbox: VecDeque<Vec<u8>>,
    /// KCP→app byte staging between `kcp.recv` and `ReadBuf` copies.
    inbox: VecDeque<u8>,
    /// Next `kcp.update` deadline, armed from `kcp.check`.
    timer: Pin<Box<Sleep>>,
    /// `recvbuf` upstream — one datagram scratch.
    udp_buf: Vec<u8>,
    /// `kcp.recv` staging — sized by `peeksize`, grown on demand.
    recv_scratch: Vec<u8>,
    /// Upstream `is_closed` / dead-link.
    dead: bool,
    /// `ratelimit` bytes/sec token bucket (0 = unlimited).
    rate_limit: u64,
    rate_tokens: f64,
    rate_last: Instant,
    /// Waker of a task parked in `poll_read`. The socket's recv
    /// readiness and `timer` each hold a single waker slot — under
    /// `tokio::io::split` (the smux session's reader/writer tasks) the
    /// last task to poll them silently replaces the other's
    /// registration, so a stalled `poll_write`/`poll_flush` can end up
    /// with no live wakers at all. Before parking each direction stores
    /// its waker here; peer progress (an inbound datagram, a timer
    /// tick, a drained outbox) wakes it so the stolen registration is
    /// never a lost wakeup.
    read_park: Mutex<Option<Waker>>,
    /// Same for `poll_write`/`poll_flush` stalls.
    write_park: Mutex<Option<Waker>>,
}

impl KcpStream {
    /// `kcp.NewConn4` — `socket` is already `connect()`ed to the server.
    /// `conv` is a fresh random conversation id.
    pub fn connect(socket: Box<dyn SocketIo>, conv: u32, config: &KcpConfig) -> io::Result<Self> {
        // `dscp` is a TOS-byte input — clamp a hand-built config's
        // out-of-range value instead of `as u8` truncating it.
        socket.apply_socket_options(
            config.sock_buf as usize,
            config.dscp.min(u8::MAX as u32) as u8,
        );
        let crypt = Crypt::new(&config.crypt, config.key.as_bytes())?;

        // Upstream `headerSize`: crypt envelope (+ FEC header when enabled).
        let mut header_size = crypt.header_size();
        let fec_enc = FecEncoder::new(config.data_shard, config.parity_shard, header_size);
        if fec_enc.is_some() {
            header_size += FEC_HEADER_SIZE_PLUS2;
        }
        // The decoder exists even with FEC disabled — autotune latches onto
        // a FEC-enabled server's packets (upstream lazy `newFECDecoder(1,1)`).
        let fec_dec = FecDecoder::new(config.data_shard, config.parity_shard);

        let (tx, rx) = sync_channel::<Vec<u8>>(512);
        let mut kcp = kcp::Kcp::new_stream(conv, PacketSink { tx });
        // `SetStreamMode(true)` — `new_stream` already selects it.
        // `SetWriteDelay(false)` — flush on every send (we call flush
        // explicitly after `send`).
        kcp.set_nodelay(
            config.nodelay != 0,
            // Upstream `FillDefaults` clamps interval into [10, 5000]; a
            // programmatic config can still carry 0, which would make
            // `kcp.check` always-due and spin the poll loops hot.
            config.interval.clamp(10, 5000) as i32,
            config.resend,
            config.nc != 0,
        );
        // Upstream windows are u32; the kcp core caps at u16 — clamp rather
        // than silently truncating `sndwnd=100000` into a nonsense window.
        // A zero `snd_wnd` would wedge `poll_write` forever, so bound ≥1.
        kcp.set_wndsize(
            config.snd_wnd.clamp(1, u16::MAX as u32) as u16,
            config.rcv_wnd.clamp(1, u16::MAX as u32) as u16,
        );
        // The configured MTU carries crypt + FEC + AEAD-tag overhead —
        // upstream `SetMtu` is `min(mtuLimit, mtu) - headerSize - aead.Overhead()`.
        let overhead = header_size + crypt.aead_overhead();
        let mtu = (config.mtu as usize).min(MTU_LIMIT);
        if mtu <= overhead {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("kcp: mtu {mtu} leaves no room for {overhead}B overhead"),
            ));
        }
        kcp.set_mtu(mtu - overhead).map_err(io::Error::other)?;
        // `maximumResendTimes` — kcp-go's IKCP_DEADLINK default.
        kcp.set_maximum_resend_times(20);

        Ok(Self {
            socket,
            kcp,
            tx: Mutex::new(rx),
            crypt,
            fec_enc,
            fec_dec,
            outbox: VecDeque::new(),
            inbox: VecDeque::new(),
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
            udp_buf: vec![0u8; MTU_LIMIT],
            recv_scratch: Vec::new(),
            dead: false,
            rate_limit: config.rate_limit,
            rate_tokens: config.rate_limit as f64,
            rate_last: Instant::now(),
            read_park: Mutex::new(None),
            write_park: Mutex::new(None),
        })
    }

    /// Wake whichever direction parked last. Called after any state
    /// progress — inbound datagrams, a consumed timer tick, sent
    /// datagrams — so a task whose socket/timer waker was overwritten
    /// by the peer's poll still gets rescheduled. Spurious wakes cost
    /// one re-poll; a missed wake deadlocks the stream.
    fn progress(&self) {
        for slot in [&self.read_park, &self.write_park] {
            let w = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(w) = w {
                w.wake();
            }
        }
    }

    fn park(&self, slot: &Mutex<Option<Waker>>, cx: &Context<'_>) {
        *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cx.waker().clone());
    }

    /// Run the KCP clock, drain the output sink through FEC+crypt into the
    /// outbox, then flush the outbox to the socket while the rate limiter
    /// and socket readiness allow. Rearms `timer` for the next `kcp.check`.
    fn pump(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Err(e) = self.kcp.update(now_ms()) {
            return Err(io::Error::other(format!("kcp update: {e}")));
        }
        if self.kcp.is_dead_link() {
            self.dead = true;
            // A parked peer direction must observe EOF/BrokenPipe now,
            // not whenever the next datagram happens to arrive.
            self.progress();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "kcp: link dead (resend limit exceeded)",
            ));
        }

        // KCP output → FEC → crypt → outbox. The lock only wraps each
        // `try_recv` — `encode_packet` borrows `&mut self` fields.
        loop {
            let pkt = {
                let rx = self
                    .tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                rx.try_recv()
            };
            match pkt {
                Ok(pkt) => self.encode_packet(&pkt),
                Err(_) => break,
            }
        }

        // Refill the rate bucket at `rate_limit` bytes/sec.
        if self.rate_limit > 0 {
            let dt = self.rate_last.elapsed().as_secs_f64();
            self.rate_last = Instant::now();
            self.rate_tokens =
                (self.rate_tokens + dt * self.rate_limit as f64).min(self.rate_limit as f64);
        }

        while let Some(pkt) = self.outbox.front() {
            // A bucket smaller than one packet must still send — overdraw
            // and let the bucket recover negative (upstream's rate limiter
            // waits for tokens the same way, minus the deadlock).
            if self.rate_limit > 0 && self.rate_tokens <= 0.0 {
                break;
            }
            match self.socket.poll_send(cx, pkt) {
                Poll::Ready(Ok(_)) => {
                    let pkt = self.outbox.pop_front().unwrap();
                    if self.rate_limit > 0 {
                        self.rate_tokens -= pkt.len() as f64;
                    }
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => break,
            }
        }

        // Arm the KCP maintenance timer. When the rate bucket is empty
        // the timer must also cover the next token's arrival — `kcp.check`
        // knows nothing of the limiter, so a drained bucket could
        // otherwise stall the outbox a whole KCP interval.
        let mut wait = self.kcp.check(now_ms());
        if self.rate_limit > 0 && self.rate_tokens <= 0.0 && !self.outbox.is_empty() {
            let refill_ms = (-self.rate_tokens / self.rate_limit as f64 * 1000.0)
                .ceil()
                .max(1.0) as u32;
            wait = wait.min(refill_ms);
        }
        self.timer
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_millis(wait as u64));
        // `update` + the drain above may have changed state the peer
        // direction waits on (unacked count, outbox capacity): wake it.
        self.progress();
        Ok(())
    }

    /// Wrap one raw KCP datagram with the FEC seal + crypt envelope and
    /// queue it (plus any parity shards) in the outbox. The outbox is
    /// bounded like a kernel TX queue — a persistently-blocked or
    /// rate-limited socket drops the datagram and KCP retransmits rather
    /// than growing memory without bound.
    fn encode_packet(&mut self, raw: &[u8]) {
        const OUTBOX_CAP: usize = 512;
        if self.outbox.len() >= OUTBOX_CAP {
            return;
        }
        let crypt_hdr = self.crypt.header_size();
        let mut buf = Vec::with_capacity(crypt_hdr + FEC_HEADER_SIZE_PLUS2 + raw.len());
        if let Some(enc) = &mut self.fec_enc {
            buf.resize(crypt_hdr + FEC_HEADER_SIZE_PLUS2, 0);
            buf.extend_from_slice(raw);
            // Upstream passes the session's live `rx_rto` here; the kcp
            // crate keeps it private, so a fixed 500ms stands in — wire-
            // compatible either way (parity is always legal), it only
            // emits parity across quieter gaps than upstream would.
            let parity = enc.encode(&mut buf, 500);
            self.crypt.seal(&mut buf);
            self.outbox.push_back(buf);
            for mut p in parity {
                self.crypt.seal(&mut p);
                self.outbox.push_back(p);
            }
        } else {
            buf.resize(crypt_hdr, 0);
            buf.extend_from_slice(raw);
            self.crypt.seal(&mut buf);
            self.outbox.push_back(buf);
        }
    }

    /// Inbound packet processing — `kcpInput` upstream: decrypt, demux on
    /// the u16 at offset 4 (FEC types vs raw KCP), feed `kcp.input`.
    fn input_packet(&mut self, mut pkt: Vec<u8>) {
        if self.crypt.open(&mut pkt).is_err() {
            return; // tampered/garbage datagram — drop, don't kill the stream
        }
        if pkt.len() >= 6 {
            let flag = u16::from_le_bytes(pkt[4..6].try_into().unwrap());
            match flag {
                TYPE_DATA | TYPE_PARITY => {
                    if pkt.len() < FEC_HEADER_SIZE_PLUS2 {
                        return;
                    }
                    // Only data shards feed KCP directly; parity shards are
                    // recovery input only.
                    if flag == TYPE_DATA {
                        let _ = self.kcp.input(&pkt[FEC_HEADER_SIZE_PLUS2..]);
                    }
                    for r in self.fec_dec.decode(&pkt) {
                        if r.len() >= 2 {
                            let sz = u16::from_le_bytes(r[..2].try_into().unwrap()) as usize;
                            if sz >= 2 && sz <= r.len() {
                                let _ = self.kcp.input(&r[2..sz]);
                            }
                        }
                    }
                    return;
                }
                _ => {}
            }
        }
        // Raw KCP datagram (no FEC on the peer either) — straight input.
        let _ = self.kcp.input(&pkt);
    }

    /// One bounded pass: socket → `input_packet` → `kcp.recv` → `inbox`.
    /// `Poll::Pending` once the socket has no more datagrams ready.
    fn poll_inbound(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut got = false;
        for _ in 0..RX_BUDGET {
            let mut rb = ReadBuf::new(&mut self.udp_buf);
            match self.socket.poll_recv(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // A legal zero-length datagram — consumed, not
                        // "socket empty". `crypt.open` drops it below.
                        continue;
                    }
                    let pkt = self.udp_buf[..n].to_vec();
                    self.input_packet(pkt);
                    got = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        // KCP → inbox staging. `recv` refuses when the queued message is
        // bigger than the buffer, so size it from `peeksize` (upstream's
        // `PeekSize` → allocate) rather than a fixed scratch. The drain
        // stops once `inbox` holds a receive-window's worth of bytes:
        // upstream only `Recv`s from `Read`, so its buffered inbound is
        // hard-capped at `rcv_wnd × mss`. Without this, the write-stall
        // and flush paths would keep pulling data past the window —
        // ACKing a peer into sending unboundedly.
        let inbox_cap = (self.kcp.rcv_wnd() as usize * self.kcp.mss()).max(self.kcp.mss());
        while self.inbox.len() < inbox_cap {
            let Ok(want) = self.kcp.peeksize() else { break };
            // A zero-length PUSH must still be popped — `peeksize == 0`
            // would otherwise wedge every later queued message behind it.
            self.recv_scratch.resize(want, 0);
            match self.kcp.recv(&mut self.recv_scratch) {
                Ok(0) => continue,
                Err(_) => break,
                Ok(n) => self.inbox.extend(&self.recv_scratch[..n]),
            }
        }

        if got {
            // Inbound datagrams change both directions' wait conditions:
            // ACKs shrink `wait_snd` (a stalled writer), payloads fill
            // `inbox` (a parked reader).
            self.progress();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut passes = 0;
        loop {
            if passes == MAX_POLL_PASSES {
                // Progress kept coming for a whole budget — yield so the
                // executor can schedule other tasks; the self-wake
                // re-queues this poll immediately.
                self.park(&self.read_park, cx);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            passes += 1;
            if !self.inbox.is_empty() {
                let n = self.inbox.len().min(buf.remaining());
                // Copy out of the deque without a second allocation.
                let (a, b) = self.inbox.as_slices();
                let an = a.len().min(n);
                buf.put_slice(&a[..an]);
                if an < n {
                    let bn = (n - an).min(b.len());
                    buf.put_slice(&b[..bn]);
                }
                self.inbox.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if self.dead {
                return Poll::Ready(Ok(())); // EOF
            }

            match self.poll_inbound(cx)? {
                Poll::Ready(()) | Poll::Pending => {}
            }
            self.pump(cx)?;

            if !self.inbox.is_empty() {
                continue;
            }
            // Park until the KCP timer or the socket wakes us.
            match self.timer.as_mut().poll(cx) {
                Poll::Ready(()) => continue, // maintenance tick — pump again
                Poll::Pending => {}
            }
            match self.poll_inbound(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.park(&self.read_park, cx);
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.dead {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "kcp: stream closed",
            )));
        }
        // `UDPSession.WriteBuffers`: block while the unacked queue is at the
        // send window. Inbound ACKs shrink `wait_snd`, so wait on the socket
        // AND the KCP timer while full.
        let mut passes = 0;
        while self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize {
            if passes == MAX_POLL_PASSES {
                self.park(&self.write_park, cx);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            passes += 1;
            self.pump(cx)?;
            let _ = self.poll_inbound(cx)?;
            if self.kcp.wait_snd() < self.kcp.snd_wnd() as usize {
                break;
            }
            match self.timer.as_mut().poll(cx) {
                Poll::Ready(()) => continue,
                Poll::Pending => {}
            }
            match self.poll_inbound(cx)? {
                Poll::Ready(()) => continue,
                Poll::Pending => {
                    self.park(&self.write_park, cx);
                    return Poll::Pending;
                }
            }
        }
        // The kcp crate refuses `>= KCP_WND_RCV` fragments per send
        // (upstream Go checks the configured window instead) — cap each
        // send so a large `write_all` chunks instead of erroring.
        let cap = 127 * self.kcp.mss();
        let n = self
            .kcp
            .send(&buf[..buf.len().min(cap)])
            .map_err(io::Error::other)?;
        let _ = self.kcp.flush();
        self.pump(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut passes = 0;
        loop {
            if passes == MAX_POLL_PASSES {
                self.park(&self.write_park, cx);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            passes += 1;
            let _ = self.kcp.flush();
            self.pump(cx)?;
            // Flush means "everything handed to the socket", not "acked" —
            // waiting on `wait_snd` would park the stream behind remote
            // ACKs (upstream `UDPSession.Write` doesn't wait either; KCP
            // retransmit state outlives the flush).
            if self.outbox.is_empty() {
                return Poll::Ready(Ok(()));
            }
            match self.timer.as_mut().poll(cx) {
                Poll::Ready(()) => continue,
                Poll::Pending => {}
            }
            match self.poll_inbound(cx)? {
                Poll::Ready(()) => continue,
                Poll::Pending => {
                    self.park(&self.write_park, cx);
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // KCP has no close handshake — flush everything queued then die.
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.dead = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcptun::KcpConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair(cfg: &KcpConfig) -> (KcpStream, KcpStream) {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        (
            KcpStream::connect(Box::new(a), 0x11223344, cfg).unwrap(),
            KcpStream::connect(Box::new(b), 0x11223344, cfg).unwrap(),
        )
    }

    #[tokio::test]
    async fn loopback_echo_aes_fec() {
        let cfg = KcpConfig {
            key: "it's a secrect".into(),
            crypt: "aes".into(),
            data_shard: 3,
            parity_shard: 2,
            no_comp: true,
            ..Default::default()
        };
        let (mut a, mut b) = pair(&cfg).await;

        let msg = b"kcp loopback payload \x00\x01\xf0\xff over fec".repeat(40);
        let want = msg.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; want.len()];
            b.read_exact(&mut buf).await.unwrap();
            b.write_all(&buf).await.unwrap();
            b.flush().await.unwrap();
            let _ = done_tx.send(buf);
            // Keep `b` polled so its KCP clock can retransmit the echo
            // until `a` acks it — see loopback_large_stream.
            let mut drain = [0u8; 512];
            while b.read(&mut drain).await.is_ok() {}
            b
        });
        a.write_all(&msg).await.unwrap();
        a.flush().await.unwrap();
        let echoed = done_rx.await.unwrap();
        assert_eq!(echoed, msg);
        let mut got = vec![0u8; msg.len()];
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
        echo.abort();
    }

    #[tokio::test]
    async fn loopback_default_crypt_none() {
        // `crypt: none` + no FEC — exercises the plain envelope path.
        let cfg = KcpConfig {
            crypt: "none".into(),
            data_shard: 0,
            parity_shard: 0,
            ..Default::default()
        };
        let (mut a, mut b) = pair(&cfg).await;
        a.write_all(b"ping").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn loopback_large_stream() {
        // ~200KB through KCP exercises segmentation, windows, ACK churn.
        let cfg = KcpConfig {
            crypt: "salsa20".into(),
            data_shard: 6,
            parity_shard: 3,
            ..Default::default()
        };
        let (mut a, mut b) = pair(&cfg).await;
        let msg: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let want = msg.clone();
        // `b` echoes then stays parked in a read: a KcpStream only makes
        // progress while *it* is being polled — the smux session reader
        // provides that permanently in production; the test must mirror it.
        // (`echo.await` would freeze `a` — its wakers wake the main task,
        // which would re-poll the JoinHandle instead of `a`.)
        let echo = tokio::spawn(async move {
            let mut got = Vec::with_capacity(want.len());
            let mut chunk = [0u8; 8192];
            while got.len() < want.len() {
                let n = b.read(&mut chunk).await.unwrap();
                got.extend_from_slice(&chunk[..n]);
            }
            b.write_all(&got).await.unwrap();
            b.flush().await.unwrap();
            while b.read(&mut chunk).await.is_ok() {}
            b
        });
        a.write_all(&msg).await.unwrap();
        a.flush().await.unwrap();
        // Receiving the full echo implies `b` saw all 200KB — no join needed.
        let mut back = vec![0u8; msg.len()];
        a.read_exact(&mut back).await.unwrap();
        assert_eq!(back, msg);
        echo.abort();
    }
}
