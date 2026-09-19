//! shadow-tls client transport — mihomo `transport/sing-shadowtls` parity
//! (upstream delegates to `github.com/metacubex/sing-shadowtls`).
//!
//! All three protocol versions run a *real* TLS handshake over the
//! connection; the shadow-tls server relays the handshake byte-for-byte to
//! a cover server, so the TLS session genuinely terminates at the cover.
//! The post-handshake data path then continues on the raw connection —
//! the TLS session is discarded, never carries payload.
//!
//! - **v1**: TLS 1.2 cover handshake, then plaintext.  No authentication —
//!   kept only for parity; upstream `version: 1` behaves the same way.
//! - **v2**: cover handshake over a hashing read shim; the first data
//!   record is prefixed with `HMAC-SHA1(password, server-handshake-bytes)[..8]`.
//!   Data then flows inside fake `application_data` TLS records.
//! - **v3**: the client proves knowledge of `password` by embedding an
//!   HMAC in the ClientHello's `legacy_session_id` (28 random bytes +
//!   a 4-byte truncated tag — the same slot BoringSSL fills for middlebox
//!   compatibility, patched on the wire).  The server, which relays the
//!   handshake, verifies the tag and then *swizzles* every cover
//!   `application_data` record (XOR with `kdf`, embedded rolling HMAC).
//!   Seeing a correctly-tagged record proves to the client that the
//!   relay is a real shadow-tls server and not an active probe ("traffic
//!   hijacked" otherwise).  Post-handshake records carry a per-direction
//!   rolling `HMAC-SHA1(password, serverRandom, "C"/"S")` tag.
//!
//! # v3 and the BoringSSL transcript
//!
//! Upstream generates the tagged session id *inside* uTLS via a
//! `SessionIDGenerator` hook, so the uTLS handshake completes normally.
//! BoringSSL has no equivalent hook, so this implementation patches the
//! serialized ClientHello on the wire — which necessarily diverges the
//! transcript: the cover hashes the patched hello while BoringSSL hashes
//! its own.  The cover handshake therefore always ends in a `Finished`
//! verification failure here; that failure is *expected* and recovered
//! from, provided the shim has already observed a correctly-swizzled
//! cover record (authorization) and certificate verification itself did
//! not fail.
//!
//! The two cover versions differ on what "certificate verification" can
//! mean: on a TLS 1.3 cover the certificate arrives encrypted under the
//! (diverged) transcript, so BoringSSL never reaches the verify callback
//! — `fingerprint`/`skip-cert-verify` cannot gate that path and the
//! relay's swizzled record is the sole authorization signal, exactly
//! like upstream.  On a TLS 1.2 cover the certificate chain arrives in
//! the clear *before* the doomed Finished, so `verify_result`,
//! `fingerprint` pinning, and `skip-cert-verify` all fail closed for
//! real.
//!
//! To get that far, the shim also rewrites the ServerHello's
//! `session_id_echo` back to the session id BoringSSL generated —
//! BoringSSL memcmp's the echo against its own value even on the TLS 1.3
//! path (`tls13_client.cc`), and would otherwise abort with DECODE_ERROR.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::{ConnectTypedError, TlsLayer};
use crate::{Result, Stream, TransportError};

type HmacSha1 = Hmac<Sha1>;

/// Upstream `DefaultALPN` for the cover handshake.
pub const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

const RECORD_HANDSHAKE: u8 = 22;
const RECORD_APPDATA: u8 = 23;
const RECORD_ALERT: u8 = 21;

const RECORD_HDR: usize = 5;
/// Handshake message types (`record[5]` on a handshake record).
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
/// RFC 8446 §4.1.3 — a HelloRetryRequest's `server_random` is the fixed
/// magic `SHA-256("HelloRetryRequest")`, not a real random.  It must
/// neither seed the de-swizzle chain nor authorize the session; the real
/// ServerHello follows the re-patched second ClientHello.
const HRR_RANDOM_MAGIC: [u8; TLS_RANDOM_LEN] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// v3 embeds a 4-byte truncated HMAC before every payload.
const HMAC_LEN: usize = 4;
/// Record overhead on the v3 data path: TLS header + embedded HMAC.
const HMAC_HDR: usize = RECORD_HDR + HMAC_LEN;
const RECORD_VER: [u8; 2] = [3, 3];
/// v2 prefixes the first data record with an 8-byte truncated HMAC.
const V2_SUM_LEN: usize = 8;
/// RFC 8446 §5.1 record payload bound used for write chunking.
const MAX_CHUNK: usize = 16384;
const TLS_RANDOM_LEN: usize = 32;
const SESSION_ID_LEN: usize = 32;
/// Offset of `server_random` inside a ServerHello-bearing record:
/// record hdr(5) + handshake hdr(4) + legacy_version(2).
const SERVER_RANDOM_INDEX: usize = RECORD_HDR + 4 + 2;
/// Offset of the `legacy_session_id` length byte inside a
/// ClientHello-bearing record: + client_random(32).
const CH_SID_LEN_INDEX: usize = SERVER_RANDOM_INDEX + TLS_RANDOM_LEN;

fn sha1_hmac(key: &[u8]) -> HmacSha1 {
    HmacSha1::new_from_slice(key).expect("HMAC accepts any key length")
}

/// Go `hash.Hash.Sum` equivalent — finalize a clone, leaving the chain
/// state untouched for further `update`s.  Returns a stack array: the
/// tag sizes are fixed constants, so the data path stays alloc-free.
fn hmac_sum<const N: usize>(chain: &HmacSha1) -> [u8; N] {
    let sum = chain.clone().finalize().into_bytes();
    let mut out = [0u8; N];
    out.copy_from_slice(&sum[..N]);
    out
}

/// `kdf(password, serverRandom)` — `SHA-256(password || serverRandom)`.
fn kdf(password: &[u8], server_random: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password);
    h.update(server_random);
    h.finalize().into()
}

fn xor_in_place(data: &mut [u8], key: &[u8; 32]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
}

/// Incremental TLS-record assembler shared by the handshake shim and the
/// post-handshake stream wrappers — one copy keeps the framing logic
/// (header-then-payload reads, read caps at the record boundary, EOF
/// rules) from drifting between three near-identical copies.
struct RecordAssembler {
    /// Bytes accumulated so far for the record under construction.
    rec: Vec<u8>,
    /// Byte count that completes the record: `RECORD_HDR` until the
    /// 5-byte header lands, then `RECORD_HDR + declared_len`.
    want: usize,
}

impl RecordAssembler {
    fn new() -> Self {
        Self {
            rec: Vec::new(),
            want: 0,
        }
    }

    /// Read one complete record into `rec`.
    ///
    /// `inbox` bytes (shim read-ahead) are consumed before touching
    /// `inner`.  `header_gate` runs once per record as soon as the header
    /// completes — *before* the payload is read — so a caller can reject
    /// a bad record type early, exactly like upstream.
    ///
    /// Returns `Some(())` with the record buffered in `rec`, `None` on
    /// clean EOF at a record boundary (only when `boundary_eof_ok`),
    /// otherwise `UnexpectedEof`.
    fn poll_fill(
        &mut self,
        inner: &mut dyn Stream,
        cx: &mut Context<'_>,
        mut inbox: Option<&mut VecDeque<u8>>,
        boundary_eof_ok: bool,
        header_gate: &mut dyn FnMut(&[u8; RECORD_HDR]) -> io::Result<()>,
    ) -> Poll<io::Result<Option<()>>> {
        loop {
            if self.want == 0 {
                self.want = RECORD_HDR;
                self.rec.clear();
            }
            let mut tmp = [0u8; 8192];
            while self.rec.len() < self.want {
                if let Some(inbox) = inbox.as_deref_mut() {
                    if !inbox.is_empty() {
                        let take = (self.want - self.rec.len()).min(inbox.len());
                        let (a, b) = inbox.as_slices();
                        let from_a = take.min(a.len());
                        self.rec.extend_from_slice(&a[..from_a]);
                        if from_a < take {
                            self.rec.extend_from_slice(&b[..take - from_a]);
                        }
                        inbox.drain(..take);
                        continue;
                    }
                }
                // Cap the read at the record boundary — a bigger slice
                // would glue head bytes of the *next* record onto this
                // one and corrupt both parsing and the HMAC chain.
                let need = (self.want - self.rec.len()).min(8192);
                let mut rb = ReadBuf::new(&mut tmp[..need]);
                match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled();
                        if filled.is_empty() {
                            if boundary_eof_ok && self.rec.is_empty() && self.want == RECORD_HDR {
                                return Poll::Ready(Ok(None));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "shadow-tls: EOF mid-record",
                            )));
                        }
                        self.rec.extend_from_slice(filled);
                    }
                }
            }
            if self.want == RECORD_HDR {
                let mut hdr = [0u8; RECORD_HDR];
                hdr.copy_from_slice(&self.rec);
                header_gate(&hdr)?;
                let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                self.want = RECORD_HDR + len;
                if self.rec.len() < self.want {
                    continue;
                }
                // len == 0 — the header was gated above; the record is
                // already complete.
            }
            self.want = 0;
            return Poll::Ready(Ok(Some(())));
        }
    }

    /// Serve the assembled record's payload (from `*rec_serve`) into
    /// `buf`; clears `rec` once fully consumed.  Returns false when no
    /// payload remains — the caller should assemble the next record.
    fn serve(&mut self, rec_serve: &mut usize, buf: &mut ReadBuf<'_>) -> bool {
        if *rec_serve == 0 {
            return false;
        }
        if *rec_serve >= self.rec.len() {
            // A zero-payload record left the cursor armed with nothing
            // to serve — disarm it, or bytes of the *next* record would
            // be served as payload as it assembles.
            *rec_serve = 0;
            return false;
        }
        let n = (self.rec.len() - *rec_serve).min(buf.remaining());
        buf.put_slice(&self.rec[*rec_serve..*rec_serve + n]);
        *rec_serve += n;
        if *rec_serve == self.rec.len() {
            self.rec.clear();
            *rec_serve = 0;
        }
        true
    }
}

/// Drain `outbox` into `inner` — shared by the shim and both stream
/// wrappers so the write-zero/partial-write rules stay identical.
fn poll_drain_outbox(
    inner: &mut dyn Stream,
    outbox: &mut VecDeque<u8>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while !outbox.is_empty() {
        let slice = outbox.make_contiguous();
        match Pin::new(&mut *inner).poll_write(cx, slice) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadow-tls: write zero",
                )));
            }
            Poll::Ready(Ok(n)) => outbox.drain(..n),
        };
    }
    Poll::Ready(Ok(()))
}

/// Dial `inner` through the shadow-tls transport.
///
/// `tls` must be built for the *cover* host (`host` opt → SNI) with the
/// version bounds the caller resolved (`min_version`/`max_version` on
/// [`crate::tls::TlsConfig`]).  `password` is the per-user PSK (v1 ignores
/// it, matching upstream).
///
/// The returned stream is the framed data path; the cover TLS session is
/// dropped quietly (BoringSSL `SSL_free` never writes `close_notify`, so
/// no spurious alert reaches the wire).
///
/// # Errors
///
/// * `TransportError::Config` — unknown `version`, or a REALITY-backed
///   `TlsLayer` (no recoverable inner stream).
/// * `TransportError::Tls` — cover handshake failure.
/// * `TransportError::Tls` — v3 handshake completed but the peer could
///   not produce a correctly-tagged record ("traffic hijacked"), or the
///   emitted ClientHello had no 32-byte session id to patch.
pub async fn dial(
    inner: Box<dyn Stream>,
    tls: &TlsLayer,
    version: u8,
    password: &[u8],
) -> Result<Box<dyn Stream>> {
    match version {
        1 | 2 => {
            let shim = HandshakeShim::new(inner, version, password);
            let mut tls_stream = tls
                .connect_typed(shim)
                .await
                .map_err(ConnectTypedError::into_transport)?;
            let mut shim = std::mem::take(tls_stream.get_mut());
            drop(tls_stream);
            match version {
                // v1 continues on the raw conn; `pending` may hold backend
                // bytes the server spliced in before the client's
                // handshake returned — keep them ahead of the live stream.
                1 => {
                    let pending = std::mem::take(&mut shim.pending);
                    let inner = shim.into_inner()?;
                    if pending.is_empty() {
                        return Ok(inner);
                    }
                    Ok(Box::new(PrefixStream {
                        prefix: pending,
                        inner,
                    }))
                }
                _ => {
                    let parts = shim.into_v2_parts()?;
                    Ok(Box::new(FramedStream::new(
                        parts.inner,
                        Some(parts.sum),
                        parts.pending,
                    )))
                }
            }
        }
        3 => dial_v3(tls, HandshakeShim::new(inner, 3, password)).await,
        other => Err(TransportError::Config(format!(
            "shadow-tls: unknown protocol version {other} (expected 1, 2 or 3)"
        ))),
    }
}

/// v3 dial: run the cover handshake over the patching shim.
///
/// The handshake cannot complete — the wire-patched ClientHello leaves
/// the cover's transcript divergent from BoringSSL's, so it dies partway
/// through the server flight.  That failure is the expected terminal
/// state; authorization is instead proven by the shim having verified at
/// least one correctly-swizzled cover record (or, for a TLS 1.2 cover, by
/// the authenticated ClientHello alone).
///
/// Divergence notes vs upstream uTLS (which completes the cover
/// handshake): with a **TLS 1.3** cover, post-ServerHello records are
/// encrypted under transcript-derived keys, so they are not even
/// decryptable here — the cover certificate is fundamentally
/// unverifiable and `skip-cert-verify`/`fingerprint` cannot take effect;
/// the embedded record tags are the only authenticator, which is the
/// point of the protocol (the password authenticates the relay, not the
/// cover).  With a **TLS 1.2** cover the handshake is plaintext, so cert
/// verification does run before the Finished failure — keep it fail
/// closed via the aborted `Ssl`'s `verify_result`.
async fn dial_v3(tls: &TlsLayer, shim: HandshakeShim) -> Result<Box<dyn Stream>> {
    use boring::ssl::SslVerifyMode;

    let shim = match tls.connect_typed(shim).await {
        Ok(mut tls_stream) => {
            // Unreachable in practice — a patched CH always diverges the
            // transcript — but handle it like upstream's success path.
            std::mem::take(tls_stream.get_mut())
        }
        Err(ConnectTypedError::Transport(e)) => return Err(e),
        Err(ConnectTypedError::Handshake(e)) => {
            // TLS 1.2 covers only: the plaintext handshake runs cert
            // verification before it dies at Finished, so the aborted
            // session's verify result is meaningful.  TLS 1.3 covers
            // never reach it (undecryptable flight) — authorized tags
            // are the whole check there.
            let cert_ok = e.ssl().is_some_and(|ssl| {
                ssl.verify_mode() == SslVerifyMode::NONE
                    // `verify_result` reports X509_V_OK even when the
                    // check never ran (e.g. the flight died before the
                    // Certificate message) — require a seen chain so
                    // "no cert" fails closed too.
                    || (ssl.verify_result().is_ok() && ssl.peer_cert_chain().is_some())
            });
            // Prefer the shim-originated io error (e.g. "hmac mismatch",
            // "no 32-byte session id") over the TLS-side wrapper text —
            // it names the real failure.
            let msg = e
                .as_io_error()
                .map_or_else(|| e.to_string(), std::string::ToString::to_string);
            let Some(shim) = e.into_source_stream() else {
                return Err(TransportError::Tls(format!("boring TLS handshake: {msg}")));
            };
            let state = shim.v3_state();
            if !state.authorized {
                // The handshake died before the relay proved itself.
                return Err(TransportError::Tls(format!(
                    "shadow-tls: cover handshake failed before authorization: {msg}"
                )));
            }
            // TLS 1.2 cover: the cert check genuinely ran — honor it.
            // TLS 1.3 cover: verification could not run; the expected
            // transcript-mismatch failure stands on the record tags.
            if !state.is_tls13 && !cert_ok {
                return Err(TransportError::Tls(format!(
                    "shadow-tls: cover certificate verification failed: {msg}"
                )));
            }
            shim
        }
    };
    // `pending` holds de-swizzled records destined for the now-dead TLS
    // stack (e.g. a cover session ticket) — drop it, exactly like
    // upstream dropping `streamWrapper.buffer`.
    let v3 = shim.into_v3_parts()?;
    Ok(Box::new(VerifiedStream::new(v3)))
}

/// Post-handshake v2 state extracted from the shim.
struct V2Parts {
    inner: Box<dyn Stream>,
    /// 8-byte transcript tag prefixed onto the first data record.
    sum: [u8; V2_SUM_LEN],
    /// Wire bytes the shim read ahead during the handshake.
    pending: VecDeque<u8>,
}

/// Raw stream that first serves bytes buffered during the handshake shim
/// (v1/v2 leftovers), then the live inner conn.
struct PrefixStream {
    prefix: VecDeque<u8>,
    inner: Box<dyn Stream>,
}

impl AsyncRead for PrefixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            serve_pending(&mut self.prefix, buf);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// ─── Handshake shim ───────────────────────────────────────────────────────────
//
// The TLS handshake runs over this shim so version-specific byte handling
// rides underneath the TLS stack: v2 hashes every inbound byte, v3 patches
// the ClientHello session id outbound and de-swizzles cover records
// inbound.  After the handshake the shim is pulled back out of the
// `SslStream` and carries its state (pending bytes, HMAC chains) into the
// data-path stream.

struct HandshakeShim {
    inner: Option<Box<dyn Stream>>,
    mode: Mode,
    /// Bytes accepted from the TLS stack but not yet on the wire —
    /// the patched v3 ClientHello lands here once complete.
    outbox: VecDeque<u8>,
    /// Record assembly for inbound processing.
    asm: RecordAssembler,
    /// Processed inbound bytes ready to serve to the TLS stack.
    pending: VecDeque<u8>,
    /// Outbound record assembly (v3 ClientHello patching needs whole
    /// records; the TLS stack may hand us partial writes).
    wbuf: Vec<u8>,
}

enum Mode {
    V1,
    V2 { hasher: HmacSha1 },
    V3(Box<V3Handshake>),
}

/// What the (always-failed) cover handshake proved, for the `dial_v3`
/// post-mortem.
struct V3State {
    /// At least one correctly-swizzled cover record was verified — the
    /// relay holds the password.
    authorized: bool,
    /// The cover negotiated TLS 1.3, so post-ServerHello records were
    /// never decryptable and cert verification could not have run.
    is_tls13: bool,
}

struct V3Handshake {
    password: Box<[u8]>,
    server_random: Option<[u8; TLS_RANDOM_LEN]>,
    /// The session id BoringSSL generated before the shim patched it on
    /// the wire — written back into the ServerHello's `session_id_echo`
    /// so BoringSSL's own echo check (`tls13_client.cc`) accepts it.
    orig_sid: Option<[u8; SESSION_ID_LEN]>,
    /// Rolling HMAC over de-swizzled cover records (`HMAC(password,
    /// serverRandom)` seeded), carried into the post-handshake reader as
    /// `hmac_ignore` — it absorbs a cover session-ticket record that
    /// raced past the relay switch.
    read_hmac: Option<HmacSha1>,
    read_key: Option<[u8; 32]>,
    /// Negotiated cover TLS version is 1.3 (`supported_versions` ext in
    /// the ServerHello) — upstream `isTLS13`.
    is_tls13: bool,
    authorized: bool,
}

/// `Default` so `mem::take` can pull the shim (and its inner conn) back
/// out of the `SslStream` after the cover handshake — the leftover stub
/// is dropped with the `SslStream` and swallows nothing.
impl Default for HandshakeShim {
    fn default() -> Self {
        Self::new(Box::new(tokio::io::empty()), 1, &[])
    }
}

impl HandshakeShim {
    fn new(inner: Box<dyn Stream>, version: u8, password: &[u8]) -> Self {
        let mode = match version {
            2 => Mode::V2 {
                hasher: sha1_hmac(password),
            },
            3 => Mode::V3(Box::new(V3Handshake {
                password: password.into(),
                server_random: None,
                orig_sid: None,
                read_hmac: None,
                read_key: None,
                is_tls13: false,
                authorized: false,
            })),
            _ => Mode::V1,
        };
        Self {
            inner: Some(inner),
            mode,
            outbox: VecDeque::new(),
            asm: RecordAssembler::new(),
            pending: VecDeque::new(),
            wbuf: Vec::new(),
        }
    }

    /// v3 handshake outcome — whether the relay proved itself, and
    /// whether the cover negotiated TLS 1.3 (which decides whether
    /// certificate verification could even have run).
    fn v3_state(&self) -> V3State {
        match &self.mode {
            Mode::V3(v3) => V3State {
                authorized: v3.authorized,
                is_tls13: v3.is_tls13,
            },
            _ => V3State {
                authorized: false,
                is_tls13: false,
            },
        }
    }

    fn into_inner(mut self) -> Result<Box<dyn Stream>> {
        self.inner.take().ok_or_else(|| {
            TransportError::Tls("shadow-tls: inner stream lost after handshake".into())
        })
    }

    fn into_v2_parts(mut self) -> Result<V2Parts> {
        let Mode::V2 { hasher } = &mut self.mode else {
            return Err(TransportError::Tls("shadow-tls: mode confusion".into()));
        };
        let sum: [u8; V2_SUM_LEN] = hmac_sum::<V2_SUM_LEN>(hasher);
        // Raw wire bytes already pulled during the handshake (record
        // headers/payloads of early data) feed the framed reader first.
        let pending = std::mem::take(&mut self.pending);
        let inner = self.into_inner()?;
        Ok(V2Parts {
            inner,
            sum,
            pending,
        })
    }

    fn into_v3_parts(mut self) -> Result<V3Parts> {
        let mode = std::mem::replace(&mut self.mode, Mode::V1);
        let Mode::V3(mut v3) = mode else {
            return Err(TransportError::Tls("shadow-tls: mode confusion".into()));
        };
        if !v3.authorized {
            return Err(TransportError::Tls(
                "shadow-tls: handshake completed but the peer produced no \
                 authenticated record — traffic hijacked?"
                    .into(),
            ));
        }
        let server_random = v3
            .server_random
            .ok_or_else(|| TransportError::Tls("shadow-tls: missing server random".into()))?;
        let mut hmac_add = sha1_hmac(&v3.password);
        hmac_add.update(&server_random);
        hmac_add.update(b"C");
        let mut hmac_verify = sha1_hmac(&v3.password);
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        // Any still-unwritten tail of the doomed client flight (e.g.
        // a client Finished record whose socket write pended as the
        // handshake aborted) MUST be drained before the first tagged
        // record — the relay consumes that flight byte-for-byte, so
        // truncating it mid-record would misalign the data stream.
        let outbox = std::mem::take(&mut self.outbox);
        let inner = self.into_inner()?;
        Ok(V3Parts {
            inner,
            outbox,
            hmac_add,
            hmac_verify,
            hmac_ignore: v3.read_hmac.take(),
        })
    }

    /// Pull whole TLS records from `inner`, process them per version, and
    /// move the result bytes into `pending`.
    fn poll_fill_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Mid-handshake any EOF is fatal (`boundary_eof_ok = false`) —
        // the TLS stack needs the rest of this record.
        let inner = self.inner.as_mut().expect("shim polled after inner taken");
        match self
            .asm
            .poll_fill(&mut **inner, cx, None, false, &mut |_| Ok(()))
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(None)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "shadow-tls: EOF mid-record",
            ))),
            Poll::Ready(Ok(Some(()))) => {
                let record = std::mem::take(&mut self.asm.rec);
                if let Err(e) = self.process_record(record) {
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Inspect one complete inbound record and queue what the TLS stack
    /// should see.  Only v3 mutates records; v2's hasher is fed in
    /// `poll_read` before this is ever called.
    ///
    /// Mirrors upstream `streamWrapper.Read` (`v3_client.go`): the real
    /// ServerHello seeds the de-swizzle chain (a HelloRetryRequest is
    /// detected by its magic `server_random` and passed through first),
    /// every `application_data` record resets `authorized` and must carry
    /// a valid embedded tag — a mismatch is fatal ("hmac mismatch,
    /// possible data corruption").
    fn process_record(&mut self, mut record: Vec<u8>) -> io::Result<()> {
        let Mode::V3(v3) = &mut self.mode else {
            self.pending.extend(record);
            return Ok(());
        };
        match record[0] {
            RECORD_HANDSHAKE
                if v3.read_hmac.is_none()
                    && record.len() > SERVER_RANDOM_INDEX + TLS_RANDOM_LEN
                    && record[RECORD_HDR] == HANDSHAKE_SERVER_HELLO =>
            {
                // ServerHello-shaped record — evaluate the version ONCE
                // here: `rewrite_sh_session_id_echo` may splice the echo
                // field (leaving the length byte stale), which would
                // misoffset a second extension scan.
                //
                // On a TLS 1.3 cover restore session_id_echo to the sid
                // BoringSSL generated (1.3 requires a verbatim echo of
                // the compat sid).  On a 1.2 cover do NOT touch it: a
                // matching echo means "resumption accepted" to BoringSSL,
                // which fails hard (SERVER_ECHOED_INVALID_SESSION_ID)
                // since the compat sid was never a real offer — the
                // patched echo reads as a server-assigned id and the
                // full handshake proceeds.
                let is_tls13 = is_server_hello_tls13(&record);
                if is_tls13 {
                    if let Some(orig) = v3.orig_sid {
                        rewrite_sh_session_id_echo(&mut record, &orig);
                    }
                }
                let mut server_random = [0u8; TLS_RANDOM_LEN];
                server_random
                    .copy_from_slice(&record[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]);
                if server_random == HRR_RANDOM_MAGIC {
                    // HelloRetryRequest — pass through without seeding.
                    // BoringSSL answers with a second ClientHello
                    // (re-patched in poll_write) and the real ServerHello
                    // follows, entering this arm again.
                    self.pending.extend(record);
                    return Ok(());
                }
                // Capture the random and seed the de-swizzle chain.
                // Upstream re-seeds on every ServerHello-typed record;
                // here the HRR check above already passed through the
                // only other one, so `read_hmac.is_none()` makes the
                // seed one-shot — a second real SH is a broken cover and
                // BoringSSL rejects it as an unexpected message anyway.
                let mut chain = sha1_hmac(&v3.password);
                chain.update(&server_random);
                v3.read_hmac = Some(chain);
                v3.read_key = Some(kdf(&v3.password, &server_random));
                v3.server_random = Some(server_random);
                v3.is_tls13 = is_tls13;
                // Upstream `authorized = !isTLS13`: a TLS 1.2 cover emits
                // no swizzled records during the handshake, so the
                // authenticated ClientHello alone authorizes the session.
                v3.authorized = !v3.is_tls13;
                self.pending.extend(record);
            }
            RECORD_APPDATA => {
                v3.deswizzle(&mut record)?;
                self.pending.extend(record);
            }
            _ => self.pending.extend(record),
        }
        Ok(())
    }
}

impl V3Handshake {
    /// Verify + de-swizzle one cover `application_data` record in place:
    /// check the embedded tag against the rolling handshake chain, un-XOR
    /// the payload, and shrink the record back to a normal TLS record.
    /// A tag mismatch is fatal mid-handshake ("possible data
    /// corruption"); a short record or a missing chain (no ServerHello
    /// yet) passes through unmodified, matching upstream.
    fn deswizzle(&mut self, record: &mut Vec<u8>) -> io::Result<()> {
        self.authorized = false;
        if record.len() <= HMAC_HDR {
            return Ok(());
        }
        let Some(chain) = self.read_hmac.as_mut() else {
            return Ok(());
        };
        chain.update(&record[HMAC_HDR..]);
        let tag = hmac_sum::<HMAC_LEN>(chain);
        if tag.ct_eq(&record[RECORD_HDR..HMAC_HDR]).unwrap_u8() != 1 {
            return Err(io_err(
                "shadow-tls: v3 hmac mismatch, possible data corruption",
            ));
        }
        // Authenticated cover record — strip the tag and de-XOR the
        // payload back to the real TLS bytes (the record keeps type 23,
        // exactly like upstream's `buffer.Advance(hmacSize)`).
        xor_in_place(
            &mut record[HMAC_HDR..],
            self.read_key.as_ref().expect("key set with hmac"),
        );
        let payload_len = (record.len() - HMAC_HDR) as u16;
        record[3..RECORD_HDR].copy_from_slice(&payload_len.to_be_bytes());
        record.drain(RECORD_HDR..HMAC_HDR);
        self.authorized = true;
        Ok(())
    }
}

/// Write `orig` into a ServerHello record's `session_id_echo` field.
///
/// BoringSSL memcmp's the echo against the compat session id it offered —
/// strictly, on every version.  Upstream Go/uTLS tolerates a non-echo on
/// TLS 1.2 (a server-chosen resumption id is legal there), so covers that
/// answer with a different-length field — empty or a fresh resumption
/// sid — would fail here but not upstream.  Splice the 32-byte original
/// in regardless (adjusting the record and handshake lengths); the echo
/// is only ever consumed by the doomed cover session, never by data.
fn rewrite_sh_session_id_echo(record: &mut Vec<u8>, orig: &[u8; SESSION_ID_LEN]) {
    let Some(&echo_len) = record.get(CH_SID_LEN_INDEX) else {
        return;
    };
    let echo_len = echo_len as usize;
    let echo_start = CH_SID_LEN_INDEX + 1;
    if record.len() < echo_start + echo_len {
        return; // truncated SH — leave it to BoringSSL's own parse error
    }
    if echo_len == SESSION_ID_LEN {
        record[echo_start..echo_start + SESSION_ID_LEN].copy_from_slice(orig);
        return;
    }
    record.splice(echo_start..echo_start + echo_len, orig.iter().copied());
    let rec_len = (record.len() - RECORD_HDR) as u16;
    record[3..RECORD_HDR].copy_from_slice(&rec_len.to_be_bytes());
    let hs_len = (record.len() - RECORD_HDR - 4) as u32;
    record[RECORD_HDR + 1..RECORD_HDR + 4].copy_from_slice(&hs_len.to_be_bytes()[1..]);
}

/// Upstream `isServerHelloSupportTLS13` — scan the ServerHello extensions
/// for `supported_versions` = 0x0304.
fn is_server_hello_tls13(record: &[u8]) -> bool {
    let Some(&sid_len) = record.get(CH_SID_LEN_INDEX) else {
        return false;
    };
    // After the session id come cipher_suite(2) + compression_method(1)
    // before the extensions length — hence `+ 3`.
    let Some(ext_len_bytes) = record
        .get(CH_SID_LEN_INDEX + 1 + sid_len as usize + 3..)
        .and_then(|b| b.get(..2))
    else {
        return false;
    };
    let ext_len = u16::from_be_bytes([ext_len_bytes[0], ext_len_bytes[1]]) as usize;
    let ext_start = CH_SID_LEN_INDEX + 1 + sid_len as usize + 3 + 2;
    let Some(mut exts) = record.get(ext_start..ext_start + ext_len) else {
        return false;
    };
    while exts.len() >= 4 {
        let ty = u16::from_be_bytes([exts[0], exts[1]]);
        let len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        exts = &exts[4..];
        if exts.len() < len {
            return false;
        }
        // supported_versions
        if ty == 0x002b {
            return len == 2 && exts[..2] == [0x03, 0x04];
        }
        exts = &exts[len..];
    }
    false
}

/// Rewrite `legacy_session_id` in a ClientHello record:
/// `[28 rand][HMAC4]` where the tag authenticates the whole CH.
/// Returns the session id BoringSSL originally generated — the shim
/// writes it back into the ServerHello's `session_id_echo` so the local
/// TLS stack accepts its own peer.
///
/// Server-side formula (`verifyClientHello`):
/// `HMAC-SHA1(password, hello[..39] || sid[..28] || 0x00000000 || hello[71..])`
/// — the 4-byte tag slot is zeroed inside the MAC input.
fn patch_client_hello(record: &mut [u8], password: &[u8]) -> io::Result<[u8; SESSION_ID_LEN]> {
    if record.len() <= RECORD_HDR
        || record[0] != RECORD_HANDSHAKE
        || record[RECORD_HDR] != HANDSHAKE_CLIENT_HELLO
        || record.len() < CH_SID_LEN_INDEX + 1 + SESSION_ID_LEN
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadow-tls: first client record is not a ClientHello",
        ));
    }
    if record[CH_SID_LEN_INDEX] as usize != SESSION_ID_LEN {
        // BoringSSL emits a 32-byte compat session id whenever TLS 1.3 is
        // enabled; a 0 here means max_version pinned the ClientHello to
        // TLS 1.2, which v3 cannot speak.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadow-tls: ClientHello has no 32-byte session id to patch \
             (v3 needs TLS 1.3 middlebox-compat mode)",
        ));
    }
    let sid_start = CH_SID_LEN_INDEX + 1; // record offset of the 32-byte sid
    let mut orig_sid = [0u8; SESSION_ID_LEN];
    orig_sid.copy_from_slice(&record[sid_start..sid_start + SESSION_ID_LEN]);
    let mut rand_part = [0u8; SESSION_ID_LEN - HMAC_LEN];
    boring::rand::rand_bytes(&mut rand_part)
        .map_err(|e| io::Error::other(format!("boring rand: {e}")))?;

    let mut chain = sha1_hmac(password);
    chain.update(&record[RECORD_HDR..sid_start]); // hello[..39] incl. sid_len
    chain.update(&rand_part);
    chain.update(&[0u8; HMAC_LEN]);
    chain.update(&record[sid_start + SESSION_ID_LEN..]); // hello[71..]
    let tag = hmac_sum::<HMAC_LEN>(&chain);

    record[sid_start..sid_start + rand_part.len()].copy_from_slice(&rand_part);
    record[sid_start + rand_part.len()..sid_start + SESSION_ID_LEN].copy_from_slice(&tag);
    Ok(orig_sid)
}

fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// Move up to `buf.remaining()` bytes off `pending` into the read buffer.
fn serve_pending(pending: &mut VecDeque<u8>, buf: &mut ReadBuf<'_>) {
    let n = pending.len().min(buf.remaining());
    let (a, b) = pending.as_slices();
    let from_a = n.min(a.len());
    buf.put_slice(&a[..from_a]);
    if from_a < n {
        buf.put_slice(&b[..n - from_a]);
    }
    pending.drain(..n);
}

impl AsyncRead for HandshakeShim {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Push any staged outbox before waiting on the peer — the patched
        // ClientHello must reach the server before its reply can arrive.
        if !self.outbox.is_empty() {
            match self.as_mut().poll_drain(cx) {
                Poll::Pending | Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        if self.pending.is_empty() {
            match &mut self.mode {
                Mode::V2 { .. } | Mode::V1 => {
                    // v1/v2 read raw bytes; v2 hashes them into the auth
                    // chain as they arrive.
                    let inner = self.inner.as_mut().expect("shim read after take");
                    let mut tmp = [0u8; 8192];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let filled = rb.filled();
                            if let Mode::V2 { hasher } = &mut self.mode {
                                hasher.update(filled);
                            }
                            self.pending.extend(filled.iter().copied());
                        }
                    }
                }
                Mode::V3(_) => {
                    if let Poll::Ready(Err(e)) = self.poll_fill_pending(cx) {
                        return Poll::Ready(Err(e));
                    }
                    if self.pending.is_empty() {
                        return Poll::Pending;
                    }
                }
            }
        }
        serve_pending(&mut self.pending, buf);
        Poll::Ready(Ok(()))
    }
}

impl HandshakeShim {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            self.outbox.clear();
            return Poll::Ready(Ok(()));
        };
        poll_drain_outbox(&mut **inner, &mut self.outbox, cx)
    }
}

impl AsyncWrite for HandshakeShim {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // v3: assemble complete client records and patch every ClientHello
        // (a HelloRetryRequest triggers a second CH — the relay verifies
        // its tag too).  All other records pass through verbatim, so the
        // wire shape stays a genuine TLS handshake: the cover sees the
        // CCS and the (doomed) client flight exactly as upstream emits
        // them.
        let this = &mut *self;
        let Mode::V3(v3) = &mut this.mode else {
            let Some(inner) = this.inner.as_mut() else {
                // TLS session torn down — swallow the trailing close_notify.
                return Poll::Ready(Ok(buf.len()));
            };
            return Pin::new(&mut *inner).poll_write(cx, buf);
        };
        this.wbuf.extend_from_slice(buf);
        while this.wbuf.len() >= RECORD_HDR {
            let len = u16::from_be_bytes([this.wbuf[3], this.wbuf[4]]) as usize;
            let total = RECORD_HDR + len;
            if this.wbuf.len() < total {
                break;
            }
            // ClientHello records need a mutable copy for the session-id
            // patch; every other record moves verbatim into the outbox.
            if total > RECORD_HDR
                && this.wbuf[0] == RECORD_HANDSHAKE
                && this.wbuf[RECORD_HDR] == HANDSHAKE_CLIENT_HELLO
            {
                let mut record: Vec<u8> = this.wbuf.drain(..total).collect();
                match patch_client_hello(&mut record, &v3.password) {
                    Ok(orig) => v3.orig_sid = Some(orig),
                    Err(e) => return Poll::Ready(Err(e)),
                }
                this.outbox.extend(record);
            } else {
                this.outbox.extend(this.wbuf.drain(..total));
            }
        }
        if !this.outbox.is_empty() {
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Never surface Pending to BoringSSL's BIO_ctrl(BIO_CTRL_FLUSH):
        // a WouldBlock there maps to SSL_ERROR_SYSCALL and kills the
        // handshake — the same hazard TolerantFlushStream masks on the
        // normal connect path.  poll_read re-drains the outbox before
        // waiting on the peer, so staged bytes still go out.
        if let Poll::Ready(Err(e)) = self.as_mut().poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(&mut *inner).poll_flush(cx) {
            Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

// ─── v2 framed stream ─────────────────────────────────────────────────────────
//
// Upstream `shadowConn`: every write is wrapped in a fake TLS
// `application_data` record (`0x17 0x03 0x03`); the first write is
// prefixed with the handshake-read HMAC.  Reads parse the same framing —
// record type must be 0x17 (the version bytes are deliberately not
// checked, matching upstream).

struct FramedStream {
    inner: Box<dyn Stream>,
    /// One-shot HMAC prefix for the first record (post-handshake auth).
    first_sum: Option<[u8; V2_SUM_LEN]>,
    /// Accepted-but-unwritten bytes (framed records).
    outbox: VecDeque<u8>,
    /// Raw wire bytes read ahead by the handshake shim — consumed before
    /// touching `inner` again.
    inbox: VecDeque<u8>,
    /// Inbound record assembly.
    asm: RecordAssembler,
    /// Payload bytes of the current record not yet served.
    rec_serve: usize,
}

impl FramedStream {
    fn new(
        inner: Box<dyn Stream>,
        first_sum: Option<[u8; V2_SUM_LEN]>,
        inbox: VecDeque<u8>,
    ) -> Self {
        Self {
            inner,
            first_sum,
            outbox: VecDeque::new(),
            inbox,
            asm: RecordAssembler::new(),
            rec_serve: 0,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_drain_outbox(&mut *self.inner, &mut self.outbox, cx)
    }

    /// Stage one framed record into the outbox.
    ///
    /// Note: the first v2 record carries `prefix` + `payload` unchunked
    /// (upstream `WriteVectorised` parity) — a caller-supplied buf >
    /// 65,527 bytes would truncate the u16 length field, exactly like
    /// upstream's `uint16(dataLen)`.  In-tree callers pass ≤ 16 KiB.
    fn push_record(&mut self, payload: &[u8], prefix: Option<&[u8]>) {
        let extra = prefix.map_or(0, <[u8]>::len);
        debug_assert!(
            payload.len() + extra <= u16::MAX as usize,
            "record payload {payload_len} + prefix {extra} overflows the u16 length field",
            payload_len = payload.len(),
        );
        self.outbox
            .extend([RECORD_APPDATA, RECORD_VER[0], RECORD_VER[1]]);
        self.outbox
            .extend(((payload.len() + extra) as u16).to_be_bytes());
        if let Some(p) = prefix {
            self.outbox.extend(p.iter().copied());
        }
        self.outbox.extend(payload.iter().copied());
    }
}

impl AsyncRead for FramedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Unstick a staged write tail first — a read-only caller must
        // not strand outbox bytes an earlier poll_write could not push.
        if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        // Split borrows: `asm`, `inner`, `inbox`, `rec_serve` are
        // disjoint fields — `Pin<&mut Self>` can't express that.
        let Self {
            inner,
            inbox,
            asm,
            rec_serve,
            ..
        } = self.as_mut().get_mut();
        loop {
            // Serve remaining payload of the current record first.
            // `rec_serve` stays 0 while a record is still assembling —
            // only a completed record arms it at RECORD_HDR.
            if asm.serve(rec_serve, buf) {
                return Poll::Ready(Ok(()));
            }
            // Upstream rejects non-appdata as soon as the 5-byte header
            // lands — before any payload is read (the version bytes are
            // deliberately not checked, matching upstream).
            let ready = asm.poll_fill(&mut **inner, cx, Some(&mut *inbox), true, &mut |hdr| {
                if hdr[0] == RECORD_APPDATA {
                    Ok(())
                } else {
                    Err(io_err(format!(
                        "shadow-tls: unexpected TLS record type {}",
                        hdr[0]
                    )))
                }
            });
            match ready {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // Clean close at a record boundary — surface EOF, not a
                // truncation error.
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                // Serve the payload after the 5-byte header.
                Poll::Ready(Ok(Some(()))) => *rec_serve = RECORD_HDR,
            }
        }
    }
}

impl AsyncWrite for FramedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Backpressure: drain any staged records before accepting more —
        // otherwise the outbox grows unboundedly behind a congested
        // uplink (upstream Go `Write` is synchronous per record).
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if let Some(sum) = self.first_sum.take() {
            // Upstream emits the first record as a single writev of
            // `sum || payload` — one record, unchunked.
            self.push_record(buf, Some(&sum));
        } else {
            for chunk in buf.chunks(MAX_CHUNK) {
                self.push_record(chunk, None);
            }
        }
        match self.poll_drain(cx) {
            Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// ─── v3 verified stream ───────────────────────────────────────────────────────
//
// Upstream `verifiedConn`: data records carry an embedded rolling
// `HMAC-SHA1(password, serverRandom || "C"/"S")` tag — each direction
// chains `tag = HMAC(chain || payload)` and feeds the tag back in, so a
// forged or replayed record breaks the chain and is detected.
//
// Inbound record handling:
//   alert(21)            → error ("remote alert")
//   application_data(23) → first, a cover session-ticket record may still
//                          be in flight from the swizzled handshake relay —
//                          it verifies against the *handshake* chain
//                          (`hmac_ignore`) and is skipped without chaining
//                          the data tag; on the first mismatch
//                          `hmac_ignore` retires.  Then the data tag is
//                          verified against `hmac_verify` (chained).
//   anything else        → error

struct V3Parts {
    inner: Box<dyn Stream>,
    /// Unsent tail of the aborted cover handshake's client flight —
    /// written ahead of the first tagged record to keep the wire aligned
    /// at a record boundary for the relay.
    outbox: VecDeque<u8>,
    hmac_add: HmacSha1,
    hmac_verify: HmacSha1,
    hmac_ignore: Option<HmacSha1>,
}

struct VerifiedStream {
    inner: Box<dyn Stream>,
    /// Inbound record assembly — verified payloads are served in place
    /// from `rec` at offset `rec_serve` (= `HMAC_HDR`), avoiding a second
    /// copy into a separate queue.
    asm: RecordAssembler,
    rec_serve: usize,
    outbox: VecDeque<u8>,
    hmac_add: HmacSha1,
    hmac_verify: HmacSha1,
    hmac_ignore: Option<HmacSha1>,
}

impl VerifiedStream {
    fn new(state: V3Parts) -> Self {
        Self {
            inner: state.inner,
            asm: RecordAssembler::new(),
            rec_serve: 0,
            outbox: state.outbox,
            hmac_add: state.hmac_add,
            hmac_verify: state.hmac_verify,
            hmac_ignore: state.hmac_ignore,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_drain_outbox(&mut *self.inner, &mut self.outbox, cx)
    }

    /// Queue a random-payload alert record — upstream `sendAlert` keeps a
    /// failed record indistinguishable from a real TLS alert on the wire.
    fn queue_alert(outbox: &mut VecDeque<u8>) {
        let mut record = [0u8; 31];
        record[0] = RECORD_ALERT;
        record[1] = 3;
        record[2] = 3;
        record[3..5].copy_from_slice(&(26u16).to_be_bytes());
        if boring::rand::rand_bytes(&mut record[RECORD_HDR..]).is_err() {
            return;
        }
        outbox.extend(record);
    }

    /// Stage an alert, best-effort drain it, and surface the error.
    fn reject(
        inner: &mut dyn Stream,
        outbox: &mut VecDeque<u8>,
        cx: &mut Context<'_>,
        msg: impl Into<String>,
    ) -> Poll<io::Result<()>> {
        Self::queue_alert(outbox);
        let _ = poll_drain_outbox(inner, outbox, cx);
        Poll::Ready(Err(io_err(msg)))
    }

    /// `verifyApplicationData(frame, chain, update)` — verify the embedded
    /// tag; `update` chains the tag into the running HMAC (data path) while
    /// `false` only advances the payload (handshake-leftover absorption).
    fn verify_record(record: &[u8], chain: &mut HmacSha1, update: bool) -> bool {
        if record[1] != 3 || record[2] != 3 || record.len() < HMAC_HDR {
            return false;
        }
        chain.update(&record[HMAC_HDR..]);
        let tag = hmac_sum::<HMAC_LEN>(chain);
        if update {
            chain.update(&tag);
        }
        record[RECORD_HDR..HMAC_HDR].ct_eq(&tag[..]).unwrap_u8() == 1
    }
}

impl AsyncRead for VerifiedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Unstick a staged write tail first — a read-only caller must
        // not strand outbox bytes (e.g. a queued alert) indefinitely.
        if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        // Split borrows — `Pin<&mut Self>` can't express disjoint fields.
        let Self {
            inner,
            asm,
            rec_serve,
            outbox,
            hmac_verify,
            hmac_ignore,
            ..
        } = self.as_mut().get_mut();
        loop {
            // Serve remaining verified payload of the current record.
            if asm.serve(rec_serve, buf) {
                return Poll::Ready(Ok(()));
            }
            match asm.poll_fill(&mut **inner, cx, None, true, &mut |_| Ok(())) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // Clean close at a record boundary.
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(()))) => {}
            }
            match asm.rec[0] {
                // Upstream does NOT answer an alert with an alert.
                RECORD_ALERT => return Poll::Ready(Err(io_err("shadow-tls: remote alert"))),
                RECORD_APPDATA => {
                    if let Some(ignore) = hmac_ignore.as_mut() {
                        if Self::verify_record(&asm.rec, ignore, false) {
                            continue; // cover session ticket — skip
                        }
                        *hmac_ignore = None;
                    }
                    if !Self::verify_record(&asm.rec, hmac_verify, true) {
                        return Self::reject(
                            &mut **inner,
                            outbox,
                            cx,
                            "shadow-tls: application data verification failed",
                        );
                    }
                    // Serve the payload after header + embedded tag.
                    *rec_serve = HMAC_HDR;
                }
                other => {
                    return Self::reject(
                        &mut **inner,
                        outbox,
                        cx,
                        format!("shadow-tls: unexpected TLS record type {other}"),
                    );
                }
            }
        }
    }
}

impl AsyncWrite for VerifiedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Backpressure: drain any staged records before accepting more —
        // otherwise the outbox grows unboundedly behind a congested
        // uplink (upstream Go `Write` is synchronous per record).
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        for chunk in buf.chunks(MAX_CHUNK) {
            self.hmac_add.update(chunk);
            let tag = hmac_sum::<HMAC_LEN>(&self.hmac_add);
            self.hmac_add.update(&tag);
            self.outbox
                .extend([RECORD_APPDATA, RECORD_VER[0], RECORD_VER[1]]);
            self.outbox
                .extend(((chunk.len() + HMAC_LEN) as u16).to_be_bytes());
            self.outbox.extend(tag.iter().copied());
            self.outbox.extend(chunk.iter().copied());
        }
        match self.poll_drain(cx) {
            Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PASSWORD: &[u8] = b"test-psk";

    /// Build a minimal synthetic ClientHello record: handshake(22),
    /// version 03 03, one ClientHello (type 1) with a 32-byte session id.
    fn synthetic_ch(sid: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(1u8); // client_hello
        body.extend([0u8; 3]); // length placeholder — unused by the patcher
        body.extend([3, 3]); // legacy_version
        body.extend([7u8; 32]); // client random
        body.push(32u8); // session id len
        body.extend(sid);
        body.extend([0, 1, 0xff]); // padding to emulate extensions tail
        let mut rec = Vec::new();
        rec.extend([RECORD_HANDSHAKE, 3, 3]);
        rec.extend((body.len() as u16).to_be_bytes());
        rec.extend(body);
        rec
    }

    /// Server-side tag check (upstream `verifyClientHello`):
    /// `HMAC(password, hello[..sid_end-4] || 00000000 || hello[sid_end..])`.
    fn server_tag(record: &[u8], password: &[u8]) -> [u8; 4] {
        let sid_start = CH_SID_LEN_INDEX + 1;
        let sid_end = sid_start + SESSION_ID_LEN;
        let mut chain = sha1_hmac(password);
        chain.update(&record[RECORD_HDR..sid_start + SESSION_ID_LEN - HMAC_LEN]);
        chain.update(&[0u8; HMAC_LEN]);
        chain.update(&record[sid_end..]);
        hmac_sum::<HMAC_LEN>(&chain)
    }

    #[test]
    fn patch_client_hello_rewrites_sid() {
        let mut rec = synthetic_ch(&[0u8; 32]);
        let orig = patch_client_hello(&mut rec, PASSWORD).unwrap();
        assert_eq!(orig, [0u8; 32], "returns the sid BoringSSL generated");
        let sid_start = CH_SID_LEN_INDEX + 1;
        let tag = server_tag(&rec, PASSWORD);
        assert_eq!(
            &rec[sid_start + 28..sid_start + 32],
            &tag[..],
            "last 4 sid bytes must be the server-verifiable tag"
        );
        assert_ne!(&rec[sid_start..sid_start + 28], &[0u8; 28][..]);
    }

    #[test]
    fn patch_client_hello_rejects_non_ch() {
        let mut rec = synthetic_ch(&[0u8; 32]);
        rec[RECORD_HDR] = 2; // server_hello
        assert!(patch_client_hello(&mut rec, PASSWORD).is_err());
        let mut rec = synthetic_ch(&[0u8; 32]);
        rec[0] = RECORD_APPDATA;
        assert!(patch_client_hello(&mut rec, PASSWORD).is_err());
        // No 32-byte session id (TLS 1.2-style CH).
        let mut rec = synthetic_ch(&[0u8; 32]);
        rec[CH_SID_LEN_INDEX] = 0;
        let err = patch_client_hello(&mut rec, PASSWORD).unwrap_err();
        assert!(err.to_string().contains("session id"), "{err}");
    }

    /// Read `out` fully on the duplex peer.
    async fn read_exact_duplex(peer: &mut tokio::io::DuplexStream, out: &mut [u8]) {
        peer.read_exact(out).await.expect("peer read");
    }

    // ── v2 framed stream ────────────────────────────────────────────────

    fn framed(
        inner: Box<dyn Stream>,
        first_sum: Option<[u8; V2_SUM_LEN]>,
        inbox: VecDeque<u8>,
    ) -> FramedStream {
        FramedStream::new(inner, first_sum, inbox)
    }

    #[tokio::test]
    async fn v2_write_frames_first_sum_prefix() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut s = framed(Box::new(inner), Some([0xAA; 8]), VecDeque::new());
        s.write_all(b"hello").await.unwrap();
        let mut wire = [0u8; 5 + 8 + 5];
        read_exact_duplex(&mut peer, &mut wire).await;
        assert_eq!(&wire[..3], &[23, 3, 3]);
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), 8 + 5);
        assert_eq!(&wire[5..13], &[0xAA; 8]);
        assert_eq!(&wire[13..], b"hello");
        // Second write carries no prefix.
        s.write_all(b"!!").await.unwrap();
        let mut wire2 = [0u8; 5 + 2];
        read_exact_duplex(&mut peer, &mut wire2).await;
        assert_eq!(u16::from_be_bytes([wire2[3], wire2[4]]), 2);
        assert_eq!(&wire2[5..], b"!!");
    }

    #[tokio::test]
    async fn v2_write_chunks_large_payload() {
        let (inner, mut peer) = tokio::io::duplex(1 << 20);
        let mut s = framed(Box::new(inner), Some([1; 8]), VecDeque::new());
        s.write_all(&vec![7u8; 16384 + 100]).await.unwrap();
        // First record: sum + whole payload in ONE record (upstream
        // emits `sum || p` unchunked).
        let mut hdr = [0u8; 5];
        read_exact_duplex(&mut peer, &mut hdr).await;
        assert_eq!(u16::from_be_bytes([hdr[3], hdr[4]]), 8 + 16384 + 100);
    }

    #[tokio::test]
    async fn v2_read_parses_records() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        // A record split mid-payload across two TCP writes is reassembled
        // — the stream only serves a record once it is complete.
        let mut wire = vec![23u8, 3, 3, 0, 6];
        wire.extend(b"abc");
        peer.write_all(&wire).await.unwrap();
        peer.write_all(b"def").await.unwrap();
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        // Small reads drain one record's payload incrementally.
        let mut out = [0u8; 3];
        s.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"abc");
        s.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"def");
        // A second complete record.
        peer.write_all(&[23, 3, 3, 0, 2, b'z', b'z']).await.unwrap();
        let mut out2 = [0u8; 4];
        let n = s.read(&mut out2).await.unwrap();
        assert_eq!(&out2[..n], b"zz");
    }

    #[tokio::test]
    async fn v2_read_consumes_inbox_first() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        // A record split between the read-ahead inbox and the live
        // stream — exercises the handover boundary: header+partial
        // payload buffered during the handshake, remainder on the wire.
        let inbox = VecDeque::from(vec![23u8, 3, 3, 0, 4, b'o', b'k']);
        peer.write_all(b"!!").await.unwrap();
        let mut s = framed(Box::new(inner), None, inbox);
        let mut out = [0u8; 8];
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"ok!!");
    }

    #[tokio::test]
    async fn v2_clean_eof_at_boundary() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        peer.write_all(&[23, 3, 3, 0, 2, b'b', b'y']).await.unwrap();
        drop(peer); // clean close after a complete record
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut out = [0u8; 4];
        assert_eq!(s.read(&mut out).await.unwrap(), 2);
        assert_eq!(s.read(&mut out).await.unwrap(), 0, "boundary EOF");
    }

    #[tokio::test]
    async fn v2_eof_mid_record_errors() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        peer.write_all(&[23, 3, 3, 0, 9, b'x']).await.unwrap();
        drop(peer);
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut out = [0u8; 16];
        let err = s.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn v2_wrong_record_type_errors() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        peer.write_all(&[21, 3, 3, 0, 2, 1, 0]).await.unwrap(); // alert
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut out = [0u8; 8];
        assert!(s.read(&mut out).await.is_err());
    }

    // ── v3 verified stream ──────────────────────────────────────────────

    fn mk_v3_parts(inner: Box<dyn Stream>) -> (V3Parts, [u8; 32]) {
        let server_random = [0x55u8; 32];
        let mut hmac_add = sha1_hmac(PASSWORD);
        hmac_add.update(&server_random);
        hmac_add.update(b"C");
        let mut hmac_verify = sha1_hmac(PASSWORD);
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        (
            V3Parts {
                inner,
                outbox: VecDeque::new(),
                hmac_add,
                hmac_verify,
                hmac_ignore: None,
            },
            server_random,
        )
    }

    /// Emit one verified record on the server side: tag over payload under
    /// the "S" chain, chained back into the rolling state.
    fn server_record(chain: &mut HmacSha1, payload: &[u8]) -> Vec<u8> {
        chain.update(payload);
        let tag = hmac_sum::<HMAC_LEN>(chain);
        chain.update(&tag);
        let mut rec = vec![23u8, 3, 3];
        rec.extend(((payload.len() + 4) as u16).to_be_bytes());
        rec.extend(&tag);
        rec.extend(payload);
        rec
    }

    #[tokio::test]
    async fn v3_write_and_read_roundtrip() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let (state, server_random) = mk_v3_parts(Box::new(inner));
        // Server-side mirror chains.
        let mut srv_s = sha1_hmac(PASSWORD);
        srv_s.update(&server_random);
        srv_s.update(b"S");
        let mut srv_c = sha1_hmac(PASSWORD);
        srv_c.update(&server_random);
        srv_c.update(b"C");

        let mut s = VerifiedStream::new(state);
        s.write_all(b"ping").await.unwrap();
        let mut wire = [0u8; 5 + 4 + 4];
        read_exact_duplex(&mut peer, &mut wire).await;
        assert_eq!(&wire[..3], &[23, 3, 3]);
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), 4 + 4);
        // Verify the client's tag with the server's "C" chain.
        srv_c.update(&wire[9..]);
        let tag = hmac_sum::<4>(&srv_c);
        srv_c.update(&tag);
        assert_eq!(&wire[5..9], &tag[..]);
        assert_eq!(&wire[9..], b"ping");

        // Server → client verified record.
        let rec = server_record(&mut srv_s, b"pong");
        peer.write_all(&rec).await.unwrap();
        let mut out = [0u8; 8];
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"pong");
    }

    #[tokio::test]
    async fn v3_tampered_record_errors_and_alerts() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let (state, server_random) = mk_v3_parts(Box::new(inner));
        let mut srv_s = sha1_hmac(PASSWORD);
        srv_s.update(&server_random);
        srv_s.update(b"S");
        let mut s = VerifiedStream::new(state);

        let mut rec = server_record(&mut srv_s, b"data");
        rec[10] ^= 0xff; // corrupt payload → tag mismatch
        peer.write_all(&rec).await.unwrap();
        let mut out = [0u8; 8];
        let err = s.read(&mut out).await.unwrap_err();
        assert!(err.to_string().contains("verification failed"), "{err}");
        // The client queued an alert record on the wire.
        let mut alert = [0u8; 5];
        read_exact_duplex(&mut peer, &mut alert).await;
        assert_eq!(alert[0], RECORD_ALERT);
    }

    #[tokio::test]
    async fn v3_ignore_chain_absorbs_cover_ticket() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let (mut state, server_random) = mk_v3_parts(Box::new(inner));
        // Handshake read chain (ignore path): HMAC(password) + serverRandom.
        let mut ignore = sha1_hmac(PASSWORD);
        ignore.update(&server_random);
        // A cover session-ticket record — tag computed with the handshake
        // chain over xor'd payload; xor is irrelevant here because the
        // record is skipped wholesale.
        let mut wire_chain = sha1_hmac(PASSWORD);
        wire_chain.update(&server_random);
        let ticket = server_record(&mut wire_chain, b"ticket-bytes");
        state.hmac_ignore = Some(ignore);
        let mut s = VerifiedStream::new(state);

        let mut srv_s = sha1_hmac(PASSWORD);
        srv_s.update(&server_random);
        srv_s.update(b"S");
        let data = server_record(&mut srv_s, b"real");
        peer.write_all(&ticket).await.unwrap();
        peer.write_all(&data).await.unwrap();
        let mut out = [0u8; 8];
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"real", "cover ticket must be skipped");
    }

    // ── handshake shim ──────────────────────────────────────────────────

    #[tokio::test]
    async fn shim_v2_hashes_inbound_bytes() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 2, PASSWORD);
        peer.write_all(b"handshake-bytes").await.unwrap();
        let mut buf = [0u8; 64];
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"handshake-bytes");
        let parts = shim.into_v2_parts().map_err(|e| e.to_string()).unwrap();
        let mut expect = sha1_hmac(PASSWORD);
        expect.update(b"handshake-bytes");
        assert_eq!(&parts.sum[..], &hmac_sum::<8>(&expect)[..]);
    }

    #[tokio::test]
    async fn shim_v1_pending_survives_handover() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 1, PASSWORD);
        // The TLS stack consumes fewer bytes than the shim pulled — the
        // leftover must surface through PrefixStream after dial().
        peer.write_all(b"abc").await.unwrap();
        let mut buf = [0u8; 2];
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        peer.write_all(b"def").await.unwrap();
        // Emulate the post-handshake handover.
        let pending = std::mem::take(&mut shim.pending);
        let mut s = PrefixStream {
            prefix: pending,
            inner: shim.into_inner().unwrap(),
        };
        let mut out = [0u8; 8];
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"c");
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"def");
    }

    /// Minimal-but-realistic ServerHello record: hs type 2, version,
    /// 32B random, empty sid, cipher suite, null compression, and a
    /// `supported_versions` extension when `tls13` (so
    /// `is_server_hello_tls13` sees a real 1.3 negotiation).
    fn server_hello_record(server_random: &[u8; 32], tls13: bool) -> Vec<u8> {
        let mut sh_body = vec![2u8, 0, 0, 0, 3, 3];
        sh_body.extend(server_random);
        sh_body.push(0); // session id len
        sh_body.extend([0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        sh_body.push(0); // compression
        if tls13 {
            sh_body.extend(6u16.to_be_bytes()); // ext len
            sh_body.extend([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        } else {
            sh_body.extend(0u16.to_be_bytes());
        }
        let mut sh = vec![22u8, 3, 3];
        sh.extend((sh_body.len() as u16).to_be_bytes());
        sh.extend(&sh_body);
        sh
    }

    #[tokio::test]
    async fn shim_v3_deswizzles_cover_appdata() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);
        let server_random = [9u8; 32];
        let sh = server_hello_record(&server_random, true);
        // Swizzled cover appdata record: tag(4) || xor(payload).
        let mut wire_chain = sha1_hmac(PASSWORD);
        wire_chain.update(&server_random);
        let payload = b"cover-tls-bytes".to_vec();
        let mut xored = payload.clone();
        xor_in_place(&mut xored, &kdf(PASSWORD, &server_random));
        wire_chain.update(&xored);
        let tag = hmac_sum::<4>(&wire_chain);
        let mut app = vec![23u8, 3, 3];
        app.extend(((xored.len() + 4) as u16).to_be_bytes());
        app.extend(&tag);
        app.extend(&xored);
        peer.write_all(&sh).await.unwrap();
        peer.write_all(&app).await.unwrap();

        // Drain both records through the shim.
        let mut buf = vec![0u8; 4096];
        let mut got = Vec::new();
        while got.len() < sh.len() + RECORD_HDR + payload.len() {
            let n = shim.read(&mut buf).await.unwrap();
            got.extend(&buf[..n]);
        }
        // De-swizzled appdata must restore the real TLS record.
        let tail = &got[sh.len()..];
        assert_eq!(&tail[..3], &[23, 3, 3]);
        assert_eq!(
            u16::from_be_bytes([tail[3], tail[4]]) as usize,
            payload.len()
        );
        assert_eq!(&tail[5..], &payload[..]);
        let v3 = shim.into_v3_parts().map_err(|e| e.to_string()).unwrap();
        assert!(v3.hmac_ignore.is_some());
    }

    #[test]
    fn server_hello_tls13_detection() {
        let sh13 = server_hello_record(&[1u8; 32], true);
        assert!(is_server_hello_tls13(&sh13), "supported_versions=0304");
        let sh12 = server_hello_record(&[1u8; 32], false);
        assert!(!is_server_hello_tls13(&sh12), "no supported_versions ext");
        assert!(!is_server_hello_tls13(&[22, 3, 3, 0, 0]), "empty record");
    }

    /// The wire-patched ClientHello sid must be written back into the
    /// ServerHello's `session_id_echo` — BoringSSL memcmp's it against
    /// the sid it generated, so the shim restores the original.
    #[tokio::test]
    async fn shim_v3_restores_server_hello_echo() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);

        // Drive a synthetic CH through the shim: the wire sid is patched.
        let orig_sid = [0xABu8; 32];
        shim.write_all(&synthetic_ch(&orig_sid)).await.unwrap();
        shim.flush().await.unwrap();
        let mut wire_ch = vec![0u8; 5];
        peer.read_exact(&mut wire_ch).await.unwrap();
        let rec_len = u16::from_be_bytes([wire_ch[3], wire_ch[4]]) as usize;
        wire_ch.resize(RECORD_HDR + rec_len, 0);
        peer.read_exact(&mut wire_ch[RECORD_HDR..]).await.unwrap();
        let sid_start = CH_SID_LEN_INDEX + 1;
        let wire_sid: [u8; 32] = wire_ch[sid_start..sid_start + 32].try_into().unwrap();
        assert_ne!(wire_sid, orig_sid, "wire sid must be the patched one");
        assert_eq!(
            &wire_ch[sid_start + 28..sid_start + 32],
            &server_tag(&wire_ch, PASSWORD)[..],
            "wire sid still carries a valid tag"
        );

        // ServerHello echoing the *patched* sid — what the cover saw.
        let server_random = [7u8; 32];
        let mut sh_body = vec![2u8, 0, 0, 0, 3, 3];
        sh_body.extend(server_random);
        sh_body.push(32);
        sh_body.extend(wire_sid); // echo = patched sid
        sh_body.extend([0x13, 0x01]);
        sh_body.push(0);
        sh_body.extend(6u16.to_be_bytes());
        sh_body.extend([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let mut sh = vec![22u8, 3, 3];
        sh.extend((sh_body.len() as u16).to_be_bytes());
        sh.extend(&sh_body);
        peer.write_all(&sh).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(n, sh.len());
        let seen_echo = &buf[sid_start..sid_start + 32];
        assert_eq!(
            seen_echo, &orig_sid,
            "session_id_echo must be restored to BoringSSL's own sid"
        );
    }

    /// A mistagged appdata record mid-handshake is fatal (upstream
    /// "hmac mismatch, possible data corruption") — never leak swizzled
    /// bytes into the TLS stack.
    #[tokio::test]
    async fn shim_v3_bad_tag_mid_handshake_errors() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);
        let sh = server_hello_record(&[9u8; 32], true);
        peer.write_all(&sh).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(n, sh.len());
        // Appdata with a bogus 4-byte tag.
        peer.write_all(&[23, 3, 3, 0, 9, 1, 2, 3, 4, 9, 8, 7, 6, 5])
            .await
            .unwrap();
        let err = shim.read(&mut buf).await.unwrap_err();
        assert!(err.to_string().contains("hmac mismatch"), "{err}");
    }

    #[tokio::test]
    async fn shim_v3_unauthorized_after_handshake_errs() {
        let (inner, _peer) = tokio::io::duplex(4096);
        let shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);
        let Err(err) = shim.into_v3_parts() else {
            panic!("unauthorized v3 must not hand over")
        };
        assert!(matches!(err, TransportError::Tls(_)), "{err:?}");
        assert!(err.to_string().contains("hijacked"), "{err}");
    }

    /// RFC 8446 §4.1.3 — the HRR detection constant must be the real
    /// `SHA-256("HelloRetryRequest")` value.
    #[test]
    fn hrr_random_magic_is_sha256() {
        let mut h = Sha256::new();
        h.update(b"HelloRetryRequest");
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(HRR_RANDOM_MAGIC, expect);
    }

    /// A HelloRetryRequest shares the ServerHello shape but must neither
    /// seed the de-swizzle chain nor authorize — the real ServerHello
    /// after the second (re-patched) ClientHello does.
    #[tokio::test]
    async fn shim_v3_hrr_passthrough_then_real_sh_seeds() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);

        // Drive CH1 through the shim so orig_sid is known.
        let orig_sid = [0xABu8; 32];
        shim.write_all(&synthetic_ch(&orig_sid)).await.unwrap();
        shim.flush().await.unwrap();
        let mut wire_ch = vec![0u8; 5];
        peer.read_exact(&mut wire_ch).await.unwrap();
        let rec_len = u16::from_be_bytes([wire_ch[3], wire_ch[4]]) as usize;
        wire_ch.resize(RECORD_HDR + rec_len, 0);
        peer.read_exact(&mut wire_ch[RECORD_HDR..]).await.unwrap();
        let sid_start = CH_SID_LEN_INDEX + 1;
        let wire_sid: [u8; 32] = wire_ch[sid_start..sid_start + 32].try_into().unwrap();

        // HelloRetryRequest: SH shape, magic random, echo = patched sid.
        let mut hrr_body = vec![2u8, 0, 0, 0, 3, 3];
        hrr_body.extend(HRR_RANDOM_MAGIC);
        hrr_body.push(32);
        hrr_body.extend(wire_sid);
        hrr_body.extend([0x13, 0x01]);
        hrr_body.push(0);
        hrr_body.extend(6u16.to_be_bytes());
        hrr_body.extend([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let mut hrr = vec![22u8, 3, 3];
        hrr.extend((hrr_body.len() as u16).to_be_bytes());
        hrr.extend(&hrr_body);
        peer.write_all(&hrr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(n, hrr.len(), "HRR passes through whole");
        assert_eq!(
            &buf[sid_start..sid_start + 32],
            &orig_sid,
            "HRR session_id_echo is restored too"
        );
        let state = shim.v3_state();
        assert!(
            !state.authorized && !state.is_tls13,
            "HRR neither seeds nor authorizes"
        );

        // The real ServerHello follows — here echoing the same patched
        // sid (a cover echoes whatever the second CH carried; the same
        // restore applies).
        let server_random = [7u8; 32];
        let mut sh_body = vec![2u8, 0, 0, 0, 3, 3];
        sh_body.extend(server_random);
        sh_body.push(32);
        sh_body.extend(wire_sid);
        sh_body.extend([0x13, 0x01]);
        sh_body.push(0);
        sh_body.extend(6u16.to_be_bytes());
        sh_body.extend([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let mut sh = vec![22u8, 3, 3];
        sh.extend((sh_body.len() as u16).to_be_bytes());
        sh.extend(&sh_body);
        peer.write_all(&sh).await.unwrap();

        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(n, sh.len());
        let state = shim.v3_state();
        assert!(
            !state.authorized && state.is_tls13,
            "real SH after HRR seeds: is_tls13 set, still unauthorized"
        );
    }

    /// Zero-length records must not spin the record loop — a hostile
    /// peer could otherwise pin the executor thread forever.
    #[tokio::test]
    async fn shim_v3_zero_length_record_passthrough() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);
        // Empty appdata + a real SH right behind it.
        peer.write_all(&[23, 3, 3, 0, 0]).await.unwrap();
        let sh = server_hello_record(&[9u8; 32], true);
        peer.write_all(&sh).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(n, 5, "empty appdata passes through for BoringSSL");
        let n = shim.read(&mut buf).await.unwrap();
        assert_eq!(n, sh.len());
    }

    #[tokio::test]
    async fn v2_zero_length_appdata_skipped() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        peer.write_all(&[23, 3, 3, 0, 0]).await.unwrap();
        peer.write_all(&[23, 3, 3, 0, 2, b'o', b'k']).await.unwrap();
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut out = [0u8; 4];
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"ok", "empty appdata yields no payload");
    }

    #[tokio::test]
    async fn v2_zero_length_non_appdata_errors() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        peer.write_all(&[21, 3, 3, 0, 0]).await.unwrap(); // empty alert
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut out = [0u8; 4];
        assert!(s.read(&mut out).await.is_err());
    }

    #[tokio::test]
    async fn v3_zero_length_record_rejected() {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let (state, _sr) = mk_v3_parts(Box::new(inner));
        peer.write_all(&[23, 3, 3, 0, 0]).await.unwrap();
        let mut s = VerifiedStream::new(state);
        let mut out = [0u8; 4];
        // A zero-length record cannot carry a valid tag — fatal.
        assert!(s.read(&mut out).await.is_err());
    }

    // ── backpressure / stranded-tail ────────────────────────────────────

    /// Inner stream whose writes and flushes pend until `open` flips —
    /// exercises backpressure without real socket pressure.
    struct GatedStream {
        written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        open: std::sync::Arc<std::sync::atomic::AtomicBool>,
        read: VecDeque<u8>,
    }

    impl AsyncRead for GatedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read.is_empty() {
                return Poll::Pending;
            }
            let n = self.read.len().min(buf.remaining());
            let chunk: Vec<u8> = self.read.drain(..n).collect();
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for GatedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
                return Poll::Pending;
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    type GatedHandle = (
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    );

    fn gated_stream(read: &[u8]) -> (GatedStream, GatedHandle) {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex};
        let open = Arc::new(AtomicBool::new(false));
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = GatedStream {
            written: Arc::clone(&written),
            open: Arc::clone(&open),
            read: VecDeque::from(read.to_vec()),
        };
        (stream, (open, written))
    }

    /// A write while the wire is congested must report Pending instead
    /// of swallowing bytes into an unbounded outbox — the first write
    /// stages into the (bounded) outbox, the next one pends.
    #[test]
    fn v2_write_backpressure() {
        let (inner, (open, written)) = gated_stream(&[]);
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(
                Pin::new(&mut s).poll_write(&mut cx, b"hi"),
                Poll::Ready(Ok(2))
            ),
            "first write stages into the outbox"
        );
        assert!(
            matches!(Pin::new(&mut s).poll_write(&mut cx, b"!!"), Poll::Pending),
            "second write pends while the outbox is stuck"
        );
        open.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            Pin::new(&mut s).poll_write(&mut cx, b"!!"),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(
            written.lock().unwrap().as_slice(),
            &[23, 3, 3, 0, 2, b'h', b'i', 23, 3, 3, 0, 2, b'!', b'!']
        );
    }

    /// A read-only caller must unstick a staged write tail — poll_read
    /// drains the outbox before waiting on the peer.
    #[test]
    fn v2_read_unsticks_outbox() {
        let (inner, (open, written)) = gated_stream(&[23, 3, 3, 0, 1, b'x']);
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        // Stages into the outbox but cannot reach the wire yet.
        assert!(matches!(
            Pin::new(&mut s).poll_write(&mut cx, b"hi"),
            Poll::Ready(Ok(2))
        ));
        open.store(true, std::sync::atomic::Ordering::Relaxed);
        // The next poll_read flushes the tail before serving inbound data.
        let mut buf = [0u8; 8];
        let mut rb = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut s).poll_read(&mut cx, &mut rb),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(rb.filled(), b"x");
        assert_eq!(
            written.lock().unwrap().as_slice(),
            &[23, 3, 3, 0, 2, b'h', b'i']
        );
    }

    /// BoringSSL's BIO_ctrl(BIO_CTRL_FLUSH) maps a WouldBlock to
    /// SSL_ERROR_SYSCALL — the shim must never report a flush Pending.
    #[test]
    fn shim_flush_never_pends() {
        let (inner, _handle) = gated_stream(&[]);
        let mut shim = HandshakeShim::new(Box::new(inner), 2, PASSWORD);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut shim).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }

    // ── regression: zero-payload records must disarm the serve cursor ──

    /// A zero-payload record completes with `rec_serve` pointing at the
    /// record end; if the cursor stays armed, the *next* record's raw
    /// bytes get served as payload while it is still assembling.
    #[test]
    fn v2_zero_payload_record_never_leaks_mid_assembly_bytes() {
        let (inner, _handle) = gated_stream(&[
            23, 3, 3, 0, 0, // complete zero-payload record
            23, 3, 3, 0, 4, b'a', b'b', b'c', // 8 of 9 bytes of the next
        ]);
        let mut s = framed(Box::new(inner), None, VecDeque::new());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut buf = [0u8; 16];
        let mut rb = ReadBuf::new(&mut buf);
        // First poll consumes the empty record and pends on the tail.
        assert!(matches!(
            Pin::new(&mut s).poll_read(&mut cx, &mut rb),
            Poll::Pending
        ));
        // Second poll must NOT serve the assembling record's bytes.
        assert!(matches!(
            Pin::new(&mut s).poll_read(&mut cx, &mut rb),
            Poll::Pending
        ));
        assert_eq!(rb.filled().len(), 0);
    }

    /// Same hazard on the v3 path is worse: the armed cursor would serve
    /// payload bytes BEFORE the record's embedded tag is verified —
    /// unauthenticated plaintext would reach the SS layer.
    #[test]
    fn v3_zero_payload_record_never_leaks_unverified_bytes() {
        // `mk_v3_parts` seeds the "S" chain from [0x55; 32].
        let mut srv_s = sha1_hmac(PASSWORD);
        srv_s.update(&[0x55u8; 32]);
        srv_s.update(b"S");
        let mut wire = server_record(&mut srv_s, &[]); // tag-only record
                                                       // First 10 bytes of a 14-byte record (declared len 9).
        wire.extend([23, 3, 3, 0, 9, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        let (stream, _h) = gated_stream(&wire);
        let (state, server_random) = mk_v3_parts(Box::new(stream));
        assert_eq!(server_random, [0x55u8; 32]);
        let mut s = VerifiedStream::new(state);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut buf = [0u8; 16];
        let mut rb = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut s).poll_read(&mut cx, &mut rb),
            Poll::Pending
        ));
        assert!(matches!(
            Pin::new(&mut s).poll_read(&mut cx, &mut rb),
            Poll::Pending
        ));
        assert_eq!(rb.filled().len(), 0);
    }

    /// A TLS 1.3 ServerHello whose `session_id_echo` isn't 32 bytes is
    /// spliced by `rewrite_sh_session_id_echo` — the version must be
    /// evaluated on the pre-splice record, or the stale length byte
    /// misoffsets the extension scan and misreports TLS 1.2 (which would
    /// authorize the session without a verified swizzled record).
    #[tokio::test]
    async fn v3_spliced_echo_still_detects_tls13() {
        let (inner, _peer) = tokio::io::duplex(64);
        let mut shim = HandshakeShim::new(Box::new(inner), 3, PASSWORD);
        let Mode::V3(v3) = &mut shim.mode else {
            panic!("v3 mode")
        };
        v3.orig_sid = Some([7u8; 32]);
        // sid_len = 0 → the splice path, not the in-place copy.
        let sh = server_hello_record(&[9u8; 32], true);
        shim.process_record(sh).unwrap();
        let state = shim.v3_state();
        assert!(state.is_tls13, "spliced 1.3 SH must still report is_tls13");
        assert!(!state.authorized, "1.3 must not authorize on the SH alone");
    }
}
