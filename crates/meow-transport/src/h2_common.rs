//! Shared raw HTTP/2 stream plumbing for the h2 transport and sing-h2mux.

use bytes::Bytes;
use http::StatusCode;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Accepted response status for a lazily resolved HTTP/2 body.
#[derive(Clone, Copy)]
pub enum StatusPolicy {
    Success,
    Exact(StatusCode),
}

enum RecvInner {
    Pending(h2::client::ResponseFuture),
    Ready(h2::RecvStream),
    Failed,
}

/// Receive half of a client-initiated h2 request, resolved lazily on first
/// read so servers that wait for request DATA cannot deadlock setup.
pub struct RecvState {
    inner: RecvInner,
    timeout: Option<Pin<Box<tokio::time::Sleep>>>,
    status: StatusPolicy,
    label: &'static str,
}

impl RecvState {
    pub fn new(response: h2::client::ResponseFuture) -> Self {
        Self {
            inner: RecvInner::Pending(response),
            timeout: None,
            status: StatusPolicy::Success,
            label: "h2",
        }
    }

    pub fn with_timeout(
        response: h2::client::ResponseFuture,
        timeout: Duration,
        status: StatusPolicy,
        label: &'static str,
    ) -> Self {
        Self {
            inner: RecvInner::Pending(response),
            timeout: Some(Box::pin(tokio::time::sleep(timeout))),
            status,
            label,
        }
    }

    fn accepts(&self, status: StatusCode) -> bool {
        match self.status {
            StatusPolicy::Success => status.is_success(),
            StatusPolicy::Exact(expected) => status == expected,
        }
    }

    /// Drive the response future far enough that [`Self::stream`] returns the
    /// body. Once this resolves `Ready(Ok(()))`, the body is retained.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RecvInner::Ready(_) => return Poll::Ready(Ok(())),
            RecvInner::Failed => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("{}: response stream already failed", self.label),
                )))
            }
            RecvInner::Pending(future) => match Pin::new(future).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(response)) => {
                    let status = response.status();
                    if !self.accepts(status) {
                        self.inner = RecvInner::Failed;
                        return Poll::Ready(Err(io::Error::other(format!(
                            "{}: unexpected response status {status}",
                            self.label
                        ))));
                    }
                    self.inner = RecvInner::Ready(response.into_body());
                    self.timeout = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.inner = RecvInner::Failed;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
            },
        }

        if let Some(timeout) = &mut self.timeout {
            if timeout.as_mut().poll(cx).is_ready() {
                self.inner = RecvInner::Failed;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{}: response timeout", self.label),
                )));
            }
        }
        Poll::Pending
    }

    pub fn stream(&mut self) -> Option<&mut h2::RecvStream> {
        match &mut self.inner {
            RecvInner::Ready(stream) => Some(stream),
            _ => None,
        }
    }
}

/// Raw bidirectional bytes over one HTTP/2 request/response pair.
pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: RecvState,
    read_buf: Bytes,
    /// Pre-encoded payload stashed while waiting for h2 send-window
    /// capacity, plus the number of bytes already handed to the
    /// connection.  Only the ungranted remainder is ever sent, so a
    /// peer that stops reading applies real backpressure instead of
    /// growing h2's internal buffer.
    pending_write: Option<(Bytes, usize)>,
    remote_no_error_is_eof: bool,
    eos_sent: bool,
}

impl H2Stream {
    pub fn new(send: h2::SendStream<Bytes>, recv: RecvState) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            pending_write: None,
            remote_no_error_is_eof: false,
            eos_sent: false,
        }
    }

    pub fn with_remote_no_error_eof(mut self) -> Self {
        self.remote_no_error_is_eof = true;
        self
    }

    fn best_effort_eos(&mut self) {
        if !self.eos_sent {
            self.eos_sent = true;
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.best_effort_eos();
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A zero-capacity buffer yields Ready(Ok(())) per the tokio
        // AsyncRead docs (a Pending here would leave `read(&mut [])`
        // parked forever).
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.read_buf.is_empty() {
                let count = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..count]);
                let _ = this.read_buf.split_to(count);
                return Poll::Ready(Ok(()));
            }
            match this.recv.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let recv = this.recv.stream().expect("poll_ready resolved Ok");
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => {
                    if this.remote_no_error_is_eof
                        && error.is_reset()
                        && error.is_remote()
                        && error.reason() == Some(h2::Reason::NO_ERROR)
                    {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // Stash the payload exactly once per logical write: if
        // pending_write is set, a previous poll returned Pending and
        // capacity has been reserved — do not encode or reserve again.
        // This relies on the AsyncWrite contract that a Pending poll is
        // retried with the same buffer.
        if this.pending_write.is_none() {
            let data = Bytes::copy_from_slice(buf);
            this.send.reserve_capacity(data.len());
            this.pending_write = Some((data, 0));
        }
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2: send stream closed",
                )))
            }
            Poll::Ready(Some(Err(error))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(error)))
            }
            Poll::Ready(Some(Ok(capacity))) => {
                let (data, offset) = this.pending_write.as_mut().expect("set above");
                let remaining = data.len() - *offset;
                // poll_capacity may grant less than the reserved amount
                // (the peer's flow-control window); send only the
                // granted prefix and keep the rest pending.
                let allowed = capacity.min(remaining);
                if allowed == 0 {
                    return Poll::Pending;
                }
                let chunk = data.slice(*offset..*offset + allowed);
                let chunk_len = chunk.len();
                if let Err(error) = this.send.send_data(chunk, false) {
                    this.pending_write = None;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                *offset += chunk_len;
                if *offset >= data.len() {
                    this.pending_write = None;
                }
                Poll::Ready(Ok(chunk_len))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().best_effort_eos();
        Poll::Ready(Ok(()))
    }
}

impl Unpin for H2Stream {}
