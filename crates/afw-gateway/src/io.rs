//! I/O helpers: replay of sniffed bytes, byte counting (and pcap tap), TCP reset.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::capture::CaptureSession;

/// Closes a TCP connection with a reset (SO_LINGER 0) instead of a FIN.
// SO_LINGER 0 never blocks on drop (it discards the send buffer and sends a RST): the
// deprecation warning is about non-zero linger values.
#[allow(deprecated)]
pub fn reset(stream: TcpStream) {
    let _ = stream.set_linger(Some(Duration::ZERO));
    drop(stream);
}

/// A stream whose first bytes (already read while sniffing) are replayed before the rest.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
    /// Drops the unread prefix and returns the inner stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            if self.pos == self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Byte counters of a flow, agent side: `out` = sent by the agent, `in` = received by it.
#[derive(Default, Debug)]
pub struct Counters {
    pub bytes_out: AtomicU64,
    pub bytes_in: AtomicU64,
}

impl Counters {
    pub fn out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }
    pub fn inn(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }
}

/// Wraps the agent-side stream: counts bytes and feeds an active pcap capture.
pub struct Tap<S> {
    inner: S,
    counters: Arc<Counters>,
    capture: Option<(Arc<CaptureSession>, SocketAddr, SocketAddr)>,
    seq_out: u32,
    seq_in: u32,
}

impl<S> Tap<S> {
    pub fn new(inner: S, counters: Arc<Counters>, capture: Option<(Arc<CaptureSession>, SocketAddr, SocketAddr)>) -> Self {
        Self {
            inner,
            counters,
            capture,
            seq_out: 1,
            seq_in: 1,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            let data = &buf.filled()[before..];
            if !data.is_empty() {
                self.counters.bytes_out.fetch_add(data.len() as u64, Ordering::Relaxed);
                if let Some((cap, src, dst)) = &self.capture {
                    cap.record(*src, *dst, self.seq_out, self.seq_in, data);
                }
                let n = data.len() as u32;
                self.seq_out = self.seq_out.wrapping_add(n);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r
            && n > 0
        {
            self.counters.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
            if let Some((cap, src, dst)) = &self.capture {
                cap.record(*dst, *src, self.seq_in, self.seq_out, &buf[..n]);
            }
            self.seq_in = self.seq_in.wrapping_add(n as u32);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bidirectional copy; returns when both directions are done or one fails.
pub async fn splice<A, B>(a: &mut A, b: &mut B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional(a, b).await.map(|_| ())
}
