//! Convenience wrapper for streams to switch between plain TCP and TLS at runtime.
//!
//!  There is no dependency on actual TLS implementations. Everything like
//! `native_tls` or `openssl` will work as long as there is a TLS stream supporting standard
//! `Read + Write` traits.

use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use futures::task::Context;
use futures::Poll;
use std::pin::Pin;
use tokio_io::{AsyncRead, AsyncWrite as FutAsyncWrite, AsyncRead as FutAsyncRead};

/// Trait to switch TCP_NODELAY.
pub trait NoDelay {
    /// Set the TCP_NODELAY option to the given value.
    fn set_nodelay(&mut self, nodelay: bool) -> IoResult<()>;
}

/// Trait to get the remote address from the underlying stream.
pub trait PeerAddr {
    /// Returns the remote address that this stream is connected to.
    fn peer_addr(&self) -> IoResult<SocketAddr>;
}

/// Stream, either plain TCP or TLS.
pub enum Stream<S, T> {
    /// Unencrypted socket stream.
    Plain(S),
    /// Encrypted socket stream.
    Tls(T),
}

impl<S: Read, T: Read> Read for Stream<S, T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match *self {
            Stream::Plain(ref mut s) => s.read(buf),
            Stream::Tls(ref mut s) => s.read(buf),
        }
    }
}

impl<S: Write, T: Write> Write for Stream<S, T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match *self {
            Stream::Plain(ref mut s) => s.write(buf),
            Stream::Tls(ref mut s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> IoResult<()> {
        match *self {
            Stream::Plain(ref mut s) => s.flush(),
            Stream::Tls(ref mut s) => s.flush(),
        }
    }
}

impl<S: NoDelay, T: NoDelay> NoDelay for Stream<S, T> {
    fn set_nodelay(&mut self, nodelay: bool) -> IoResult<()> {
        match *self {
            Stream::Plain(ref mut s) => s.set_nodelay(nodelay),
            Stream::Tls(ref mut s) => s.set_nodelay(nodelay),
        }
    }
}

impl<S: PeerAddr, T: PeerAddr> PeerAddr for Stream<S, T> {
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        match *self {
            Stream::Plain(ref s) => s.peer_addr(),
            Stream::Tls(ref s) => s.peer_addr(),
        }
    }
}

impl<S: AsyncRead, T: AsyncRead> AsyncRead for Stream<S, T> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match *self {
            Stream::Plain(ref s) => s.prepare_uninitialized_buffer(buf),
            Stream::Tls(ref s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let stream = unsafe { self.get_unchecked_mut() };
        match stream {
            Stream::Plain(ref mut s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
            Stream::Tls(ref mut s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
        }
    }

    fn poll_read_buf<B: BufMut>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<Result<usize, IoError>> {
        let stream = unsafe { self.get_unchecked_mut() };
        match stream {
            Stream::Plain(ref mut s) => unsafe { Pin::new_unchecked(s).poll_read_buf(cx, buf) },
            Stream::Tls(ref mut s) => unsafe { Pin::new_unchecked(s).poll_read_buf(cx, buf) },
        }
    }
}

impl<S: AsyncWrite, T: AsyncWrite> AsyncWrite for Stream<S, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        let stream = unsafe { self.get_unchecked_mut() };
        match stream {
            Stream::Plain(ref mut s) => unsafe { Pin::new_unchecked(s).poll_write(cx, buf) },
            Stream::Tls(ref mut s) => unsafe { Pin::new_unchecked(s).poll_write(cx, buf) },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        let stream = unsafe { self.get_unchecked_mut() };
        match stream {
            Stream::Plain(ref mut s) => unsafe { Pin::new_unchecked(s).poll_flush(cx) },
            Stream::Tls(ref mut s) => unsafe { Pin::new_unchecked(s).poll_flush(cx) },
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        let stream = unsafe { self.get_unchecked_mut() };
        match stream {
            Stream::Plain(ref mut s) => unsafe { Pin::new_unchecked(s).poll_shutdown(cx) },
            Stream::Tls(ref mut s) => unsafe { Pin::new_unchecked(s).poll_shutdown(cx) },
        }
    }

    fn poll_write_buf<B: Buf>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<Result<usize, IoError>> {
        let stream = unsafe { self.get_unchecked_mut() };
        match stream {
            Stream::Plain(ref mut s) => unsafe { Pin::new_unchecked(s).poll_write_buf(cx, buf) },
            Stream::Tls(ref mut s) => unsafe { Pin::new_unchecked(s).poll_write_buf(cx, buf) },
        }
    }
}
