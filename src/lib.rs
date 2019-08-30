//! Async WebSocket usage.
//!
//! This library is an implementation of WebSocket handshakes and streams. It
//! is based on the crate which implements all required WebSocket protocol
//! logic. So this crate basically just brings tokio support / tokio integration
//! to it.
//!
//! Each WebSocket stream implements the required `Stream` and `Sink` traits,
//! so the socket is just a stream of messages coming in and going out.

#![deny(
    missing_docs,
    unused_must_use,
    unused_mut,
    unused_imports,
    unused_import_braces
)]

pub use tungstenite;

#[cfg(feature = "connect")]
mod connect;

#[cfg(feature = "stream")]
pub mod stream;

use std::io::ErrorKind;

#[cfg(feature = "stream")]
use std::{io::Result as IoResult, net::SocketAddr};

use futures::{task::Context, Future, Poll, Sink, Stream};
use std::pin::Pin;
use tokio_io::{AsyncRead, AsyncWrite};

use tungstenite::{
    error::Error as WsError,
    handshake::{
        client::{ClientHandshake, Request, Response},
        server::{Callback, NoCallback, ServerHandshake},
        HandshakeError, HandshakeRole,
    },
    protocol::{Message, Role, WebSocket, WebSocketConfig},
    server,
};

#[cfg(feature = "connect")]
pub use connect::{client_async_tls, connect_async, connect_async_ip_secure};

#[cfg(feature = "stream")]
pub use stream::PeerAddr;

#[cfg(all(feature = "connect", feature = "tls"))]
pub use connect::MaybeTlsStream;
use std::io::{Read, Write};

/// Creates a WebSocket handshake from a request and a stream.
/// For convenience, the user may call this with a url string, a URL,
/// or a `Request`. Calling with `Request` allows the user to add
/// a WebSocket protocol or other custom headers.
///
/// Internally, this custom creates a handshake representation and returns
/// a future representing the resolution of the WebSocket handshake. The
/// returned future will resolve to either `WebSocketStream<S>` or `Error`
/// depending on whether the handshake is successful.
///
/// This is typically used for clients who have already established, for
/// example, a TCP connection to the remote server.
pub fn client_async<'a, R, S>(request: R, stream: S) -> ConnectAsync<S>
where
    R: Into<Request<'a>>,
    S: AsyncRead + AsyncWrite + Unpin + Read + Write
{
    client_async_with_config(request, stream, None)
}

/// The same as `client_async()` but the one can specify a websocket configuration.
/// Please refer to `client_async()` for more details.
pub fn client_async_with_config<'a, R, S>(
    request: R,
    stream: S,
    config: Option<WebSocketConfig>,
) -> ConnectAsync<S>
where
    R: Into<Request<'a>>,
    S: AsyncRead + AsyncWrite + Unpin + Read + Write,
{
    ConnectAsync {
        inner: MidHandshake {
            inner: Some(ClientHandshake::start(stream, request.into(), config).handshake()),
        },
    }
}

/// Accepts a new WebSocket connection with the provided stream.
///
/// This function will internally call `server::accept` to create a
/// handshake representation and returns a future representing the
/// resolution of the WebSocket handshake. The returned future will resolve
/// to either `WebSocketStream<S>` or `Error` depending if it's successful
/// or not.
///
/// This is typically used after a socket has been accepted from a
/// `TcpListener`. That socket is then passed to this function to perform
/// the server half of the accepting a client's websocket connection.
pub fn accept_async<S>(stream: S) -> AcceptAsync<S, NoCallback>
where
    S: AsyncRead + AsyncWrite + Read + Write,
{
    accept_hdr_async(stream, NoCallback)
}

/// The same as `accept_async()` but the one can specify a websocket configuration.
/// Please refer to `accept_async()` for more details.
pub fn accept_async_with_config<S>(
    stream: S,
    config: Option<WebSocketConfig>,
) -> AcceptAsync<S, NoCallback>
where
    S: AsyncRead + AsyncWrite + Read + Write,
{
    accept_hdr_async_with_config(stream, NoCallback, config)
}

/// Accepts a new WebSocket connection with the provided stream.
///
/// This function does the same as `accept_async()` but accepts an extra callback
/// for header processing. The callback receives headers of the incoming
/// requests and is able to add extra headers to the reply.
pub fn accept_hdr_async<S, C>(stream: S, callback: C) -> AcceptAsync<S, C>
where
    S: AsyncRead + AsyncWrite + Read + Write,
    C: Callback,
{
    accept_hdr_async_with_config(stream, callback, None)
}

/// The same as `accept_hdr_async()` but the one can specify a websocket configuration.
/// Please refer to `accept_hdr_async()` for more details.
pub fn accept_hdr_async_with_config<S, C>(
    stream: S,
    callback: C,
    config: Option<WebSocketConfig>,
) -> AcceptAsync<S, C>
where
    S: AsyncRead + AsyncWrite + Read + Write,
    C: Callback,
{
    AcceptAsync {
        inner: MidHandshake {
            inner: Some(server::accept_hdr_with_config(stream, callback, config)),
        },
    }
}

/// A wrapper around an underlying raw stream which implements the WebSocket
/// protocol.
///
/// A `WebSocketStream<S>` represents a handshake that has been completed
/// successfully and both the server and the client are ready for receiving
/// and sending data. Message from a `WebSocketStream<S>` are accessible
/// through the respective `Stream` and `Sink`. Check more information about
/// them in `futures-rs` crate documentation or have a look on the examples
/// and unit tests for this crate.
pub struct WebSocketStream<S> {
    inner: WebSocket<S>,
}

impl<S> WebSocketStream<S> {
    pin_utils::unsafe_unpinned!(inner: WebSocket<S>);
    /// Convert a raw socket into a WebSocketStream without performing a
    /// handshake.
    pub fn from_raw_socket(stream: S, role: Role, config: Option<WebSocketConfig>) -> Self {
        Self::new(WebSocket::from_raw_socket(stream, role, config))
    }

    /// Convert a raw socket into a WebSocketStream without performing a
    /// handshake.
    pub fn from_partially_read(
        stream: S,
        part: Vec<u8>,
        role: Role,
        config: Option<WebSocketConfig>,
    ) -> Self {
        Self::new(WebSocket::from_partially_read(stream, part, role, config))
    }

    fn new(ws: WebSocket<S>) -> Self {
        WebSocketStream { inner: ws }
    }
}

#[cfg(feature = "stream")]
impl<S: PeerAddr> PeerAddr for WebSocketStream<S> {
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
}

impl<T> Stream for WebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Read + Write,
{
    type Item = Result<Message, WsError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.inner()
            .read_message()
            .map(Some)
            .into_async()
            .map(|res| {
                res.or_else(|err| match err {
                    WsError::ConnectionClosed => Ok(None),
                    err => Err(err)
                })
                    .transpose()
            })
    }
}

impl<T> Sink<Message> for WebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Read + Write,
{
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner().write_pending().into_async()
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.inner().write_message(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.inner().write_pending().into_async()
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.inner().close(None).into_async()
    }
}

/// Future returned from client_async() which will resolve
/// once the connection handshake has finished.
pub struct ConnectAsync<S: AsyncRead + AsyncWrite + Unpin + Read + Write> {
    inner: MidHandshake<ClientHandshake<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Read + Write> ConnectAsync<S> {
    pin_utils::unsafe_pinned!(inner: MidHandshake<ClientHandshake<S>>);
}

impl<S: AsyncRead + AsyncWrite + Unpin + Read + Write> Future for ConnectAsync<S> {
    type Output = Result<(WebSocketStream<S>, Response), WsError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner().poll(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready((ws, resp)) => Poll::Ready(Ok((WebSocketStream::new(ws), resp))),
        }
    }
}

/// Future returned from accept_async() which will resolve
/// once the connection handshake has finished.
pub struct AcceptAsync<S: AsyncRead + AsyncWrite + Read + Write, C: Callback> {
    inner: MidHandshake<ServerHandshake<S, C>>,
}

impl<S: AsyncRead + AsyncWrite + Read + Write, C: Callback> AcceptAsync<S, C> {
    pin_utils::unsafe_pinned!(inner: MidHandshake<ServerHandshake<S, C>>);
}

impl<S: AsyncRead + AsyncWrite + Read + Write, C: Callback> Future for AcceptAsync<S, C> {
    type Output = Result<WebSocketStream<S>, WsError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner().poll(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(ws) => Poll::Ready(Ok(WebSocketStream::new(ws))),
        }
    }
}

struct MidHandshake<H: HandshakeRole> {
    inner: Option<Result<<H as HandshakeRole>::FinalResult, HandshakeError<H>>>,
}

impl<H: HandshakeRole> MidHandshake<H> {
    pin_utils::unsafe_unpinned!(
        inner: Option<Result<<H as HandshakeRole>::FinalResult, HandshakeError<H>>>
    );
}

impl<H: HandshakeRole> Future for MidHandshake<H> {
    type Output = Result<<H as HandshakeRole>::FinalResult, WsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().inner().take().expect("cannot poll MidHandshake twice") {
            Ok(result) => Poll::Ready(Ok(result)),
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
            Err(HandshakeError::Interrupted(s)) => match s.handshake() {
                Ok(result) => Poll::Ready(Ok(result)),
                Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
                Err(HandshakeError::Interrupted(s)) => {
                    let mut this = unsafe {self.get_unchecked_mut()};
                    this.inner = Some(Err(HandshakeError::Interrupted(s)));
                    Poll::Pending
                }
            },
        }
    }
}

trait IntoAsync {
    type O;
    fn into_async(self) -> Poll<Self::O>;
}

impl<T> IntoAsync for Result<T, WsError> {
    type O = Result<T, WsError>;
    fn into_async(self) -> Poll<Self::O> {
        match self {
            Ok(x) => Poll::Ready(Ok(x)),
            Err(error) => match error {
                WsError::Io(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
                err => Poll::Ready(Err(err)),
            },
        }
    }
}
