//! Connection helper.

use std::io::Result as IoResult;
use std::io;
use std::net::SocketAddr;

use tokio_net::tcp::TcpStream;

use futures::{Poll, task::Context};
use tokio_io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use tungstenite::client::url_mode;
use tungstenite::handshake::client::Response;
use tungstenite::Error;

use super::{client_async, Request, WebSocketStream};
use crate::stream::{NoDelay, PeerAddr};

impl NoDelay for TcpStream {
    fn set_nodelay(&mut self, nodelay: bool) -> IoResult<()> {
        TcpStream::set_nodelay(self, nodelay)
    }
}

impl PeerAddr for TcpStream {
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        self.peer_addr()
    }
}

pub struct ReadWriteWrapper<T> {
    inner: T
}

impl<T: AsyncRead + AsyncWrite> ReadWriteWrapper<T> {
    pin_utils::unsafe_pinned!(inner: T);
    pub(crate) fn new(inner: T) -> Self {
        ReadWriteWrapper {
            inner
        }
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Read for ReadWriteWrapper<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        block_on(self.inner.read(buf))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Write for ReadWriteWrapper<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        block_on(self.inner.write(buf))
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        block_on(self.inner.flush())
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncWrite for ReadWriteWrapper<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        self.inner().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.inner().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.inner().poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for ReadWriteWrapper<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        self.inner().poll_read(cx, buf)
    }
}

#[cfg(feature = "tls")]
mod encryption {
    use native_tls::TlsConnector;
    use tokio_tls::{TlsConnector as TokioTlsConnector, TlsStream};

    use tokio_io::{AsyncRead, AsyncWrite};

    use tungstenite::stream::Mode;
    use tungstenite::Error;

    use crate::stream::Stream as StreamSwitcher;
    use crate::connect::ReadWriteWrapper;

    /// A stream that might be protected with TLS.
    pub type MaybeTlsStream<S> = StreamSwitcher<ReadWriteWrapper<S>, ReadWriteWrapper<TlsStream<S>>>;

    pub type AutoStream<S> = MaybeTlsStream<S>;

    pub async fn wrap_stream<S>(
        socket: ReadWriteWrapper<S>,
        domain: String,
        mode: Mode,
    ) -> Result<AutoStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match mode {
            Mode::Plain => Ok(StreamSwitcher::Plain(socket)),
            Mode::Tls => {
                let connector = TlsConnector::new().map(TokioTlsConnector::from).unwrap();
                let stream = connector
                    .connect(&domain, socket.into_inner())
                    .await
                    .map(ReadWriteWrapper::new)
                    .map(StreamSwitcher::Tls)
                    .map_err(Error::Tls);
                stream
            }
        }
    }
}

#[cfg(feature = "tls")]
pub use self::encryption::MaybeTlsStream;

/*#[cfg(not(feature = "tls"))]
mod encryption {
    use futures::{future, Future};
    use tokio_io::{AsyncRead, AsyncWrite};

    use tungstenite::stream::Mode;
    use tungstenite::Error;

    pub type AutoStream<S> = S;

    pub fn wrap_stream<S>(
        socket: S,
        _domain: String,
        mode: Mode,
    ) -> impl Future<Output = Result<AutoStream<S>, Error>>
    where
        S: AsyncRead + AsyncWrite,
    {
        match mode {
            Mode::Plain => future::ok(socket),
            Mode::Tls => future::err(Error::Url("TLS support not compiled in.".into())),
        }
    }
}*/

use self::encryption::{wrap_stream, AutoStream};
use std::io::Read;
use std::io::Write;
use futures::executor::block_on;
use std::pin::Pin;

/// Get a domain from an URL.
#[inline]
fn domain(request: &Request) -> Result<String, Error> {
    match request.url.host_str() {
        Some(d) => Ok(d.to_string()),
        None => Err(Error::Url("no host name in the url".into())),
    }
}

/// Creates a WebSocket handshake from a request and a stream,
/// upgrading the stream to TLS if required.
pub async fn client_async_tls<R, S>(
    request: R,
    stream: S,
) -> Result<(WebSocketStream<AutoStream<S>>, Response), Error>
where
    R: Into<Request<'static>>,
    S: AsyncRead + AsyncWrite + NoDelay + Unpin,
{
    let request: Request = request.into();

    let domain = match domain(&request) {
        Ok(domain) => domain,
        Err(err) => return Err(err),
    };

    // Make sure we check domain and mode first. URL must be valid.
    let mode = match url_mode(&request.url) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    let stream = wrap_stream(ReadWriteWrapper::new(stream), domain, mode).await?;
    client_async(request, stream).await
}

/// Connect to a given URL.
pub async fn connect_async<R>(
    request: R,
) -> Result<(WebSocketStream<AutoStream<TcpStream>>, Response), Error>
where
    R: Into<Request<'static>>,
{
    let request: Request = request.into();

    let domain = match domain(&request) {
        Ok(domain) => domain,
        Err(err) => return Err(err),
    };
    let port = request
        .url
        .port_or_known_default()
        .expect("Bug: port unknown");

    let socket: Result<TcpStream, Error> = tokio_dns::TcpStream::connect((domain.as_str(), port))
        .await
        .map_err(|e| e.into());
    let socket = socket?;
    client_async_tls(request, socket).await
}
/// Do
pub async fn connect_async_ip_secure<R: Into<Request<'static>>>(request: R, host: &str) -> Result<(WebSocketStream<AutoStream<TcpStream>>, Response), Error> {
    let addr = &format!("{}:443", host).parse().unwrap();
    let request = request.into();
    let socket = TcpStream::connect(addr).await.unwrap();
    client_async_tls(request, socket).await
}
