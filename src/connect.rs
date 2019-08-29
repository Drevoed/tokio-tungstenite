//! Connection helper.

use std::io::Result as IoResult;
use std::net::SocketAddr;

use tokio_net::tcp::TcpStream;

use futures::{future, Future, TryFutureExt};
use tokio_io::{AsyncRead, AsyncWrite};

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

#[cfg(feature = "tls")]
mod encryption {
    use native_tls::TlsConnector;
    use tokio_tls::{TlsConnector as TokioTlsConnector, TlsStream};

    use std::io::{Read, Result as IoResult, Write};
    use std::net::SocketAddr;

    use futures::{future, Future, FutureExt, TryFutureExt, TryFuture, TryStreamExt};
    use tokio_io::{AsyncRead, AsyncWrite};

    use tungstenite::stream::Mode;
    use tungstenite::Error;

    use crate::stream::{NoDelay, PeerAddr, Stream as StreamSwitcher};

    /// A stream that might be protected with TLS.
    pub type MaybeTlsStream<S> = StreamSwitcher<S, TlsStream<S>>;

    pub type AutoStream<S> = MaybeTlsStream<S>;

    impl<T: Read + Write + NoDelay> NoDelay for TlsStream<T> {
        fn set_nodelay(&mut self, nodelay: bool) -> IoResult<()> {
            self.get_mut().get_mut().set_nodelay(nodelay)
        }
    }

    impl<S: Read + Write + PeerAddr> PeerAddr for TlsStream<S> {
        fn peer_addr(&self) -> IoResult<SocketAddr> {
            self.get_ref().get_ref().peer_addr()
        }
    }

    pub fn wrap_stream<S>(
        socket: S,
        domain: String,
        mode: Mode,
    ) -> impl Future<Output = Result<AutoStream<S>, Error>>
    where
        S: AsyncRead + AsyncWrite
    {
        match mode {
            Mode::Plain => future::ok(StreamSwitcher::Plain(socket)),
            Mode::Tls =>
                future::ready(TlsConnector::new())
                    .map_ok(TokioTlsConnector::from)
                    .and_then(move |connector| connector.connect(&domain, socket))
                    .map_ok(StreamSwitcher::Tls)
                    .map_err(Error::Tls),
        }
    }
}

#[cfg(feature = "tls")]
pub use self::encryption::MaybeTlsStream;

#[cfg(not(feature = "tls"))]
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
        S: AsyncRead + AsyncWrite
    {
        match mode {
            Mode::Plain => future::ok(socket),
            Mode::Tls => future::err(Error::Url(
                "TLS support not compiled in.".into(),
            )),
        }
    }
}

use self::encryption::{wrap_stream, AutoStream};
use std::io::Write;
use std::io::Read;

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
pub fn client_async_tls<R, S>(
    request: R,
    stream: S,
) -> impl Future<Output = Result<(WebSocketStream<AutoStream<S>>, Response), Error>>
where
    R: Into<Request<'static>>,
    S: AsyncRead + AsyncWrite + Read + Write + NoDelay,
{
    let request: Request = request.into();

    let domain = match domain(&request) {
        Ok(domain) => domain,
        Err(err) => return future::err(err),
    };

    // Make sure we check domain and mode first. URL must be valid.
    let mode = match url_mode(&request.url) {
        Ok(m) => m,
        Err(e) => return future::err(e),
    };

    let _:() = wrap_stream(stream, domain, mode);

    wrap_stream(stream, domain, mode)
        .and_then(|mut stream| {
            NoDelay::set_nodelay(&mut stream, true)
                .map(move |()| stream)
                .map_err(|e| e.into());
            future::ready(stream)
        })
        .and_then(move |stream| client_async(request, stream))
}

/// Connect to a given URL.
pub fn connect_async<R>(
    request: R,
) -> impl Future<Output = Result<(WebSocketStream<AutoStream<TcpStream>>, Response), Error>>
where
    R: Into<Request<'static>>,
{
    let request: Request = request.into();

    let domain = match domain(&request) {
        Ok(domain) => domain,
        Err(err) => future::err(err),
    };
    let port = request
        .url
        .port_or_known_default()
        .expect("Bug: port unknown");

    tokio_dns::TcpStream::connect((domain.as_str(), port))
        .map_err(|e| e.into())
        .and_then(move |socket| client_async_tls(request, socket))
}
