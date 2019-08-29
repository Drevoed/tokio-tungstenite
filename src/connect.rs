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

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<(), Error> {
        unimplemented!()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        unimplemented!()
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

    use tokio_io::{AsyncRead, AsyncWrite};

    use tungstenite::stream::Mode;
    use tungstenite::Error;

    use crate::stream::{NoDelay, PeerAddr, Stream as StreamSwitcher};
    use futures::future::Either;

    /// A stream that might be protected with TLS.
    pub type MaybeTlsStream<S> = StreamSwitcher<S, TlsStream<S>>;

    pub type AutoStream<S> = MaybeTlsStream<S>;

    impl<T: Read + Write + NoDelay> NoDelay for TlsStream<T> {
        fn set_nodelay(&mut self, nodelay: bool) -> IoResult<()> {
            self.get_mut().get_mut().set_nodelay(nodelay)
        }
    }

    impl<T: Write> Write for TlsStream<T> {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            unimplemented!()
        }

        fn flush(&mut self) -> Result<(), Error> {
            unimplemented!()
        }
    }

    impl<T: Read> Read for TlsStream<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            unimplemented!()
        }
    }

    pub async fn wrap_stream<S>(
        socket: S,
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
                    .connect(&domain, socket)
                    .await
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
use futures::future::Either;

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
    S: AsyncRead + AsyncWrite + Read + Write + NoDelay + Unpin,
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

    let stream = wrap_stream(stream, domain, mode).await;
    let res: Result<Result<AutoStream<S>, Error>, Error> = stream.map(|mut stream| {
        NoDelay::set_nodelay(&mut stream, true)
            .map(move |()| stream)
            .map_err(|e| e.into())
    });
    let res = res?;
    let stream = res?;
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
