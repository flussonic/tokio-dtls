//! Async DTLS streams

use std::io::{self, Read, Write};

use bytes::Buf;
use bytes::BytesMut;
use futures::{Async, Future, Poll, AsyncSink};
use futures::Sink;
use futures::Stream;
use tokio_io::{AsyncRead, AsyncWrite};

use crate::{Error, HandshakeError};
use std::hint::unreachable_unchecked;

/// A wrapper around an underlying raw stream which implements the DTLS
/// protocol.
///
/// A `DtlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `DtlsStream` are decrypted from `S` and bytes written
/// to a `DtlsStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct DtlsStream<S> {
    inner: crate::DtlsStream<S>,
}

/// A wrapper around a `crate::DtlsConnector`, providing an async `connect`
/// method.
#[derive(Clone)]
pub struct DtlsConnector {
    inner: crate::DtlsConnector,
}

/// A wrapper around a `crate::DtlsAcceptor`, providing an async `accept`
/// method.
#[derive(Clone)]
pub struct DtlsAcceptor {
    inner: crate::DtlsAcceptor,
}

/// Future returned from `DtlsConnector::connect` which will resolve
/// once the connection handshake has finished.
pub struct Connect<S> {
    inner: MidHandshake<S>,
}

/// Future returned from `DtlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<S> {
    inner: MidHandshake<S>,
}

struct MidHandshake<S> {
    inner: Option<Result<crate::DtlsStream<S>, HandshakeError<S>>>,
}

impl<S> DtlsStream<S> {
    /// Get access to the internal `crate::DtlsStream` stream which also
    /// transitively allows access to `S`.
    pub fn get_ref(&self) -> &crate::DtlsStream<S> {
        &self.inner
    }

    /// Get mutable access to the internal `crate::DtlsStream` stream which
    /// also transitively allows mutable access to `S`.
    pub fn get_mut(&mut self) -> &mut crate::DtlsStream<S> {
        &mut self.inner
    }
}

impl<S: Read + Write> Read for DtlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Read + Write> Write for DtlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for DtlsStream<S> {}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for DtlsStream<S> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        try_nb!(self.inner.shutdown());
        self.inner.get_mut().shutdown()
    }
}

impl DtlsConnector {
    /// Connects the provided stream with this connector, assuming the provided
    /// domain.
    ///
    pub fn connect<S>(&self, domain: &str, stream: S) -> Connect<S>
        where
            S: AsyncRead + AsyncWrite,
    {
        Connect {
            inner: MidHandshake {
                inner: Some(self.inner.connect(domain, stream)),
            },
        }
    }
}

impl From<crate::DtlsConnector> for DtlsConnector {
    fn from(inner: crate::DtlsConnector) -> DtlsConnector {
        DtlsConnector { inner }
    }
}

impl DtlsAcceptor {
    /// Accepts a new client connection with the provided stream.
    ///
    /// This function will internally call `DtlsAcceptor::accept` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `DtlsStream<S>` or `Error` depending if it's successful or not.
    ///
    /// This is typically used after a new socket has been accepted from a
    /// `TcpListener`. That socket is then passed to this function to perform
    /// the server half of accepting a client connection.
    pub fn accept<S>(&self, stream: S) -> Accept<S>
        where
            S: AsyncRead + AsyncWrite,
    {
        Accept {
            inner: MidHandshake {
                inner: Some(self.inner.accept(stream)),
            },
        }
    }
}

impl From<crate::DtlsAcceptor> for DtlsAcceptor {
    fn from(inner: crate::DtlsAcceptor) -> DtlsAcceptor {
        DtlsAcceptor { inner }
    }
}

impl<S: AsyncRead + AsyncWrite> Future for Connect<S> {
    type Item = DtlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<DtlsStream<S>, Error> {
        self.inner.poll()
    }
}

impl<S: AsyncRead + AsyncWrite> Future for Accept<S> {
    type Item = DtlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<DtlsStream<S>, Error> {
        self.inner.poll()
    }
}

impl<S: AsyncRead + AsyncWrite> Future for MidHandshake<S> {
    type Item = DtlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<DtlsStream<S>, Error> {
        match self.inner.take().expect("cannot poll MidHandshake twice") {
            Ok(stream) => Ok(DtlsStream { inner: stream }.into()),
            Err(HandshakeError::Failure(e)) => Err(e),
            Err(HandshakeError::WouldBlock(s)) => match s.handshake() {
                Ok(stream) => Ok(DtlsStream { inner: stream }.into()),
                Err(HandshakeError::Failure(e)) => Err(e),
                Err(HandshakeError::WouldBlock(s)) => {
                    self.inner = Some(Err(HandshakeError::WouldBlock(s)));
                    Ok(Async::NotReady)
                }
            },
        }
    }
}