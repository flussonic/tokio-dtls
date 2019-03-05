#[allow(unused_imports)]
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::thread;

use hex;
use tokio::prelude::*;

use super::*;

macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        }
    };
}

#[derive(Debug)]
struct UdpChannel {
    socket: UdpSocket,
    remote_addr: SocketAddr,
}

impl Read for UdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }
}

impl Write for UdpChannel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send_to(buf, self.remote_addr)
    }

    fn flush(&mut self) -> result::Result<(), io::Error> {
        Ok(())
    }
}

#[derive(Debug)]
struct TokioUdpChannel {
    socket: tokio::net::UdpSocket,
    remote_addr: SocketAddr,
}

impl Read for TokioUdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }
}

impl Write for TokioUdpChannel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send_to(buf, &self.remote_addr)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for TokioUdpChannel {
    fn shutdown(&mut self) -> io::Result<Async<()>> {
        Ok(Async::Ready(()))
    }
}

impl AsyncRead for TokioUdpChannel {}

mod tests {
    use openssl::ssl::SslMethod;

    use super::*;

    #[test]
    fn test_sync() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let acceptor = p!(DtlsAcceptor::builder(identity).build());
        let connector = p!(DtlsConnector::builder()
            .add_srtp_profile(SrtpProfile::Aes128CmSha180)
            .add_srtp_profile(SrtpProfile::AeadAes256Gcm)
            .add_root_certificate(root_ca)
            .build());

        let server = p!(UdpSocket::bind("127.0.0.1:0"));
        let client = p!(UdpSocket::bind("127.0.0.1:0"));

        let server_addr = p!(server.local_addr());
        let client_addr = p!(client.local_addr());

        let server_channel = UdpChannel {
            socket: server,
            remote_addr: client_addr,
        };

        let client_channel = UdpChannel {
            socket: client,
            remote_addr: server_addr,
        };


        let guard = thread::spawn(move || {
            let mut dtls_server = p!(acceptor.accept(server_channel));

            let mut buf = [0; 5];
            p!(dtls_server.read_exact(&mut buf));
            buf
        });

        let mut dtls_client = p!(connector.connect("foobar.com", client_channel));
        let buf = b"hello";
        p!(dtls_client.write_all(buf));
        let buf2 = p!(guard.join());
        assert_eq!(buf, &buf2);
    }

    #[test]
    fn test_async() {
        use futures::prelude::*;
        use futures::lazy;

        use tokio::net::UdpSocket;
        use tokio::runtime::Runtime;;

        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let acceptor: tokio_dtls::DtlsAcceptor = p!(DtlsAcceptor::builder(identity).build()).into();
        let connector: tokio_dtls::DtlsConnector = p!(DtlsConnector::builder()
            .add_srtp_profile(SrtpProfile::Aes128CmSha180)
            .add_srtp_profile(SrtpProfile::AeadAes256Gcm)
            .add_root_certificate(root_ca)
            .build())
            .into();

        let server = p!(UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()));
        let client = p!(UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()));

        let server_addr = p!(server.local_addr());
        let client_addr = p!(client.local_addr());

        let server_channel = TokioUdpChannel {
            socket: server,
            remote_addr: client_addr,
        };

        let client_channel = TokioUdpChannel {
            socket: client,
            remote_addr: server_addr,
        };

        let buf = b"hello".to_vec();

        let mut rt = Runtime::new().unwrap();
        let res = rt.block_on(lazy({
            let buf = buf.clone();

            move || {
                tokio::spawn(acceptor.accept(server_channel)
                    .map_err(|_| ())
                    .and_then(move |mut conn| {
                        conn.poll_write(&buf).map_err(|_| ()).map(|_| ())
                    }));
                connector.connect("foobar.com", client_channel)
                    .map_err(|_| ())
                    .and_then(move |mut connection| {
                        let mut res = vec![0u8; 5];
                        connection.poll_read(&mut res[..]).map_err(|_| ()).map(move |_| {
                            res
                        })
                    })
            }
        })).unwrap();
        assert_eq!(res, buf);
    }
}
