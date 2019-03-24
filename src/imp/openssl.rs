extern crate openssl;
extern crate openssl_probe;

use std::error;
use std::fmt;
use std::io;
use std::sync::{Once, ONCE_INIT};

use crate::{DtlsAcceptorBuilder, DtlsConnectorBuilder, Protocol, SrtpProfile, SrtpProfileError};

use self::openssl::error::ErrorStack;
use self::openssl::hash::MessageDigest;
use self::openssl::nid::Nid;
use self::openssl::pkcs12::{ParsedPkcs12, Pkcs12};
use self::openssl::ssl::{
    self, MidHandshakeSslStream, SslAcceptor, SslConnector, SslContextBuilder, SslMethod,
    SslVerifyMode,
};
use self::openssl::x509::{X509VerifyResult, X509};

//fn supported_protocols(
//    min: Option<Protocol>,
//    max: Option<Protocol>,
//    ctx: &mut SslContextBuilder,
//) -> Result<(), ErrorStack> {
//    use self::openssl::ssl::SslOptions;
//
//    let no_ssl_mask = SslOptions::NO_SSL_MASK;
//
//    ctx.clear_options(no_ssl_mask);
//    let mut options = SslOptions::empty();
//    options |= match min {
//        None | Some(Protocol::Dtlsv10) => SslOptions::empty(),
//        Some(Protocol::Dtlsv12) => SslOptions::NO_DTLSV1,
//        Some(Protocol::__NonExhaustive) => unreachable!(),
//    };
//    options |= match max {
//        None | Some(Protocol::Dtlsv12) => SslOptions::empty(),
//        Some(Protocol::Dtlsv10) => SslOptions::NO_DTLSV1_2,
//        Some(Protocol::__NonExhaustive) => unreachable!(),
//    };
//
//    ctx.set_options(options);
//
//    Ok(())
//}

fn init_trust() {
    static ONCE: Once = ONCE_INIT;
    ONCE.call_once(|| openssl_probe::init_ssl_cert_env_vars());
}

#[cfg(target_os = "android")]
fn load_android_root_certs(connector: &mut SslContextBuilder) -> Result<(), Error> {
    use std::fs;

    if let Ok(dir) = fs::read_dir("/system/etc/security/cacerts") {
        let certs = dir
            .filter_map(|r| r.ok())
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| X509::from_pem(&b).ok());
        for cert in certs {
            if let Err(err) = connector.cert_store_mut().add_cert(cert) {
                debug!("load_android_root_certs error: {:?}", err);
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Normal(ErrorStack),
    Ssl(ssl::Error, X509VerifyResult),
    SrtpProfile(SrtpProfileError),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Normal(ref e) => error::Error::description(e),
            Error::Ssl(ref e, _) => error::Error::description(e),
            Error::SrtpProfile(ref e) => error::Error::description(e),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Normal(ref e) => error::Error::cause(e),
            Error::Ssl(ref e, _) => error::Error::cause(e),
            Error::SrtpProfile(ref e) => error::Error::cause(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Normal(ref e) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, X509VerifyResult::OK) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, v) => write!(fmt, "{} ({})", e, v),
            Error::SrtpProfile(ref e) => fmt::Display::fmt(e, fmt),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::Normal(err)
    }
}

impl From<SrtpProfileError> for Error {
    fn from(err: SrtpProfileError) -> Error {
        Error::SrtpProfile(err)
    }
}

pub struct Identity(ParsedPkcs12);

impl Identity {
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        let pkcs12 = Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse(pass)?;
        Ok(Identity(parsed))
    }

    pub fn certificate(&self) -> Certificate {
        Certificate(self.0.cert.clone())
    }
}

#[derive(Clone)]
pub struct Certificate(X509);

impl Certificate {
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = X509::from_der(buf)?;
        Ok(Certificate(cert))
    }

    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = X509::from_pem(buf)?;
        Ok(Certificate(cert))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = self.0.to_der()?;
        Ok(der)
    }

    pub fn fingerprint(
        &self,
        signature_algorithm: crate::SignatureAlgorithm,
    ) -> Result<crate::CertificateFingerprint, Error> {
        let md = match signature_algorithm {
            crate::SignatureAlgorithm::Sha1 => MessageDigest::sha1(),
            crate::SignatureAlgorithm::Sha256 => MessageDigest::sha256(),
        };

        let digest = self.0.digest(md)?;

        Ok(crate::CertificateFingerprint {
            bytes: digest.to_vec(),
            signature_algorithm,
        })
    }
}

pub struct MidHandshakeDtlsStream<S>(MidHandshakeSslStream<S>);

impl<S> fmt::Debug for MidHandshakeDtlsStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> MidHandshakeDtlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S> MidHandshakeDtlsStream<S>
where
    S: io::Read + io::Write,
{
    pub fn handshake(self) -> Result<DtlsStream<S>, HandshakeError<S>> {
        match self.0.handshake() {
            Ok(s) => Ok(DtlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub enum HandshakeError<S> {
    Failure(Error),
    WouldBlock(MidHandshakeDtlsStream<S>),
}

impl<S> From<ssl::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: ssl::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            ssl::HandshakeError::SetupFailure(e) => HandshakeError::Failure(e.into()),
            ssl::HandshakeError::Failure(e) => {
                let v = e.ssl().verify_result();
                HandshakeError::Failure(Error::Ssl(e.into_error(), v))
            }
            ssl::HandshakeError::WouldBlock(s) => {
                HandshakeError::WouldBlock(MidHandshakeDtlsStream(s))
            }
        }
    }
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

#[derive(Clone)]
pub struct DtlsConnector {
    connector: SslConnector,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl DtlsConnector {
    pub fn new(builder: &DtlsConnectorBuilder) -> Result<DtlsConnector, Error> {
        init_trust();

        let mut connector = SslConnector::builder(SslMethod::dtls()).unwrap();

        if builder.srtp_profiles.len() > 0 {
            let srtp_line = builder
                .srtp_profiles
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            connector.set_tlsext_use_srtp(&srtp_line)?;
        }

        if let Some(ref identity) = builder.identity {
            connector.set_certificate(&(identity.0).0.cert)?;
            connector.set_private_key(&(identity.0).0.pkey)?;
            if let Some(ref chain) = (identity.0).0.chain {
                for cert in chain.iter().rev() {
                    connector.add_extra_chain_cert(cert.to_owned())?;
                }
            }
        }

//        supported_protocols(builder.min_protocol, builder.max_protocol, &mut connector)?;

        for cert in &builder.root_certificates {
            if let Err(err) = connector.cert_store_mut().add_cert((cert.0).0.clone()) {
                debug!("add_cert error: {:?}", err);
            }
        }

        #[cfg(target_os = "android")]
        load_android_root_certs(&mut connector)?;

        Ok(DtlsConnector {
            connector: connector.build(),
            use_sni: builder.use_sni,
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
            accept_invalid_certs: builder.accept_invalid_certs,
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let mut ssl = self
            .connector
            .configure()?
            .use_server_name_indication(self.use_sni)
            .verify_hostname(!self.accept_invalid_hostnames);
        if self.accept_invalid_certs {
            ssl.set_verify(SslVerifyMode::NONE);
        }

        let s = ssl.connect(domain, stream)?;
        Ok(DtlsStream(s))
    }
}

#[derive(Clone)]
pub struct DtlsAcceptor(SslAcceptor);

impl DtlsAcceptor {
    pub fn new(builder: &DtlsAcceptorBuilder) -> Result<DtlsAcceptor, Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;

        if builder.srtp_profiles.len() > 0 {
            let srtp_line = builder
                .srtp_profiles
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            acceptor.set_tlsext_use_srtp(&srtp_line)?;
        }

        acceptor.set_private_key(&(builder.identity.0).0.pkey)?;
        acceptor.set_certificate(&(builder.identity.0).0.cert)?;
        if let Some(ref chain) = (builder.identity.0).0.chain {
            for cert in chain.iter().rev() {
                acceptor.add_extra_chain_cert(cert.to_owned())?;
            }
        }
//        supported_protocols(builder.min_protocol, builder.max_protocol, &mut acceptor)?;

        Ok(DtlsAcceptor(acceptor.build()))
    }

    pub fn accept<S>(&self, stream: S) -> Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.accept(stream)?;
        Ok(DtlsStream(s))
    }
}

pub struct DtlsStream<S>(ssl::SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for DtlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> DtlsStream<S> {
    pub fn keying_material(&self, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; len];
        self.0
            .ssl()
            .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)?;
        Ok(buf)
    }

    pub fn selected_srtp_profile(&self) -> Result<Option<SrtpProfile>, Error> {
        match self.0.ssl().selected_srtp_profile() {
            Some(profile) => Ok(profile.name().parse()?).map(Some),
            None => Ok(None),
        }
    }

    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.0.ssl().pending())
    }

    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        Ok(self.0.ssl().peer_certificate().map(Certificate))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

impl<S: io::Read + io::Write> io::Read for DtlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for DtlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
