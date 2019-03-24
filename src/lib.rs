//! An abstraction over OpenSSL DTLS implementations.

extern crate futures;
#[macro_use]
extern crate tokio_io;
extern crate bytes;

use core::fmt::Write;
use openssl::hash::MessageDigest;
use std::any::Any;
use std::error;
use std::fmt;
use std::io;
use std::result;
use std::str::FromStr;

#[macro_use]
extern crate log;

#[path = "imp/openssl.rs"]
mod imp;

#[cfg(test)]
mod test;

pub mod tokio_dtls;

/// A typedef of the result-type returned by many methods.
pub type Result<T> = result::Result<T, Error>;

/// An error returned from the DTLS implementation.
pub struct Error(imp::Error);

impl error::Error for Error {
    fn description(&self) -> &str {
        error::Error::description(&self.0)
    }

    fn cause(&self) -> Option<&error::Error> {
        error::Error::cause(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl From<imp::Error> for Error {
    fn from(err: imp::Error) -> Error {
        Error(err)
    }
}

/// A cryptographic identity.
///
/// An identity is an X509 certificate along with its corresponding private key and chain of certificates to a trusted
/// root.
pub struct Identity(imp::Identity);

impl Identity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that should be sent to clients to allow them to build a chain to a trusted
    /// root. The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    pub fn from_pkcs12(der: &[u8], password: &str) -> Result<Identity> {
        let identity = imp::Identity::from_pkcs12(der, password)?;
        Ok(Identity(identity))
    }

    pub fn certificate(&self) -> Certificate {
        Certificate(self.0.certificate())
    }
}

/// An X509 certificate.
#[derive(Clone)]
pub struct Certificate(imp::Certificate);

impl Certificate {
    /// Parses a DER-formatted X509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Certificate> {
        let cert = imp::Certificate::from_der(der)?;
        Ok(Certificate(cert))
    }

    /// Parses a PEM-formatted X509 certificate.
    pub fn from_pem(der: &[u8]) -> Result<Certificate> {
        let cert = imp::Certificate::from_pem(der)?;
        Ok(Certificate(cert))
    }

    /// Returns the DER-encoded representation of this certificate.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = self.0.to_der()?;
        Ok(der)
    }

    pub fn fingerprint(
        &self,
        signature_algorithm: crate::SignatureAlgorithm,
    ) -> Result<crate::CertificateFingerprint> {
        let fingerprint = self.0.fingerprint(signature_algorithm)?;
        Ok(fingerprint)
    }
}

/// A DTLS stream which has been interrupted midway through the handshake process.
pub struct MidHandshakeDtlsStream<S>(imp::MidHandshakeDtlsStream<S>);

impl<S> fmt::Debug for MidHandshakeDtlsStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> MidHandshakeDtlsStream<S>
where
    S: io::Read + io::Write,
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Restarts the handshake process.
    ///
    /// If the handshake completes successfully then the negotiated stream is
    /// returned. If there is a problem, however, then an error is returned.
    /// Note that the error may not be fatal. For example if the underlying
    /// stream is an asynchronous one then `HandshakeError::WouldBlock` may
    /// just mean to wait for more I/O to happen later.
    pub fn handshake(self) -> result::Result<DtlsStream<S>, HandshakeError<S>> {
        match self.0.handshake() {
            Ok(s) => Ok(DtlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    WouldBlock(MidHandshakeDtlsStream<S>),
}

impl<S> error::Error for HandshakeError<S>
where
    S: Any + fmt::Debug,
{
    fn description(&self) -> &str {
        "handshake error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            HandshakeError::Failure(ref e) => Some(e),
            HandshakeError::WouldBlock(_) => None,
        }
    }
}

impl<S> fmt::Display for HandshakeError<S>
where
    S: Any + fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HandshakeError::Failure(ref e) => fmt::Display::fmt(e, fmt),
            HandshakeError::WouldBlock(_) => fmt.write_str("the handshake process was interrupted"),
        }
    }
}

impl<S> From<imp::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: imp::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            imp::HandshakeError::Failure(e) => HandshakeError::Failure(Error(e)),
            imp::HandshakeError::WouldBlock(s) => {
                HandshakeError::WouldBlock(MidHandshakeDtlsStream(s))
            }
        }
    }
}

#[derive(Hash, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum SrtpProfile {
    Aes128CmSha180,
    Aes128CmSha132,
    AeadAes128Gcm,
    AeadAes256Gcm,
    #[doc(hidden)]
    __Nonexhaustive,
}

/// DDTLS protocol versions.
#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    Dtlsv10,
    Dtlsv12,
    #[doc(hidden)]
    __NonExhaustive,
}

impl ToString for SrtpProfile {
    fn to_string(&self) -> String {
        match self {
            SrtpProfile::Aes128CmSha180 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::Aes128CmSha132 => "SRTP_AES128_CM_SHA1_32",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            SrtpProfile::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
            SrtpProfile::__Nonexhaustive => unreachable!(),
        }
        .to_string()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum SrtpProfileError {
    BadProfile,
}

impl error::Error for SrtpProfileError {
    fn description(&self) -> &str {
        match *self {
            SrtpProfileError::BadProfile => "bad SRTP profile",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl fmt::Display for SrtpProfileError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SrtpProfileError::BadProfile => fmt.write_str("bad SRTP profile"),
        }
    }
}

impl FromStr for SrtpProfile {
    type Err = SrtpProfileError;

    fn from_str(s: &str) -> result::Result<Self, SrtpProfileError> {
        match s {
            "SRTP_AES128_CM_SHA1_80" => Ok(SrtpProfile::Aes128CmSha180),
            "SRTP_AES128_CM_SHA1_32" => Ok(SrtpProfile::Aes128CmSha132),
            "SRTP_AEAD_AES_128_GCM" => Ok(SrtpProfile::AeadAes128Gcm),
            "SRTP_AEAD_AES_256_GCM" => Ok(SrtpProfile::AeadAes256Gcm),
            _ => Err(SrtpProfileError::BadProfile),
        }
    }
}

/// A builder for `DtlsConnector`s.
pub struct DtlsConnectorBuilder {
    identity: Option<Identity>,
    srtp_profiles: Vec<SrtpProfile>,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
    root_certificates: Vec<Certificate>,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    use_sni: bool,
}

impl DtlsConnectorBuilder {
    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(&mut self, identity: Identity) -> &mut DtlsConnectorBuilder {
        self.identity = Some(identity);
        self
    }

    /// TODO
    ///
    pub fn add_srtp_profile(&mut self, profile: SrtpProfile) -> &mut DtlsConnectorBuilder {
        self.srtp_profiles.push(profile);
        self
    }

    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Dtlsv10)`.
    pub fn min_protocol_version(
        &mut self,
        protocol: Option<Protocol>,
    ) -> &mut DtlsConnectorBuilder {
        self.min_protocol = protocol;
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(
        &mut self,
        protocol: Option<Protocol>,
    ) -> &mut DtlsConnectorBuilder {
        self.max_protocol = protocol;
        self
    }

    /// Adds a certificate to the set of roots that the connector will trust.
    ///
    /// The connector will use the system's trust root by default. This method can be used to add
    /// to that set when communicating with servers not trusted by the system.
    ///
    /// Defaults to an empty set.
    pub fn add_root_certificate(&mut self, cert: Certificate) -> &mut DtlsConnectorBuilder {
        self.root_certificates.push(cert);
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid certificates are trusted, *any*
    /// certificate for *any* site will be trusted for use. This includes expired certificates. This introduces
    /// significant vulnerabilities, and should only be used as a last resort.
    pub fn danger_accept_invalid_certs(
        &mut self,
        accept_invalid_certs: bool,
    ) -> &mut DtlsConnectorBuilder {
        self.accept_invalid_certs = accept_invalid_certs;
        self
    }

    /// Controls the use of Server Name Indication (SNI).
    ///
    /// Defaults to `true`.
    pub fn use_sni(&mut self, use_sni: bool) -> &mut DtlsConnectorBuilder {
        self.use_sni = use_sni;
        self
    }

    /// Controls the use of hostname verification.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid hostnames are trusted, *any* valid
    /// certificate for *any* site will be trusted for use. This introduces significant vulnerabilities, and should
    /// only be used as a last resort.
    pub fn danger_accept_invalid_hostnames(
        &mut self,
        accept_invalid_hostnames: bool,
    ) -> &mut DtlsConnectorBuilder {
        self.accept_invalid_hostnames = accept_invalid_hostnames;
        self
    }

    /// Creates a new `DtlsConnector`.
    pub fn build(&self) -> result::Result<DtlsConnector, Error> {
        let connector = imp::DtlsConnector::new(self)?;
        Ok(DtlsConnector(connector))
    }
}

/// A builder for client-side DTLS connections.
#[derive(Clone)]
pub struct DtlsConnector(imp::DtlsConnector);

impl DtlsConnector {
    /// Returns a new connector with default settings.
    pub fn new() -> Result<DtlsConnector> {
        DtlsConnector::builder().build()
    }

    /// Returns a new builder for a `DtlsConnector`.
    pub fn builder() -> DtlsConnectorBuilder {
        DtlsConnectorBuilder {
            identity: None,
            srtp_profiles: vec![],
            min_protocol: Some(Protocol::Dtlsv10),
            max_protocol: None,
            root_certificates: vec![],
            use_sni: true,
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        }
    }

    /// Initiates a DTLS handshake.
    ///
    /// The provided domain will be used for both SNI and certificate hostname
    /// validation.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    ///
    /// The domain is ignored if both SNI and hostname verification are
    /// disabled.
    pub fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> result::Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.connect(domain, stream)?;
        Ok(DtlsStream(s))
    }

    /// Convert this `DtlsConnector` to tokio variant
    pub fn into_async(self) -> tokio_dtls::DtlsConnector {
        tokio_dtls::DtlsConnector { inner: self }
    }
}

/// A builder for `DtlsAcceptor`s.
pub struct DtlsAcceptorBuilder {
    identity: Identity,
    srtp_profiles: Vec<SrtpProfile>,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
}

impl DtlsAcceptorBuilder {
    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Dtlsv10)`.
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut DtlsAcceptorBuilder {
        self.min_protocol = protocol;
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut DtlsAcceptorBuilder {
        self.max_protocol = protocol;
        self
    }

    /// TODO
    ///
    pub fn add_srtp_profile(&mut self, profile: SrtpProfile) -> &mut DtlsAcceptorBuilder {
        self.srtp_profiles.push(profile);
        self
    }

    /// Creates a new `DtlsAcceptor`.
    pub fn build(&self) -> Result<DtlsAcceptor> {
        let acceptor = imp::DtlsAcceptor::new(self)?;
        Ok(DtlsAcceptor(acceptor))
    }
}

/// A builder for server-side DTLS connections.
#[derive(Clone)]
pub struct DtlsAcceptor(imp::DtlsAcceptor);

impl DtlsAcceptor {
    /// Creates a acceptor with default settings.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn new(identity: Identity) -> Result<DtlsAcceptor> {
        DtlsAcceptor::builder(identity).build()
    }

    /// Returns a new builder for a `DtlsAcceptor`.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn builder(identity: Identity) -> DtlsAcceptorBuilder {
        DtlsAcceptorBuilder {
            identity,
            srtp_profiles: vec![],
            min_protocol: Some(Protocol::Dtlsv10),
            max_protocol: None,
        }
    }

    /// Initiates a DTLS handshake.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn accept<S>(&self, stream: S) -> result::Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        match self.0.accept(stream) {
            Ok(s) => Ok(DtlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }

    /// Convert this `DtlsAcceptor` to tokio variant
    pub fn into_async(self) -> tokio_dtls::DtlsAcceptor {
        tokio_dtls::DtlsAcceptor { inner: self }
    }
}

/// A stream managing a DTLS session.
pub struct DtlsStream<S>(imp::DtlsStream<S>);

impl<S: fmt::Debug> fmt::Debug for DtlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> DtlsStream<S> {
    /// Export keying material
    pub fn keying_material(&self, len: usize) -> Result<Vec<u8>> {
        Ok(self.0.keying_material(len)?)
    }

    /// Export keying material
    pub fn selected_srtp_profile(&self) -> Result<Option<SrtpProfile>> {
        Ok(self.0.selected_srtp_profile()?)
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Returns the peer's leaf certificate, if available.
    pub fn peer_certificate(&self) -> Result<Option<Certificate>> {
        Ok(self.0.peer_certificate()?.map(Certificate))
    }

    /// Shuts down the DTLS session.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Clone, Debug)]
pub struct CertificateFingerprint {
    bytes: Vec<u8>,
    signature_algorithm: SignatureAlgorithm,
}

impl ToString for CertificateFingerprint {
    fn to_string(&self) -> String {
        let mut s = match self.signature_algorithm {
            SignatureAlgorithm::Sha1 => "sha-1 ",
            SignatureAlgorithm::Sha256 => "sha-256 ",
        }
        .to_string();

        for b in &self.bytes {
            s.write_fmt(format_args!("{:02X}:", b)).unwrap();
        }

        if s.len() > 0 {
            s.pop(); //remove last ':'
        }

        s
    }
}

impl CertificateFingerprint {
    pub fn new(bytes: Vec<u8>, signature_algorithm: SignatureAlgorithm) -> CertificateFingerprint {
        CertificateFingerprint {
            bytes,
            signature_algorithm,
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

fn _check_kinds() {
    use std::net::TcpStream;

    fn is_sync<T: Sync>() {}
    fn is_send<T: Send>() {}
    is_sync::<Error>();
    is_send::<Error>();
    is_sync::<DtlsConnectorBuilder>();
    is_send::<DtlsConnectorBuilder>();
    is_sync::<DtlsConnector>();
    is_send::<DtlsConnector>();
    is_sync::<DtlsAcceptorBuilder>();
    is_send::<DtlsAcceptorBuilder>();
    is_sync::<DtlsAcceptor>();
    is_send::<DtlsAcceptor>();
    is_sync::<DtlsStream<TcpStream>>();
    is_send::<DtlsStream<TcpStream>>();
    is_sync::<MidHandshakeDtlsStream<TcpStream>>();
    is_send::<MidHandshakeDtlsStream<TcpStream>>();
}
