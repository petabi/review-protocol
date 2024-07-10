//! Client-specific protocol implementation.

#[cfg(feature = "client")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(any(feature = "client", feature = "server"))]
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(feature = "client")]
use oinq::frame::{self};
#[cfg(feature = "client")]
pub use oinq::message::{send_err, send_ok, send_request};
#[cfg(feature = "client")]
use quinn::Connection;

#[cfg(feature = "client")]
use crate::{AgentInfo, HandshakeError};

/// Numeric representation of the message types.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub(crate) enum RequestCode {
    /// Start DNS filtering
    DnsStart = 1,

    /// Stop DNS filtering
    DnsStop = 2,

    /// Reboot the host
    Reboot = 4,

    /// Reload the configuration
    ReloadConfig = 6,

    /// Fetch the TI database and reload it
    ReloadTi = 5,

    /// Collect resource usage stats
    ResourceUsage = 7,

    /// Update the list of tor exit nodes
    TorExitNodeList = 8,

    /// Update the list of sampling policies
    SamplingPolicyList = 9,

    /// Update traffic filter rules
    ReloadFilterRule = 10,

    /// Get configuration
    GetConfig = 11,

    /// Set Configuration
    SetConfig = 12,

    /// Delete the list of sampling policies
    DeleteSamplingPolicy = 13,

    /// Update the list of Internal network
    InternalNetworkList = 14,

    /// Update the list of allow
    AllowList = 15,

    /// Update the list of block
    BlockList = 16,

    /// Request Echo (for ping)
    EchoRequest = 17,

    /// Update the list of trusted User-agent
    TrustedUserAgentList = 18,

    /// Update the list of trusted domains
    TrustedDomainList = 0,

    /// Collect process list
    ProcessList = 19,

    /// Update the semi-supervised models
    SemiSupervisedModels = 20,

    /// Shutdown the host
    Shutdown = 21,

    /// Unknown request
    #[num_enum(default)]
    Unknown = u32::MAX,
}

#[cfg(feature = "client")]
/// A builder for creating a new endpoint.
pub struct EndpointBuilder {
    addr: IpAddr,
    roots: rustls::RootCertStore,
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[cfg(feature = "client")]
impl EndpointBuilder {
    /// Creates a new builder with the given address, certificate, and key.
    ///
    /// Note that `addr` is the *local* address to bind to.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid.
    pub fn new(addr: IpAddr, cert: Vec<u8>, key: Vec<u8>) -> std::io::Result<Self> {
        Ok(Self {
            addr,
            roots: rustls::RootCertStore::empty(),
            cert: cert.into(),
            key: key
                .try_into()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        })
    }

    /// Adds root certificates to the certificate store.
    ///
    /// It reads certificates from the given reader, filtering out any PEM
    /// sections.
    ///
    /// # Errors
    ///
    /// Returns an error if the reader is invalid or the certificates are
    /// invalid.
    pub fn add_root_certs(&mut self, rd: &mut dyn std::io::BufRead) -> std::io::Result<&mut Self> {
        for cert in rustls_pemfile::certs(rd) {
            let cert = cert?;
            self.roots
                .add(cert)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(self)
    }

    /// Creates a new endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored TLS configuration is invalid.
    pub fn build(self) -> std::io::Result<Endpoint> {
        use std::sync::Arc;
        use std::time::Duration;

        const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);

        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.roots)
            .with_client_auth_cert(vec![self.cert], self.key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        ));
        config.transport_config(Arc::new(transport));

        let mut inner = quinn::Endpoint::client(SocketAddr::new(self.addr, 0))?;
        inner.set_default_client_config(config);
        Ok(Endpoint { inner })
    }
}

#[cfg(feature = "client")]
/// A protocol endpoint for outbound connections.
///
/// An endpoint may host many connections.
pub struct Endpoint {
    inner: quinn::Endpoint,
}

#[cfg(feature = "client")]
impl Endpoint {
    /// Connects to the server and performs a handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or the server requires a different
    /// protocol version.
    #[cfg(feature = "client")]
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
        app_name: &str,
        app_version: &str,
        protocol_version: &str,
    ) -> std::io::Result<Connection> {
        use std::io;

        let connecting = self
            .inner
            .connect(server_addr, server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let conn = connecting.await.map_err(|e| {
            // quinn (as of 0.11) provides automatic conversion from
            // `ConnectionError` to `ReadError`, and from `ReadError` to
            // `io::Error`. However, the conversion treats all `ConnectionError`
            // variants as `NotConnected`, which is too generic. We need to provide
            // more specific error messages.
            use quinn::ConnectionError;
            match e {
                ConnectionError::ApplicationClosed(e) => {
                    std::io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
                }
                ConnectionError::CidsExhausted => {
                    io::Error::new(io::ErrorKind::Other, "connection IDs exhausted")
                }
                ConnectionError::ConnectionClosed(e) => {
                    std::io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
                }
                ConnectionError::LocallyClosed => {
                    io::Error::new(io::ErrorKind::NotConnected, "locally closed")
                }
                ConnectionError::Reset => io::Error::from(io::ErrorKind::ConnectionReset),
                ConnectionError::TimedOut => io::Error::from(io::ErrorKind::TimedOut),
                ConnectionError::TransportError(e) => {
                    std::io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                }
                ConnectionError::VersionMismatch => {
                    io::Error::new(io::ErrorKind::ConnectionRefused, "version mismatch")
                }
            }
        })?;

        // A placeholder for the address of this agent. Will be replaced by the
        // server.
        //
        // TODO: This is unnecessary in handshake, and thus should be removed in the
        // future.
        let addr = if conn.remote_address().is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };

        let agent_info = AgentInfo {
            app_name: app_name.to_string(),
            version: app_version.to_string(),
            protocol_version: protocol_version.to_string(),
            addr,
        };

        let (mut send, mut recv) = conn.open_bi().await?;
        let mut buf = Vec::new();
        frame::send(&mut send, &mut buf, &agent_info).await?;
        match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await? {
            Ok(_) => Ok(conn),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("server requires protocol version {e}"),
            )),
        }
    }
}

/// Sends a handshake request and processes the response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
#[cfg(feature = "client")]
pub async fn handshake(
    conn: &Connection,
    app_name: &str,
    app_version: &str,
    protocol_version: &str,
) -> Result<(), HandshakeError> {
    // A placeholder for the address of this agent. Will be replaced by the
    // server.
    //
    // TODO: This is unnecessary in handshake, and thus should be removed in the
    // future.

    use crate::{handle_handshake_recv_io_error, handle_handshake_send_io_error};
    let addr = if conn.remote_address().is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };

    let agent_info = AgentInfo {
        app_name: app_name.to_string(),
        version: app_version.to_string(),
        protocol_version: protocol_version.to_string(),
        addr,
    };

    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = Vec::new();
    frame::send(&mut send, &mut buf, &agent_info)
        .await
        .map_err(handle_handshake_send_io_error)?;

    match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(HandshakeError::IncompatibleProtocol(
            protocol_version.to_string(),
            e.to_string(),
        )),
        Err(e) => Err(handle_handshake_recv_io_error(e)),
    }
}
