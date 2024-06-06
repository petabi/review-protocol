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
