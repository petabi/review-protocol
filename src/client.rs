//! Client-specific protocol implementation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use oinq::frame::{self, RecvError, SendError};
pub use oinq::message::{send_err, send_ok, send_request};
use quinn::{Connection, RecvStream, SendStream};

use crate::{AgentInfo, HandshakeError};

/// Sends a handshake request and processes the response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
pub async fn handshake(
    conn: &Connection,
    app_name: &str,
    app_version: &str,
    protocol_version: &str,
) -> Result<(SendStream, RecvStream), HandshakeError> {
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
    if let Err(e) = frame::send(&mut send, &mut buf, &agent_info).await {
        match e {
            SendError::SerializationFailure(e) => {
                return Err(HandshakeError::SerializationFailure(e))
            }
            SendError::MessageTooLarge(_) => return Err(HandshakeError::MessageTooLarge),
            SendError::WriteError(e) => return Err(HandshakeError::WriteError(e)),
        }
    }

    match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await {
        Ok(Ok(_)) => Ok((send, recv)),
        Ok(Err(e)) => Err(HandshakeError::IncompatibleProtocol(
            protocol_version.to_string(),
            e.to_string(),
        )),
        Err(RecvError::DeserializationFailure(_)) => Err(HandshakeError::InvalidMessage),
        Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly)) => {
            Err(HandshakeError::ConnectionClosed)
        }
        Err(RecvError::ReadError(quinn::ReadExactError::ReadError(e))) => {
            Err(HandshakeError::ReadError(e))
        }
    }
}
