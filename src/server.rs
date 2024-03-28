//! Server-specific protocol implementation.

use std::net::SocketAddr;

use oinq::{
    frame,
    message::{send_err, send_ok},
};
use quinn::Connection;
use semver::{Version, VersionReq};

use crate::{AgentInfo, HandshakeError};

/// Processes a handshake message and sends a response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
///
/// # Panics
///
/// * panic if it failed to parse version requirement string.
pub async fn handshake(
    conn: &Connection,
    addr: SocketAddr,
    version_req: &str,
    highest_protocol_version: &str,
) -> Result<AgentInfo, HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(HandshakeError::ConnectionLost)?;
    let mut buf = Vec::new();
    let mut agent_info = frame::recv::<AgentInfo>(&mut recv, &mut buf)
        .await
        .map_err(|_| HandshakeError::InvalidMessage)?;
    agent_info.addr = addr;
    let version_req = VersionReq::parse(version_req).expect("valid version requirement");
    let protocol_version = Version::parse(&agent_info.protocol_version).map_err(|_| {
        HandshakeError::IncompatibleProtocol(
            agent_info.protocol_version.clone(),
            version_req.to_string(),
        )
    })?;
    if version_req.matches(&protocol_version) {
        let highest_protocol_version =
            Version::parse(highest_protocol_version).expect("valid semver");
        if protocol_version <= highest_protocol_version {
            send_ok(&mut send, &mut buf, highest_protocol_version.to_string())
                .await
                .map_err(HandshakeError::from)?;
            Ok(agent_info)
        } else {
            send_err(&mut send, &mut buf, &highest_protocol_version)
                .await
                .map_err(HandshakeError::from)?;
            send.finish().await.ok();
            Err(HandshakeError::IncompatibleProtocol(
                protocol_version.to_string(),
                version_req.to_string(),
            ))
        }
    } else {
        send_err(&mut send, &mut buf, version_req.to_string())
            .await
            .map_err(HandshakeError::from)?;
        send.finish().await.ok();
        Err(HandshakeError::IncompatibleProtocol(
            protocol_version.to_string(),
            version_req.to_string(),
        ))
    }
}
