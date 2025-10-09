//! # review-protocol
//!
//! This crate defines the wire and API surface used to interact with
//! review nodes and services. It focuses on a small set of long-lived
//! abstractions that embedding applications should rely on when
//! integrating with the review protocol.
//!
//! ## Public modules
//!
//! - [`client`] – Client-side utilities and typed clients for calling
//!   review services.
//! - [`server`] – Server-side helpers, service wiring, and the
//!   `server::Connection` API used to issue requests to agents.
//!   The [`server::node`] module provides the recommended
//!   service-family entry point for node operations via
//!   [`Connection::node()`](server::Connection::node).
//! - [`types`] – Shared types used across the protocol surface.
//! - [`service_id`] – Definitions and helpers for [`ServiceId`], the
//!   key used to scope authorization and identify services.
//! - [`auth`] – Authorization-related types and helpers.
//! - [`protocol_error`] – Semantic error categories
//!   ([`ProtocolErrorKind`]) for internal classification.
//!
//! ## Node API family
//!
//! The preferred public terminology for the APIs that operate on an
//! agent/node is **node**. The node API family groups the endpoints and
//! types that model long-lived interactions with a managed node.
//! Embedding applications should treat the node APIs as the stable
//! surface for node-centric operations. Item-level docs on the
//! node-related modules provide concrete guidance and examples.
//!
//! ## Compatibility with legacy flat APIs
//!
//! Historically some functionality was exposed through legacy, flatter
//! endpoints (for example: reboot or resource-usage endpoints). Those
//! legacy endpoints remain available for compatibility and may overlap
//! with the node API family. For new integrations prefer the node APIs,
//! but be aware the compatibility surface exists and may be relied upon
//! by existing consumers.
//!
//! ## Authorization model
//!
//! Authorization in this crate assumes certificate-backed peer identity
//! is available at request time. The embedding application provides
//! `PeerContext` at each authorization decision point—both when
//! handling incoming requests and when issuing authorized calls to
//! agents (e.g., the `node_*_authorized` methods on
//! `server::Connection`). The crate does not embed a policy engine:
//! authorization decisions are made by the embedding application using
//! the identity and the [`ServiceId`] to scope policies. In short:
//!
//! 1. Peer identity is certificate-backed and surfaced as
//!    `PeerContext`.
//! 2. Policy is supplied and enforced by the embedding application
//!    outside this crate.
//! 3. Authorization is keyed by [`ServiceId`] so policies can be
//!    targeted to individual services.
//!
//! ### Richer context with `AuthorizationContext`
//!
//! [`AuthorizationContext`] extends the authorization model with
//! optional authenticated metadata (agent kind, roles, protocol
//! version, and application-supplied attributes) without changing
//! the wire format or breaking existing code.
//! [`ServiceId`] remains **separate** from `AuthorizationContext`
//! so the operation being authorized is always explicit.
//!
//! Existing [`Authorizer`] implementations continue to work
//! unchanged.  To use them where an [`AuthorizerV2`] is required,
//! wrap with [`AuthorizerV2Adapter`].  New code that needs the
//! richer metadata can implement [`AuthorizerV2`] directly.
//! See [`auth::AuthorizationContext`] for construction examples
//! and migration guidance.
//!
//! **Compatibility:** policy engines remain outside
//! `review-protocol`.  This crate provides identity plumbing and
//! dispatch hooks; the actual allow/deny logic belongs to the
//! embedding application.  Existing `PeerContext` flows continue
//! to work unchanged — no migration is required until the
//! application opts in to the richer context.
//!
//! [`AuthorizationContext`]: auth::AuthorizationContext
//! [`Authorizer`]: auth::Authorizer
//! [`AuthorizerV2`]: auth::AuthorizerV2
//! [`AuthorizerV2Adapter`]: auth::AuthorizerV2Adapter
//!
//! ## Further reading
//!
//! Release-specific rollout choreography and sequencing are documented
//! in `CHANGELOG.md`. Item-level docs on each module contain
//! implementation detail.
//!
//! [`ServiceId`]: crate::service_id::ServiceId

#[cfg(any(feature = "client", feature = "server"))]
pub mod auth;
pub mod client;
#[cfg(feature = "client")]
pub mod frame;
pub mod protocol_error;
#[cfg(feature = "client")]
pub mod request;
pub mod server;
#[cfg(any(feature = "client", feature = "server"))]
pub mod service_id;
#[cfg(any(
    feature = "test-support",
    all(test, any(feature = "client", feature = "server"))
))]
#[doc(hidden)]
pub mod test;
pub mod types;

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
pub use server::EventStreamHandler;
#[cfg(any(feature = "client", feature = "server"))]
use thiserror::Error;

pub use self::protocol_error::ProtocolErrorKind;
use crate::types::Status;

/// The error type for a handshake failure.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("connection closed by peer")]
    ConnectionClosed,
    #[error("connection lost")]
    ConnectionLost(#[from] quinn::ConnectionError),
    #[error("cannot receive a message: {0}")]
    ReadError(std::io::Error),
    #[error("cannot send a message")]
    WriteError(std::io::Error),
    #[error("arguments are too long")]
    MessageTooLarge,
    #[error("invalid message")]
    InvalidMessage,
    #[error("protocol version {0} is not supported; version {1} is required")]
    IncompatibleProtocol(String, String),
}

#[cfg(feature = "server")]
fn handle_handshake_send_io_error(e: std::io::Error) -> HandshakeError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        HandshakeError::MessageTooLarge
    } else {
        HandshakeError::WriteError(e)
    }
}

#[cfg(feature = "server")]
fn handle_handshake_recv_io_error(e: std::io::Error) -> HandshakeError {
    match e.kind() {
        std::io::ErrorKind::InvalidData => HandshakeError::InvalidMessage,
        std::io::ErrorKind::UnexpectedEof => HandshakeError::ConnectionClosed,
        _ => HandshakeError::ReadError(e),
    }
}

/// Properties of an agent.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentInfo {
    pub app_name: String,
    pub version: String,
    pub protocol_version: String,
    pub addr: SocketAddr,
    pub status: Status,
}

/// Sends a unary request and returns the response.
///
/// # Errors
///
/// Returns an error if there was a problem sending the request or receiving the
/// response.
#[cfg(any(feature = "client", feature = "server"))]
pub async fn unary_request<I, O>(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: u32,
    input: I,
) -> std::io::Result<O>
where
    I: serde::Serialize,
    O: serde::de::DeserializeOwned,
{
    let mut buf = vec![];
    oinq::message::send_request(send, &mut buf, code, input).await?;

    oinq::frame::recv(recv, &mut buf).await
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::test::{TOKEN, channel};

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const APP_NAME: &str = "oinq";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                APP_NAME,
                APP_VERSION,
                PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let agent_info = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(agent_info.app_name, APP_NAME);
        assert_eq!(agent_info.version, APP_VERSION);
        assert_eq!(agent_info.protocol_version, PROTOCOL_VERSION);

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_version_incompatible_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const APP_NAME: &str = "oinq";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                APP_NAME,
                APP_VERSION,
                PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            &format!("<{PROTOCOL_VERSION}"),
            PROTOCOL_VERSION,
        )
        .await;

        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_incompatible_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const APP_NAME: &str = "oinq";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let version_req = semver::VersionReq::parse(&format!(">={PROTOCOL_VERSION}")).unwrap();
        let mut highest_version = semver::Version::parse(PROTOCOL_VERSION).unwrap();
        highest_version.patch += 1;
        let mut protocol_version = highest_version.clone();
        protocol_version.minor += 1;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                APP_NAME,
                APP_VERSION,
                &protocol_version.to_string(),
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            &version_req.to_string(),
            &highest_version.to_string(),
        )
        .await;

        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }
}
