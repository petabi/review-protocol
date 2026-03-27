//! Authorization hooks for request dispatch.
//!
//! This module bridges certificate-backed peer identity
//! ([`PeerContext`]) with application-supplied authorization
//! policy ([`Authorizer`]).  The crate itself embeds no policy
//! rules—the actual allow/deny decisions belong to the embedding
//! application (e.g. `REview`), which implements the
//! [`Authorizer`] trait and passes it to the server's request
//! handler or the `node_*_authorized` methods on
//! [`server::Connection`](crate::server::Connection).
//!
//! # Design
//!
//! - [`ServiceId`](crate::service_id::ServiceId), not wire
//!   `RequestCode`, is the semantic key for authorization.
//!   Every authorization decision receives the logical
//!   `ServiceId` that identifies the requested operation
//!   (e.g. `"node.power.reboot"`).
//! - [`PeerContext`] carries certificate-backed identity only;
//!   self-reported identity is not used at this layer.
//! - The default [`NoopAuthorizer`] permits all requests,
//!   ensuring backward compatibility when no policy is
//!   configured.
//!
//! # How identity and policy interact
//!
//! 1. When a connection is established, the server constructs a
//!    [`PeerContext`] from the peer's TLS/QUIC certificate.
//! 2. For each request, the server resolves the wire request code
//!    to a [`ServiceId`](crate::service_id::ServiceId) and calls
//!    [`Authorizer::authorize`] with the peer's identity and the
//!    target service.
//! 3. If `authorize` returns `Ok(())`, the request is dispatched
//!    normally.  If it returns
//!    `Err(`[`AuthorizationError`]`)`, the server sends an error
//!    response and returns
//!    [`io::ErrorKind::PermissionDenied`](std::io::ErrorKind::PermissionDenied).

use std::fmt;

use crate::service_id::ServiceId;

/// Certificate-backed peer identity for authorization decisions.
///
/// A `PeerContext` is constructed from the TLS/QUIC connection
/// certificate—never from self-reported data—and represents the
/// authoritative identity of a connected peer.  The embedding
/// application populates this when accepting a connection and
/// passes it to the [`Authorizer`] on every request.
///
/// # Authoritative fields
///
/// All fields are derived from the peer's certificate:
///
/// - **[`name`](Self::name)** — peer identifier, typically the
///   certificate Common Name (CN) or the connection address.
///   This is the primary identity key.
/// - **[`subject`](Self::subject)** — the full certificate
///   subject DN (e.g. `"CN=agent-1,O=Acme"`), if available.
/// - **[`fingerprint`](Self::fingerprint)** — hex-encoded
///   certificate fingerprint, if available.
///
/// Because these values originate from the certificate, they
/// should be treated as the sole basis for identity in
/// [`Authorizer`] implementations.  Do not rely on
/// transport-layer metadata (IP addresses, port numbers) for
/// authorization decisions.
///
/// # Construction
///
/// Use the builder-style API to construct a context:
///
/// ```
/// use review_protocol::auth::PeerContext;
///
/// let peer = PeerContext::new("agent-1")
///     .with_subject("CN=agent-1,O=Acme")
///     .with_fingerprint("aa:bb:cc");
///
/// assert_eq!(peer.name(), "agent-1");
/// assert_eq!(peer.subject(), Some("CN=agent-1,O=Acme"));
/// ```
#[derive(Clone, Debug)]
pub struct PeerContext {
    /// Peer identifier string, typically derived from the
    /// certificate common name or connection address.
    name: String,
    /// Certificate subject (e.g. the full subject DN), if
    /// available from the peer certificate.
    subject: Option<String>,
    /// Certificate fingerprint (hex-encoded), if available.
    fingerprint: Option<String>,
}

impl PeerContext {
    /// Creates a new `PeerContext` with the given peer name.
    ///
    /// The name is typically derived from the certificate common
    /// name or the connection address.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            subject: None,
            fingerprint: None,
        }
    }

    /// Sets the certificate subject.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the certificate fingerprint (hex-encoded).
    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    /// Returns the peer name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the certificate subject, if available.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Returns the certificate fingerprint, if available.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

/// Error returned when an [`Authorizer`] denies a request or
/// encounters a runtime problem during policy evaluation.
///
/// An `AuthorizationError` should be returned for:
///
/// - **Explicit denials** — the policy determined that the peer
///   is not allowed to invoke the requested service.
/// - **Policy evaluation failures** — the authorizer could not
///   reach a decision (e.g. a backend database or network call
///   failed).  Returning an error in this case causes the server
///   to treat the request as denied rather than silently
///   allowing it.
///
/// The [`reason`](Self::reason) string should describe the
/// denial in machine-readable terms without leaking sensitive
/// certificate data (subject DNs, fingerprints, or private
/// extensions).  The [`Display`](fmt::Display) implementation
/// produces a human-readable message suitable for logging:
/// `"authorization denied: <reason>"`.
#[derive(Clone, Debug)]
pub struct AuthorizationError {
    reason: String,
}

impl AuthorizationError {
    /// Creates a new authorization error with the given reason.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Returns the denial reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authorization denied: {}", self.reason)
    }
}

impl std::error::Error for AuthorizationError {}

/// Application-supplied authorization policy for request
/// dispatch.
///
/// Implementations decide whether a given peer is allowed to
/// invoke a given service.  This trait is designed to be
/// implemented by the embedding application (e.g. `REview`), not
/// by `review-protocol` itself.
///
/// # When it is called
///
/// The server calls [`authorize`](Self::authorize) once per
/// incoming request, after resolving the wire request code to a
/// logical [`ServiceId`].  The two integration points are:
///
/// - **[`server::handler::handle_authorized`](crate::server::handler::handle_authorized)**
///   — checks every incoming request before dispatching it to
///   the [`Handler`](crate::server::handler::Handler).
/// - **`Connection::node_*_authorized` methods** (e.g.
///   [`node_power_authorized`](crate::server::Connection::node_power_authorized))
///   — checks authorization before sending an outgoing request
///   to an agent.
///
/// # Inputs
///
/// - **`peer`** ([`&PeerContext`](PeerContext)) — the
///   certificate-backed identity of the connected peer.
/// - **`service`** ([`&ServiceId`](crate::service_id::ServiceId))
///   — the logical service being requested.  Authorization is
///   keyed by `ServiceId`, so policies can target individual
///   operations (e.g. `"node.power.reboot"`) or entire service
///   families (e.g. `"node.power"`).
///
/// # Return semantics
///
/// - `Ok(())` — the request is **allowed** and will be
///   dispatched normally.
/// - `Err(`[`AuthorizationError`]`)` — the request is
///   **denied**.  The server sends an error response to the
///   client and returns
///   [`io::ErrorKind::PermissionDenied`](std::io::ErrorKind::PermissionDenied).
///   Use this for both explicit policy denials and transient
///   evaluation errors (e.g. unreachable policy backend); in
///   both cases the request will not proceed.
///
/// # Examples
///
/// A simple authorizer that allows only `"node.*"` services:
///
/// ```
/// use review_protocol::auth::{
///     AuthorizationError, Authorizer, PeerContext,
/// };
/// use review_protocol::service_id::ServiceId;
///
/// /// Allows only services whose family starts with `"node."`.
/// struct NodeOnly;
///
/// impl Authorizer for NodeOnly {
///     fn authorize(
///         &self,
///         _peer: &PeerContext,
///         service: &ServiceId,
///     ) -> Result<(), AuthorizationError> {
///         if service.family.starts_with("node.") {
///             Ok(())
///         } else {
///             Err(AuthorizationError::new(
///                 "only node services are allowed",
///             ))
///         }
///     }
/// }
/// ```
///
/// To register the authorizer with the server, pass it to
/// [`handle_authorized`](crate::server::handler::handle_authorized):
///
/// ```ignore
/// use review_protocol::auth::PeerContext;
/// use review_protocol::server::handler::handle_authorized;
///
/// // Inside a connection handler:
/// let peer = PeerContext::new("agent-1")
///     .with_subject("CN=agent-1");
/// let authorizer = NodeOnly;
/// handle_authorized(
///     &mut handler, &mut send, &mut recv,
///     &peer, &authorizer,
/// ).await?;
/// ```
pub trait Authorizer: Send + Sync {
    /// Checks whether `peer` is authorized to invoke `service`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError`] if the peer is not
    /// authorized to invoke the requested service.
    fn authorize(&self, peer: &PeerContext, service: &ServiceId) -> Result<(), AuthorizationError>;
}

/// Default authorizer that permits all requests unconditionally.
///
/// `NoopAuthorizer` always returns `Ok(())`, allowing every
/// request regardless of peer identity or target service.  It is
/// used internally by
/// [`handle`](crate::server::handler::handle) to preserve
/// backward compatibility when no authorization policy is
/// configured.
///
/// Use `NoopAuthorizer` when:
///
/// - Authorization is handled at the transport layer (e.g.
///   mutual TLS with a restricted CA) and no per-request policy
///   is needed.
/// - Running in a development or testing environment where all
///   requests should be allowed.
/// - Migrating incrementally: start with `NoopAuthorizer` and
///   replace it with a real policy once the application is
///   ready.
pub struct NoopAuthorizer;

impl Authorizer for NoopAuthorizer {
    fn authorize(
        &self,
        _peer: &PeerContext,
        _service: &ServiceId,
    ) -> Result<(), AuthorizationError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_id;

    #[test]
    fn peer_context_builder() {
        let ctx = PeerContext::new("agent-1")
            .with_subject("CN=agent-1")
            .with_fingerprint("aa:bb:cc");
        assert_eq!(ctx.name(), "agent-1");
        assert_eq!(ctx.subject(), Some("CN=agent-1"));
        assert_eq!(ctx.fingerprint(), Some("aa:bb:cc"));
    }

    #[test]
    fn peer_context_minimal() {
        let ctx = PeerContext::new("agent-2");
        assert_eq!(ctx.name(), "agent-2");
        assert_eq!(ctx.subject(), None);
        assert_eq!(ctx.fingerprint(), None);
    }

    #[test]
    fn noop_authorizer_allows_all() {
        let auth = NoopAuthorizer;
        let peer = PeerContext::new("any-peer");
        assert!(
            auth.authorize(&peer, &service_id::NODE_POWER_REBOOT)
                .is_ok()
        );
        assert!(
            auth.authorize(&peer, &service_id::SERVER_CONFIG_GET)
                .is_ok()
        );
        assert!(auth.authorize(&peer, &service_id::COMMON_ECHO).is_ok());
    }

    #[test]
    fn deny_authorizer() {
        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("denied"))
            }
        }

        let auth = DenyAll;
        let peer = PeerContext::new("any-peer");
        let err = auth
            .authorize(&peer, &service_id::NODE_POWER_REBOOT)
            .unwrap_err();
        assert_eq!(err.reason(), "denied");
        assert!(err.to_string().contains("authorization denied"));
    }

    #[test]
    fn selective_authorizer() {
        struct NodeOnly;
        impl Authorizer for NodeOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if service.family.starts_with("node.") {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("only node APIs allowed"))
                }
            }
        }

        let auth = NodeOnly;
        let peer = PeerContext::new("node-agent");
        assert!(
            auth.authorize(&peer, &service_id::NODE_POWER_REBOOT)
                .is_ok()
        );
        assert!(
            auth.authorize(&peer, &service_id::SERVER_CONFIG_GET)
                .is_err()
        );
    }

    #[test]
    fn authorization_error_display() {
        let err = AuthorizationError::new("policy violation");
        assert_eq!(err.to_string(), "authorization denied: policy violation");
    }
}
