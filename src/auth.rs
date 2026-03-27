//! Authorization hooks for request dispatch.
//!
//! This module provides the protocol-level plumbing for
//! authorization decisions without embedding any policy rules.
//! The actual allow/deny policy belongs to the embedding
//! application (e.g. `REview`), not to `review-protocol`.
//!
//! # Design
//!
//! - [`ServiceId`](crate::service_id::ServiceId), not wire
//!   `RequestCode`, is the semantic key for authorization.
//! - [`PeerContext`] carries certificate-backed identity only;
//!   self-reported identity is not used at this layer.
//! - The default [`NoopAuthorizer`] permits all requests,
//!   ensuring backward compatibility when no policy is
//!   configured.

use std::fmt;

use crate::service_id::ServiceId;

/// Certificate-backed peer identity for authorization decisions.
///
/// Constructed from the TLS/QUIC connection certificate, not from
/// any self-reported data.  The embedding application populates
/// this when accepting a connection.
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

/// Error returned when authorization is denied.
///
/// Contains a stable, machine-readable denial without exposing
/// internal policy details.  The [`Display`](fmt::Display)
/// implementation produces a human-readable message suitable for
/// logging.
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

/// Authorization hook for request dispatch.
///
/// Implementations decide whether a given peer is allowed to
/// invoke a given service.  This trait is designed to be
/// implemented by the embedding application (e.g. `REview`), not
/// by `review-protocol` itself.
///
/// # Examples
///
/// ```ignore
/// use review_protocol::auth::{
///     AuthorizationError, Authorizer, PeerContext,
/// };
/// use review_protocol::service_id::ServiceId;
///
/// struct DenyAll;
///
/// impl Authorizer for DenyAll {
///     fn authorize(
///         &self,
///         _peer: &PeerContext,
///         _service: &ServiceId,
///     ) -> Result<(), AuthorizationError> {
///         Err(AuthorizationError::new("access denied"))
///     }
/// }
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

/// Default authorizer that permits all requests.
///
/// Used when no authorization policy is configured.  This ensures
/// backward compatibility: applications that do not provide an
/// [`Authorizer`] see no change in behavior.
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
