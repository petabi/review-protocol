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
//! - [`ServiceId`], not wire
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
//!    to a [`ServiceId`] and calls
//!    [`Authorizer::authorize`] with the peer's identity and the
//!    target service.
//! 3. If `authorize` returns `Ok(())`, the request is dispatched
//!    normally.  If it returns
//!    `Err(`[`AuthorizationError`]`)`, the server sends an error
//!    response and returns
//!    [`io::ErrorKind::PermissionDenied`](std::io::ErrorKind::PermissionDenied).

use std::collections::HashMap;
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

/// Certificate-backed identity extracted from a [`PeerContext`].
///
/// `PeerIdentity` captures the subset of [`PeerContext`] fields
/// that represent the authenticated identity of a peer: the peer
/// name (typically the certificate CN), the optional certificate
/// subject DN, and the optional certificate fingerprint.
///
/// This type is used as the `peer_identity` field of
/// [`AuthorizationContext`] so that authorization decisions can
/// reference the identity without carrying the full
/// [`PeerContext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Peer identifier string, typically derived from the
    /// certificate common name or connection address.
    name: String,
    /// Full certificate subject DN (e.g. `"CN=agent-1,O=Acme"`),
    /// if available from the peer certificate.
    subject: Option<String>,
    /// Hex-encoded certificate fingerprint, if available.
    fingerprint: Option<String>,
}

impl PeerIdentity {
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

impl From<&PeerContext> for PeerIdentity {
    fn from(peer: &PeerContext) -> Self {
        Self {
            name: peer.name().to_owned(),
            subject: peer.subject().map(str::to_owned),
            fingerprint: peer.fingerprint().map(str::to_owned),
        }
    }
}

/// The kind of agent or component that authenticated.
///
/// `AgentKind` is an optional classifier attached to an
/// [`AuthorizationContext`].  It lets authorization policies
/// distinguish between different roles in the system without
/// inspecting certificate fields directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentKind {
    /// An agent managed by the review system.
    Agent,
    /// A proxy or relay acting on behalf of another peer.
    Proxy,
    /// An application-defined kind not covered by the standard
    /// variants.
    Other(String),
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent => f.write_str("agent"),
            Self::Proxy => f.write_str("proxy"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

/// Protocol and capability metadata for an authenticated peer.
///
/// `ProtocolMetadata` is an optional extension attached to an
/// [`AuthorizationContext`].  It carries version and capability
/// information that the embedding application may use to make
/// policy decisions (e.g. denying requests from outdated agents).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolMetadata {
    /// Protocol version string (e.g. `"0.17.0"`), if known.
    pub version: Option<String>,
    /// Capability tokens advertised by the peer.
    pub capabilities: Vec<String>,
}

/// Authenticated peer metadata for richer authorization decisions.
///
/// `AuthorizationContext` bundles certificate-backed
/// [`PeerIdentity`] with optional embedding-application-supplied
/// metadata (agent kind, roles, protocol information, and an
/// arbitrary attribute map).  It is designed as an **additive,
/// non-breaking** extension alongside the existing [`PeerContext`]
/// and [`ServiceId`] types.
///
/// # Relationship to `PeerContext` and `ServiceId`
///
/// - [`PeerContext`] remains the primary type for establishing
///   certificate-backed identity at connection time.
///   `AuthorizationContext` **derives** its [`peer_identity`]
///   from a `PeerContext` via [`From<&PeerContext>`] or the
///   explicit constructors.
/// - [`ServiceId`] identifies the
///   operation being requested and is **not** included in
///   `AuthorizationContext`.  Authorization decisions should
///   receive `AuthorizationContext` and `ServiceId` as separate
///   inputs so that the operation being authorized is always
///   explicit.
///
/// [`peer_identity`]: Self::peer_identity
///
/// # Security: authenticated-only fields
///
/// **Every field in `AuthorizationContext` must be populated from
/// authenticated sources only** — the peer's TLS/QUIC certificate
/// or the embedding application's own trusted inputs.  The
/// constructors deliberately accept only [`PeerContext`] (which
/// is itself certificate-backed) and explicit parameters that the
/// embedding application provides from its trusted context.
///
/// The [`attributes`](Self::attributes) map is an explicit
/// extension point for embedding-application-supplied metadata.
/// **Do not populate it from request bodies, query parameters, or
/// any other untrusted payload.**  If an embedding application
/// needs to carry user-supplied attributes, it must authenticate
/// and validate them before placing them in this map.
///
/// # Construction
///
/// Use [`from_peer_context`](Self::from_peer_context) for a
/// minimal context derived from a certificate, or
/// [`from_authenticated_inputs`](Self::from_authenticated_inputs)
/// when the embedding application can supply additional
/// authenticated metadata:
///
/// ```
/// use review_protocol::auth::{
///     AuthorizationContext, PeerContext,
/// };
///
/// let peer = PeerContext::new("agent-1")
///     .with_subject("CN=agent-1,O=Acme")
///     .with_fingerprint("aa:bb:cc");
///
/// // Minimal context — only certificate identity.
/// let ctx = AuthorizationContext::from_peer_context(&peer);
/// assert_eq!(ctx.peer_identity().name(), "agent-1");
/// assert!(ctx.agent_kind().is_none());
/// ```
///
/// # Migration guidance
///
/// `AuthorizationContext` is additive.  Existing code that passes
/// `&PeerContext` to [`Authorizer::authorize`] continues to work
/// unchanged.  When an embedding application is ready to supply
/// richer metadata, it can construct an `AuthorizationContext` and
/// pass it alongside the `ServiceId` to its own policy layer.
#[derive(Clone, Debug)]
pub struct AuthorizationContext {
    /// Certificate-backed identity of the peer.
    peer_identity: PeerIdentity,
    /// Optional classifier for the kind of agent or component.
    agent_kind: Option<AgentKind>,
    /// Optional role strings for policy evaluation.
    roles: Option<Vec<String>>,
    /// Optional protocol version and capability metadata.
    protocol_metadata: Option<ProtocolMetadata>,
    /// Embedding-application-supplied authenticated metadata.
    ///
    /// **Populate only from authenticated channels.**  Do not
    /// populate from request bodies, headers, or any untrusted
    /// source unless those inputs have been authenticated at
    /// connection setup.
    attributes: Option<HashMap<String, String>>,
}

impl AuthorizationContext {
    /// Creates an `AuthorizationContext` from a [`PeerContext`],
    /// populating only the certificate-backed identity.  All
    /// optional fields are set to `None`.
    ///
    /// This is the recommended constructor when the embedding
    /// application has no additional authenticated metadata to
    /// supply.
    #[must_use]
    pub fn from_peer_context(peer: &PeerContext) -> Self {
        Self {
            peer_identity: PeerIdentity::from(peer),
            agent_kind: None,
            roles: None,
            protocol_metadata: None,
            attributes: None,
        }
    }

    /// Creates an `AuthorizationContext` from a [`PeerContext`]
    /// and additional authenticated inputs supplied by the
    /// embedding application.
    ///
    /// All parameters beyond `peer` are optional and should come
    /// from **authenticated sources only** (e.g. server-side
    /// configuration, connection-setup metadata, or verified
    /// claims).  Never populate these from untrusted request
    /// payloads.
    #[must_use]
    pub fn from_authenticated_inputs(
        peer: &PeerContext,
        agent_kind: Option<AgentKind>,
        roles: Option<Vec<String>>,
        protocol_metadata: Option<ProtocolMetadata>,
        attributes: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            peer_identity: PeerIdentity::from(peer),
            agent_kind,
            roles,
            protocol_metadata,
            attributes,
        }
    }

    /// Returns the certificate-backed identity of the peer.
    #[must_use]
    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer_identity
    }

    /// Returns the agent kind, if set.
    #[must_use]
    pub fn agent_kind(&self) -> Option<&AgentKind> {
        self.agent_kind.as_ref()
    }

    /// Returns the roles, if set.
    #[must_use]
    pub fn roles(&self) -> Option<&[String]> {
        self.roles.as_deref()
    }

    /// Returns the protocol metadata, if set.
    #[must_use]
    pub fn protocol_metadata(&self) -> Option<&ProtocolMetadata> {
        self.protocol_metadata.as_ref()
    }

    /// Returns the authenticated attributes map, if set.
    #[must_use]
    pub fn attributes(&self) -> Option<&HashMap<String, String>> {
        self.attributes.as_ref()
    }
}

impl From<&PeerContext> for AuthorizationContext {
    fn from(peer: &PeerContext) -> Self {
        Self::from_peer_context(peer)
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

    /// Returns the [`ProtocolErrorKind`] for this error.
    ///
    /// Authorization errors always map to
    /// [`ProtocolErrorKind::Forbidden`].
    ///
    /// [`ProtocolErrorKind`]: crate::protocol_error::ProtocolErrorKind
    /// [`ProtocolErrorKind::Forbidden`]: crate::protocol_error::ProtocolErrorKind::Forbidden
    #[must_use]
    pub fn kind(&self) -> crate::protocol_error::ProtocolErrorKind {
        crate::protocol_error::ProtocolErrorKind::from(self)
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
/// - **[`server::handler::handle_authorized`](crate::server::handle_authorized)**
///   — checks every incoming request before dispatching it to
///   the [`Handler`](crate::server::Handler).
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
/// [`handle_authorized`](crate::server::handle_authorized):
///
/// ```ignore
/// use review_protocol::auth::PeerContext;
/// use review_protocol::server::handle_authorized;
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
/// [`handle`](crate::server::handle) to preserve
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
    fn authorization_context_from_peer_context() {
        let peer = PeerContext::new("agent-1")
            .with_subject("CN=agent-1,O=Acme")
            .with_fingerprint("aa:bb:cc");
        let ctx = AuthorizationContext::from_peer_context(&peer);

        assert_eq!(ctx.peer_identity().name(), "agent-1");
        assert_eq!(ctx.peer_identity().subject(), Some("CN=agent-1,O=Acme"));
        assert_eq!(ctx.peer_identity().fingerprint(), Some("aa:bb:cc"));
        assert!(ctx.agent_kind().is_none());
        assert!(ctx.roles().is_none());
        assert!(ctx.protocol_metadata().is_none());
        assert!(ctx.attributes().is_none());
    }

    #[test]
    fn authorization_context_from_trait() {
        let peer = PeerContext::new("agent-2");
        let ctx = AuthorizationContext::from(&peer);
        assert_eq!(ctx.peer_identity().name(), "agent-2");
        assert!(ctx.agent_kind().is_none());
    }

    #[test]
    fn authorization_context_with_authenticated_inputs() {
        let peer = PeerContext::new("proxy-1").with_subject("CN=proxy-1,O=Acme");

        let mut attrs = HashMap::new();
        attrs.insert("tenant".to_owned(), "acme-corp".to_owned());

        let meta = ProtocolMetadata {
            version: Some("0.17.0".to_owned()),
            capabilities: vec!["streaming".to_owned()],
        };

        let ctx = AuthorizationContext::from_authenticated_inputs(
            &peer,
            Some(AgentKind::Proxy),
            Some(vec!["admin".to_owned(), "reader".to_owned()]),
            Some(meta),
            Some(attrs),
        );

        assert_eq!(ctx.peer_identity().name(), "proxy-1");
        assert_eq!(ctx.agent_kind(), Some(&AgentKind::Proxy));
        assert_eq!(ctx.roles().map(<[String]>::len), Some(2));
        let meta = ctx.protocol_metadata().expect("metadata set");
        assert_eq!(meta.version.as_deref(), Some("0.17.0"));
        assert_eq!(meta.capabilities, vec!["streaming"]);
        assert_eq!(
            ctx.attributes()
                .and_then(|a| a.get("tenant"))
                .map(String::as_str),
            Some("acme-corp"),
        );
    }

    /// Demonstrates that `AuthorizationContext` constructors only
    /// accept `PeerContext` (certificate-backed) and explicit
    /// authenticated inputs — there is no API that populates
    /// fields from an untrusted request payload.
    #[test]
    fn authenticated_only_constraints() {
        // Simulate untrusted payload data.
        let untrusted_name = "evil-peer";
        let untrusted_role = "superadmin";

        // The only way to build an AuthorizationContext is via
        // PeerContext (certificate-backed) and explicit params.
        let peer = PeerContext::new("real-agent");
        let ctx = AuthorizationContext::from_peer_context(&peer);

        // The untrusted payload cannot influence the identity.
        assert_ne!(ctx.peer_identity().name(), untrusted_name);
        assert_eq!(ctx.peer_identity().name(), "real-agent");

        // Roles are None unless explicitly provided by the
        // embedding application via from_authenticated_inputs.
        assert!(ctx.roles().is_none());

        // Even with from_authenticated_inputs, the identity
        // comes from PeerContext, not from untrusted data.
        let ctx2 = AuthorizationContext::from_authenticated_inputs(
            &peer,
            None,
            Some(vec![untrusted_role.to_owned()]),
            None,
            None,
        );
        // Identity is still from the certificate.
        assert_eq!(ctx2.peer_identity().name(), "real-agent");
    }

    #[test]
    fn peer_identity_from_peer_context() {
        let peer = PeerContext::new("node-3")
            .with_subject("CN=node-3")
            .with_fingerprint("dd:ee:ff");
        let id = PeerIdentity::from(&peer);
        assert_eq!(id.name(), "node-3");
        assert_eq!(id.subject(), Some("CN=node-3"));
        assert_eq!(id.fingerprint(), Some("dd:ee:ff"));
    }

    #[test]
    fn agent_kind_display() {
        assert_eq!(AgentKind::Agent.to_string(), "agent");
        assert_eq!(AgentKind::Proxy.to_string(), "proxy");
        assert_eq!(
            AgentKind::Other("scanner".to_owned()).to_string(),
            "scanner"
        );
    }

    #[test]
    fn authorization_error_display() {
        let err = AuthorizationError::new("policy violation");
        assert_eq!(err.to_string(), "authorization denied: policy violation");
    }

    #[test]
    fn authorization_error_kind_is_forbidden() {
        use crate::protocol_error::ProtocolErrorKind;

        let err = AuthorizationError::new("denied");
        assert_eq!(err.kind(), ProtocolErrorKind::Forbidden);
    }
}
