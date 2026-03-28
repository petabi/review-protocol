//! Semantic protocol error categories for internal use.
//!
//! [`ProtocolErrorKind`] is a **semantic taxonomy** of protocol-level
//! error categories.  It is intended for internal APIs that need a
//! shared, documented vocabulary for classifying errors — for
//! example, when mapping diverse internal error types into a small
//! set of well-known categories for logging, metrics, or
//! higher-level error handling.
//!
//! # Not a wire type
//!
//! This enum does **not** define or influence the on-wire encoding
//! of errors.  Wire representation is handled separately by the
//! transport layer.  A future release may introduce a wire mapping,
//! but for now this type exists purely for internal classification.
//!
//! # Typical usage
//!
//! ```
//! use review_protocol::protocol_error::ProtocolErrorKind;
//!
//! let kind = ProtocolErrorKind::Forbidden;
//! assert_eq!(kind.to_string(), "forbidden");
//! ```

use std::fmt;

/// Semantic category for a protocol-level error.
///
/// Each variant represents a broad class of failure that internal
/// code can match on without coupling to a specific error type.
/// This is a **semantic taxonomy**, not a wire-level
/// representation — see the [module docs](self) for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolErrorKind {
    /// The requested operation is not supported by the receiver.
    ///
    /// Use this when a handler does not implement a particular
    /// request or when a feature is unavailable in the current
    /// configuration.
    NotSupported,

    /// The caller is not authorized to perform the requested
    /// operation.
    ///
    /// Maps naturally from [`AuthorizationError`](crate::auth::AuthorizationError)
    /// when authorization is denied.
    Forbidden,

    /// The request arguments are invalid, missing, or
    /// malformed.
    ///
    /// Use this for input-validation failures that are
    /// independent of authorization or version negotiation.
    InvalidArgs,

    /// The protocol versions of the two peers are incompatible.
    ///
    /// Typically produced during the handshake when the version
    /// requirement cannot be satisfied.
    VersionMismatch,

    /// A catch-all for errors that do not fit any other
    /// variant.
    ///
    /// Prefer a more specific variant when one applies.  `Other`
    /// is intended as a fallback so that conversions remain
    /// total.
    Other,
}

impl fmt::Display for ProtocolErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "not supported"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::InvalidArgs => write!(f, "invalid arguments"),
            Self::VersionMismatch => write!(f, "version mismatch"),
            Self::Other => write!(f, "other error"),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl From<&crate::auth::AuthorizationError> for ProtocolErrorKind {
    fn from(_: &crate::auth::AuthorizationError) -> Self {
        Self::Forbidden
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl From<crate::auth::AuthorizationError> for ProtocolErrorKind {
    fn from(_: crate::auth::AuthorizationError) -> Self {
        Self::Forbidden
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl From<&crate::HandshakeError> for ProtocolErrorKind {
    fn from(err: &crate::HandshakeError) -> Self {
        match err {
            crate::HandshakeError::IncompatibleProtocol(_, _) => Self::VersionMismatch,
            _ => Self::Other,
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl From<crate::HandshakeError> for ProtocolErrorKind {
    fn from(err: crate::HandshakeError) -> Self {
        Self::from(&err)
    }
}

/// An error from the dispatch loop that carries a
/// [`ProtocolErrorKind`] classification.
///
/// Used as the inner error of [`io::Error`](std::io::Error) values
/// produced by
/// [`handle_authorized`](crate::server::handle_authorized) for
/// authorization denials and unknown request codes.  Callers can
/// recover the classification via
/// [`ProtocolErrorKind::of_io_error`].
#[cfg(feature = "server")]
#[derive(Debug)]
pub(crate) struct DispatchError {
    kind: ProtocolErrorKind,
    message: String,
}

#[cfg(feature = "server")]
impl DispatchError {
    /// Creates a new dispatch error with the given classification
    /// and human-readable message.
    pub(crate) fn new(kind: ProtocolErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the semantic classification of this error.
    pub(crate) fn protocol_kind(&self) -> ProtocolErrorKind {
        self.kind
    }
}

#[cfg(feature = "server")]
impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[cfg(feature = "server")]
impl std::error::Error for DispatchError {}

#[cfg(feature = "server")]
impl ProtocolErrorKind {
    /// Extracts the [`ProtocolErrorKind`] from an
    /// [`io::Error`](std::io::Error).
    ///
    /// If the error was produced by the dispatch loop (and wraps
    /// a classified inner error), the embedded classification is
    /// returned directly.  Otherwise the `io::ErrorKind` is mapped:
    ///
    /// - [`PermissionDenied`](std::io::ErrorKind::PermissionDenied)
    ///   → [`Forbidden`]
    /// - [`InvalidData`](std::io::ErrorKind::InvalidData)
    ///   → [`NotSupported`]
    /// - [`InvalidInput`](std::io::ErrorKind::InvalidInput)
    ///   → [`InvalidArgs`]
    /// - All others → [`Other`]
    ///
    /// [`Forbidden`]: ProtocolErrorKind::Forbidden
    /// [`NotSupported`]: ProtocolErrorKind::NotSupported
    /// [`InvalidArgs`]: ProtocolErrorKind::InvalidArgs
    /// [`Other`]: ProtocolErrorKind::Other
    #[must_use]
    pub fn of_io_error(err: &std::io::Error) -> Self {
        if let Some(inner) = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<DispatchError>())
        {
            return inner.protocol_kind();
        }
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => Self::Forbidden,
            std::io::ErrorKind::InvalidData => Self::NotSupported,
            std::io::ErrorKind::InvalidInput => Self::InvalidArgs,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(ProtocolErrorKind::NotSupported.to_string(), "not supported");
        assert_eq!(ProtocolErrorKind::Forbidden.to_string(), "forbidden");
        assert_eq!(
            ProtocolErrorKind::InvalidArgs.to_string(),
            "invalid arguments"
        );
        assert_eq!(
            ProtocolErrorKind::VersionMismatch.to_string(),
            "version mismatch"
        );
        assert_eq!(ProtocolErrorKind::Other.to_string(), "other error");
    }

    #[test]
    fn equality_and_copy() {
        let a = ProtocolErrorKind::Forbidden;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(ProtocolErrorKind::Forbidden, ProtocolErrorKind::Other);
    }

    #[test]
    fn debug_format() {
        // Verify Debug is derived and produces the variant name.
        let dbg = format!("{:?}", ProtocolErrorKind::NotSupported);
        assert_eq!(dbg, "NotSupported");
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ProtocolErrorKind::Forbidden);
        set.insert(ProtocolErrorKind::Forbidden);
        assert_eq!(set.len(), 1);
        set.insert(ProtocolErrorKind::Other);
        assert_eq!(set.len(), 2);
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn from_authorization_error() {
        use crate::auth::AuthorizationError;

        let err = AuthorizationError::new("denied");
        let kind = ProtocolErrorKind::from(&err);
        assert_eq!(kind, ProtocolErrorKind::Forbidden);

        let kind: ProtocolErrorKind = err.into();
        assert_eq!(kind, ProtocolErrorKind::Forbidden);
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn from_handshake_error_version_mismatch() {
        use crate::HandshakeError;

        let err = HandshakeError::IncompatibleProtocol("1.0.0".into(), "2.0.0".into());
        assert_eq!(
            ProtocolErrorKind::from(&err),
            ProtocolErrorKind::VersionMismatch
        );
        assert_eq!(
            ProtocolErrorKind::from(err),
            ProtocolErrorKind::VersionMismatch
        );
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn from_handshake_error_other_variants() {
        use crate::HandshakeError;

        let cases = [
            HandshakeError::ConnectionClosed,
            HandshakeError::MessageTooLarge,
            HandshakeError::InvalidMessage,
        ];
        for err in &cases {
            assert_eq!(
                ProtocolErrorKind::from(err),
                ProtocolErrorKind::Other,
                "expected Other for {err}"
            );
        }
    }

    #[cfg(feature = "server")]
    #[test]
    fn of_io_error_with_dispatch_error() {
        use std::io;

        use super::DispatchError;

        // Embedded DispatchError takes priority over ErrorKind
        let err = io::Error::new(
            io::ErrorKind::PermissionDenied,
            DispatchError::new(ProtocolErrorKind::Forbidden, "authorization denied: test"),
        );
        assert_eq!(
            ProtocolErrorKind::of_io_error(&err),
            ProtocolErrorKind::Forbidden,
        );

        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            DispatchError::new(ProtocolErrorKind::NotSupported, "unknown request code"),
        );
        assert_eq!(
            ProtocolErrorKind::of_io_error(&err),
            ProtocolErrorKind::NotSupported,
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn of_io_error_fallback_mappings() {
        use std::io;

        // Without embedded DispatchError, falls back to ErrorKind
        let err = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authorization denied: test",
        );
        assert_eq!(
            ProtocolErrorKind::of_io_error(&err),
            ProtocolErrorKind::Forbidden,
        );

        let err = io::Error::new(io::ErrorKind::InvalidData, "unknown request code");
        assert_eq!(
            ProtocolErrorKind::of_io_error(&err),
            ProtocolErrorKind::NotSupported,
        );

        let err = io::Error::new(io::ErrorKind::InvalidInput, "bad arguments");
        assert_eq!(
            ProtocolErrorKind::of_io_error(&err),
            ProtocolErrorKind::InvalidArgs,
        );

        let err = io::Error::new(io::ErrorKind::ConnectionReset, "connection lost");
        assert_eq!(
            ProtocolErrorKind::of_io_error(&err),
            ProtocolErrorKind::Other,
        );
    }
}
