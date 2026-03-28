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

/// Classifies a handler error message into a
/// [`ProtocolErrorKind`].
///
/// Handler methods return `Result<T, String>`, where the error
/// string is a human-readable message.  This function maps
/// well-known message patterns to their semantic category:
///
/// - `"not supported"` → [`NotSupported`](ProtocolErrorKind::NotSupported)
/// - All other messages → [`Other`](ProtocolErrorKind::Other)
///
/// This is a **crate-internal** helper used by dispatch code to
/// attach a semantic category to handler errors without changing
/// the wire message.
#[cfg(feature = "server")]
#[must_use]
#[allow(dead_code)] // part of the internal mapping API; used by tests and available for callers
pub(crate) fn classify_handler_error(msg: &str) -> ProtocolErrorKind {
    if msg == "not supported" {
        ProtocolErrorKind::NotSupported
    } else {
        ProtocolErrorKind::Other
    }
}

/// Classifies a dispatch-level I/O error into a
/// [`ProtocolErrorKind`].
///
/// The dispatch loop in
/// [`handle_authorized`](crate::server::handle_authorized)
/// produces `io::Error` values for authorization denials, unknown
/// request codes, and argument parse failures.  This function
/// maps the `io::ErrorKind` to the corresponding semantic
/// category:
///
/// - [`PermissionDenied`](std::io::ErrorKind::PermissionDenied)
///   → [`Forbidden`](ProtocolErrorKind::Forbidden)
/// - [`InvalidData`](std::io::ErrorKind::InvalidData)
///   → [`NotSupported`](ProtocolErrorKind::NotSupported)
///   (unknown request codes produce this kind)
/// - [`InvalidInput`](std::io::ErrorKind::InvalidInput)
///   → [`InvalidArgs`](ProtocolErrorKind::InvalidArgs)
/// - All others → [`Other`](ProtocolErrorKind::Other)
#[cfg(feature = "server")]
#[must_use]
#[allow(dead_code)] // part of the internal mapping API; used by tests and available for callers
pub(crate) fn classify_dispatch_error(err: &std::io::Error) -> ProtocolErrorKind {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => ProtocolErrorKind::Forbidden,
        std::io::ErrorKind::InvalidData => ProtocolErrorKind::NotSupported,
        std::io::ErrorKind::InvalidInput => ProtocolErrorKind::InvalidArgs,
        _ => ProtocolErrorKind::Other,
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
    fn classify_handler_error_not_supported() {
        use super::classify_handler_error;

        assert_eq!(
            classify_handler_error("not supported"),
            ProtocolErrorKind::NotSupported
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn classify_handler_error_other() {
        use super::classify_handler_error;

        assert_eq!(
            classify_handler_error("some other error"),
            ProtocolErrorKind::Other
        );
        assert_eq!(classify_handler_error(""), ProtocolErrorKind::Other);
    }

    #[cfg(feature = "server")]
    #[test]
    fn classify_dispatch_error_mappings() {
        use std::io;

        use super::classify_dispatch_error;

        // PermissionDenied -> Forbidden
        let err = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authorization denied: test",
        );
        assert_eq!(classify_dispatch_error(&err), ProtocolErrorKind::Forbidden);

        // InvalidData -> NotSupported (unknown request code)
        let err = io::Error::new(io::ErrorKind::InvalidData, "unknown request code");
        assert_eq!(
            classify_dispatch_error(&err),
            ProtocolErrorKind::NotSupported
        );

        // InvalidInput -> InvalidArgs
        let err = io::Error::new(io::ErrorKind::InvalidInput, "bad arguments");
        assert_eq!(
            classify_dispatch_error(&err),
            ProtocolErrorKind::InvalidArgs
        );

        // Other kinds -> Other
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "connection lost");
        assert_eq!(classify_dispatch_error(&err), ProtocolErrorKind::Other);
    }
}
