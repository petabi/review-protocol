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
}
