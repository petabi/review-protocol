//! Stable logical service identifiers independent of wire request
//! codes.
//!
//! This module defines a semantic naming layer for the protocol's
//! service families and methods.  Each [`ServiceId`] represents a
//! logical API operation (e.g. `"node.power.reboot"`) that remains
//! stable even if the underlying wire [`RequestCode`](super::client::RequestCode)
//! values are renumbered or reorganized.
//!
//! # Relationship to `RequestCode`
//!
//! `RequestCode` remains the transport dispatch mechanism.  The
//! identifiers defined here are **not** a replacement for request
//! codes — they are a higher-level abstraction suitable for:
//!
//! - authorization decisions
//! - capability reporting
//! - service-family organization
//! - public-facing API documentation
//!
//! Use [`from_request_code`] to map a wire request code to its
//! logical identifier when needed.
//!
//! # Naming conventions
//!
//! - **Family** components are separated by `.`
//!   (e.g. `"node.power"`, `"common"`).
//! - **Method** names use stable `lower_snake_case`
//!   (e.g. `"reboot"`, `"process_list"`).
//! - The canonical string form is `"{family}.{method}"`
//!   (e.g. `"node.power.reboot"`).

use std::fmt;

/// A logical service identifier.
///
/// Represents a specific API operation as a `(family, method)` pair
/// using static strings.  The identifier is independent of the
/// numeric wire request code used for transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServiceId {
    /// The service family (e.g. `"node.power"`, `"common"`).
    pub family: &'static str,
    /// The method within the family (e.g. `"reboot"`).
    pub method: &'static str,
}

impl ServiceId {
    /// Creates a new `ServiceId`.
    #[must_use]
    pub const fn new(family: &'static str, method: &'static str) -> Self {
        Self { family, method }
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.family, self.method)
    }
}

// ── node.service ───────────────────────────────────────────────

pub const NODE_SERVICE_START: ServiceId = ServiceId::new("node.service", "start");
pub const NODE_SERVICE_STOP: ServiceId = ServiceId::new("node.service", "stop");
pub const NODE_SERVICE_STATUS: ServiceId = ServiceId::new("node.service", "status");
pub const NODE_SERVICE_RESTART: ServiceId = ServiceId::new("node.service", "restart");

// ── node.network_interface ─────────────────────────────────────

pub const NODE_NETWORK_INTERFACE_LIST: ServiceId = ServiceId::new("node.network_interface", "list");
pub const NODE_NETWORK_INTERFACE_GET: ServiceId = ServiceId::new("node.network_interface", "get");
pub const NODE_NETWORK_INTERFACE_SET: ServiceId = ServiceId::new("node.network_interface", "set");
pub const NODE_NETWORK_INTERFACE_RESET_CONFIG: ServiceId =
    ServiceId::new("node.network_interface", "reset_config");
pub const NODE_NETWORK_INTERFACE_REMOVE: ServiceId =
    ServiceId::new("node.network_interface", "remove");

// ── node.hostname ──────────────────────────────────────────────

pub const NODE_HOSTNAME_GET: ServiceId = ServiceId::new("node.hostname", "get");
pub const NODE_HOSTNAME_SET: ServiceId = ServiceId::new("node.hostname", "set");

// ── node.time_sync ─────────────────────────────────────────────

pub const NODE_TIME_SYNC_GET: ServiceId = ServiceId::new("node.time_sync", "get");
pub const NODE_TIME_SYNC_SET: ServiceId = ServiceId::new("node.time_sync", "set");
pub const NODE_TIME_SYNC_ENABLE: ServiceId = ServiceId::new("node.time_sync", "enable");
pub const NODE_TIME_SYNC_DISABLE: ServiceId = ServiceId::new("node.time_sync", "disable");
pub const NODE_TIME_SYNC_STATUS: ServiceId = ServiceId::new("node.time_sync", "status");

// ── node.logging ───────────────────────────────────────────────

pub const NODE_LOGGING_GET: ServiceId = ServiceId::new("node.logging", "get");
pub const NODE_LOGGING_SET: ServiceId = ServiceId::new("node.logging", "set");
pub const NODE_LOGGING_CLEAR: ServiceId = ServiceId::new("node.logging", "clear");
pub const NODE_LOGGING_RESTART: ServiceId = ServiceId::new("node.logging", "restart");

// ── node.remote_access ─────────────────────────────────────────

pub const NODE_REMOTE_ACCESS_GET: ServiceId = ServiceId::new("node.remote_access", "get");
pub const NODE_REMOTE_ACCESS_SET: ServiceId = ServiceId::new("node.remote_access", "set");
pub const NODE_REMOTE_ACCESS_RESTART: ServiceId = ServiceId::new("node.remote_access", "restart");

// ── node.power ─────────────────────────────────────────────────

pub const NODE_POWER_REBOOT: ServiceId = ServiceId::new("node.power", "reboot");
pub const NODE_POWER_SHUTDOWN: ServiceId = ServiceId::new("node.power", "shutdown");
pub const NODE_POWER_GRACEFUL_REBOOT: ServiceId = ServiceId::new("node.power", "graceful_reboot");
pub const NODE_POWER_GRACEFUL_SHUTDOWN: ServiceId =
    ServiceId::new("node.power", "graceful_shutdown");

// ── node.observation ───────────────────────────────────────────

pub const NODE_OBSERVATION_PROCESS_LIST: ServiceId =
    ServiceId::new("node.observation", "process_list");
pub const NODE_OBSERVATION_RESOURCE_USAGE: ServiceId =
    ServiceId::new("node.observation", "resource_usage");
pub const NODE_OBSERVATION_UPTIME: ServiceId = ServiceId::new("node.observation", "uptime");

// ── node.version ───────────────────────────────────────────────

pub const NODE_VERSION_GET: ServiceId = ServiceId::new("node.version", "get");
pub const NODE_VERSION_SET_OS: ServiceId = ServiceId::new("node.version", "set_os_version");
pub const NODE_VERSION_SET_PRODUCT: ServiceId =
    ServiceId::new("node.version", "set_product_version");

// ── common ─────────────────────────────────────────────────────
//
// Legacy/common operations that are relevant for dispatch and
// compatibility during the transition to service families.

pub const COMMON_DNS_START: ServiceId = ServiceId::new("common", "dns_start");
pub const COMMON_DNS_STOP: ServiceId = ServiceId::new("common", "dns_stop");
pub const COMMON_RELOAD_CONFIG: ServiceId = ServiceId::new("common", "reload_config");
pub const COMMON_UPDATE_CONFIG: ServiceId = ServiceId::new("common", "update_config");
pub const COMMON_RELOAD_TI: ServiceId = ServiceId::new("common", "reload_ti");
pub const COMMON_TOR_EXIT_NODE_LIST: ServiceId = ServiceId::new("common", "tor_exit_node_list");
pub const COMMON_TRUSTED_DOMAIN_LIST: ServiceId = ServiceId::new("common", "trusted_domain_list");
pub const COMMON_SAMPLING_POLICY_LIST: ServiceId = ServiceId::new("common", "sampling_policy_list");
pub const COMMON_DELETE_SAMPLING_POLICY: ServiceId =
    ServiceId::new("common", "delete_sampling_policy");
pub const COMMON_RELOAD_FILTER_RULE: ServiceId = ServiceId::new("common", "reload_filter_rule");
pub const COMMON_INTERNAL_NETWORK_LIST: ServiceId =
    ServiceId::new("common", "internal_network_list");
pub const COMMON_ALLOWLIST: ServiceId = ServiceId::new("common", "allowlist");
pub const COMMON_BLOCKLIST: ServiceId = ServiceId::new("common", "blocklist");
pub const COMMON_ECHO: ServiceId = ServiceId::new("common", "echo");
pub const COMMON_TRUSTED_USER_AGENT_LIST: ServiceId =
    ServiceId::new("common", "trusted_user_agent_list");
pub const COMMON_SEMI_SUPERVISED_MODELS: ServiceId =
    ServiceId::new("common", "semi_supervised_models");
pub const COMMON_RENEW_CERTIFICATE: ServiceId = ServiceId::new("common", "renew_certificate");

// ── RequestCode → ServiceId mapping ────────────────────────────
//
// Maps wire request codes to their logical service identifiers.
// This is an explicit match table so that the mapping does not
// depend on numeric request-code values.

#[cfg(any(feature = "client", feature = "server"))]
use crate::client::RequestCode;

/// Maps a client-side wire [`RequestCode`] to its logical
/// [`ServiceId`].
///
/// Returns `None` for `RequestCode::Unknown` or any code that does
/// not have a defined logical identifier.  Node family codes map to
/// the family-level identifier (method resolution requires the
/// deserialized request payload).
#[cfg(any(feature = "client", feature = "server"))]
#[must_use]
#[allow(clippy::match_same_arms)] // intentional: legacy flat codes
// and node family codes carry
// different semantic intent
pub(crate) fn from_request_code(code: RequestCode) -> Option<ServiceId> {
    match code {
        // Legacy flat codes
        RequestCode::DnsStart => Some(COMMON_DNS_START),
        RequestCode::DnsStop => Some(COMMON_DNS_STOP),
        RequestCode::Reboot => Some(NODE_POWER_REBOOT),
        RequestCode::ReloadConfig => Some(COMMON_RELOAD_CONFIG),
        RequestCode::ReloadTi => Some(COMMON_RELOAD_TI),
        RequestCode::ResourceUsage => Some(NODE_OBSERVATION_RESOURCE_USAGE),
        RequestCode::TorExitNodeList => Some(COMMON_TOR_EXIT_NODE_LIST),
        RequestCode::SamplingPolicyList => Some(COMMON_SAMPLING_POLICY_LIST),
        RequestCode::ReloadFilterRule => Some(COMMON_RELOAD_FILTER_RULE),
        RequestCode::UpdateConfig => Some(COMMON_UPDATE_CONFIG),
        RequestCode::DeleteSamplingPolicy => Some(COMMON_DELETE_SAMPLING_POLICY),
        RequestCode::InternalNetworkList => Some(COMMON_INTERNAL_NETWORK_LIST),
        RequestCode::Allowlist => Some(COMMON_ALLOWLIST),
        RequestCode::Blocklist => Some(COMMON_BLOCKLIST),
        RequestCode::EchoRequest => Some(COMMON_ECHO),
        RequestCode::TrustedUserAgentList => Some(COMMON_TRUSTED_USER_AGENT_LIST),
        RequestCode::TrustedDomainList => Some(COMMON_TRUSTED_DOMAIN_LIST),
        RequestCode::ProcessList => Some(NODE_OBSERVATION_PROCESS_LIST),
        RequestCode::SemiSupervisedModels => Some(COMMON_SEMI_SUPERVISED_MODELS),
        RequestCode::Shutdown => Some(NODE_POWER_SHUTDOWN),

        // Node feature-family codes.  These map to the family
        // level; the specific method is determined by deserializing
        // the request payload, not by the wire code alone.  We use
        // the first method in the family as a representative; call
        // site code should refine further if needed.
        RequestCode::NodeService => Some(NODE_SERVICE_START),
        RequestCode::NodeNetworkInterface => Some(NODE_NETWORK_INTERFACE_LIST),
        RequestCode::NodeHostname => Some(NODE_HOSTNAME_GET),
        RequestCode::NodeTimeSync => Some(NODE_TIME_SYNC_GET),
        RequestCode::NodeLogging => Some(NODE_LOGGING_GET),
        RequestCode::NodeRemoteAccess => Some(NODE_REMOTE_ACCESS_GET),
        RequestCode::NodePower => Some(NODE_POWER_REBOOT),
        RequestCode::NodeObservation => Some(NODE_OBSERVATION_PROCESS_LIST),
        RequestCode::NodeVersion => Some(NODE_VERSION_GET),

        RequestCode::Unknown => None,
    }
}

/// Returns an iterator over all known [`ServiceId`] constants.
///
/// Useful for capability reporting and testing coverage.
#[must_use]
pub fn all() -> &'static [ServiceId] {
    &[
        // node.service
        NODE_SERVICE_START,
        NODE_SERVICE_STOP,
        NODE_SERVICE_STATUS,
        NODE_SERVICE_RESTART,
        // node.network_interface
        NODE_NETWORK_INTERFACE_LIST,
        NODE_NETWORK_INTERFACE_GET,
        NODE_NETWORK_INTERFACE_SET,
        NODE_NETWORK_INTERFACE_RESET_CONFIG,
        NODE_NETWORK_INTERFACE_REMOVE,
        // node.hostname
        NODE_HOSTNAME_GET,
        NODE_HOSTNAME_SET,
        // node.time_sync
        NODE_TIME_SYNC_GET,
        NODE_TIME_SYNC_SET,
        NODE_TIME_SYNC_ENABLE,
        NODE_TIME_SYNC_DISABLE,
        NODE_TIME_SYNC_STATUS,
        // node.logging
        NODE_LOGGING_GET,
        NODE_LOGGING_SET,
        NODE_LOGGING_CLEAR,
        NODE_LOGGING_RESTART,
        // node.remote_access
        NODE_REMOTE_ACCESS_GET,
        NODE_REMOTE_ACCESS_SET,
        NODE_REMOTE_ACCESS_RESTART,
        // node.power
        NODE_POWER_REBOOT,
        NODE_POWER_SHUTDOWN,
        NODE_POWER_GRACEFUL_REBOOT,
        NODE_POWER_GRACEFUL_SHUTDOWN,
        // node.observation
        NODE_OBSERVATION_PROCESS_LIST,
        NODE_OBSERVATION_RESOURCE_USAGE,
        NODE_OBSERVATION_UPTIME,
        // node.version
        NODE_VERSION_GET,
        NODE_VERSION_SET_OS,
        NODE_VERSION_SET_PRODUCT,
        // common
        COMMON_DNS_START,
        COMMON_DNS_STOP,
        COMMON_RELOAD_CONFIG,
        COMMON_UPDATE_CONFIG,
        COMMON_RELOAD_TI,
        COMMON_TOR_EXIT_NODE_LIST,
        COMMON_TRUSTED_DOMAIN_LIST,
        COMMON_SAMPLING_POLICY_LIST,
        COMMON_DELETE_SAMPLING_POLICY,
        COMMON_RELOAD_FILTER_RULE,
        COMMON_INTERNAL_NETWORK_LIST,
        COMMON_ALLOWLIST,
        COMMON_BLOCKLIST,
        COMMON_ECHO,
        COMMON_TRUSTED_USER_AGENT_LIST,
        COMMON_SEMI_SUPERVISED_MODELS,
        COMMON_RENEW_CERTIFICATE,
    ]
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn display_format() {
        assert_eq!(NODE_POWER_REBOOT.to_string(), "node.power.reboot");
        assert_eq!(
            NODE_OBSERVATION_PROCESS_LIST.to_string(),
            "node.observation.process_list"
        );
        assert_eq!(
            COMMON_RENEW_CERTIFICATE.to_string(),
            "common.renew_certificate"
        );
        assert_eq!(COMMON_ECHO.to_string(), "common.echo");
    }

    #[test]
    fn equality_and_hash() {
        let a = ServiceId::new("node.power", "reboot");
        assert_eq!(a, NODE_POWER_REBOOT);

        let mut set = HashSet::new();
        set.insert(NODE_POWER_REBOOT);
        assert!(set.contains(&a));
    }

    #[test]
    fn from_request_code_legacy() {
        assert_eq!(
            from_request_code(RequestCode::DnsStart),
            Some(COMMON_DNS_START)
        );
        assert_eq!(
            from_request_code(RequestCode::Reboot),
            Some(NODE_POWER_REBOOT)
        );
        assert_eq!(
            from_request_code(RequestCode::Shutdown),
            Some(NODE_POWER_SHUTDOWN)
        );
        assert_eq!(
            from_request_code(RequestCode::ResourceUsage),
            Some(NODE_OBSERVATION_RESOURCE_USAGE)
        );
        assert_eq!(
            from_request_code(RequestCode::ProcessList),
            Some(NODE_OBSERVATION_PROCESS_LIST)
        );
        assert_eq!(
            from_request_code(RequestCode::EchoRequest),
            Some(COMMON_ECHO)
        );
    }

    #[test]
    fn from_request_code_node_families() {
        assert!(from_request_code(RequestCode::NodeService).is_some());
        assert!(from_request_code(RequestCode::NodeNetworkInterface).is_some());
        assert!(from_request_code(RequestCode::NodeHostname).is_some());
        assert!(from_request_code(RequestCode::NodeTimeSync).is_some());
        assert!(from_request_code(RequestCode::NodeLogging).is_some());
        assert!(from_request_code(RequestCode::NodeRemoteAccess).is_some());
        assert!(from_request_code(RequestCode::NodePower).is_some());
        assert!(from_request_code(RequestCode::NodeObservation).is_some());
        assert!(from_request_code(RequestCode::NodeVersion).is_some());
    }

    #[test]
    fn from_request_code_unknown() {
        assert_eq!(from_request_code(RequestCode::Unknown), None);
    }

    /// Every non-`Unknown` `RequestCode` variant should have a
    /// logical identifier mapping.
    #[test]
    fn all_known_request_codes_are_mapped() {
        let codes: &[RequestCode] = &[
            RequestCode::DnsStart,
            RequestCode::DnsStop,
            RequestCode::Reboot,
            RequestCode::ReloadConfig,
            RequestCode::ReloadTi,
            RequestCode::ResourceUsage,
            RequestCode::TorExitNodeList,
            RequestCode::SamplingPolicyList,
            RequestCode::ReloadFilterRule,
            RequestCode::UpdateConfig,
            RequestCode::DeleteSamplingPolicy,
            RequestCode::InternalNetworkList,
            RequestCode::Allowlist,
            RequestCode::Blocklist,
            RequestCode::EchoRequest,
            RequestCode::TrustedUserAgentList,
            RequestCode::TrustedDomainList,
            RequestCode::ProcessList,
            RequestCode::SemiSupervisedModels,
            RequestCode::Shutdown,
            RequestCode::NodeService,
            RequestCode::NodeNetworkInterface,
            RequestCode::NodeHostname,
            RequestCode::NodeTimeSync,
            RequestCode::NodeLogging,
            RequestCode::NodeRemoteAccess,
            RequestCode::NodePower,
            RequestCode::NodeObservation,
            RequestCode::NodeVersion,
        ];
        for &code in codes {
            assert!(
                from_request_code(code).is_some(),
                "RequestCode::{code:?} should map to a ServiceId"
            );
        }
    }

    /// All service identifiers returned by [`all()`] should have
    /// unique string representations.
    #[test]
    fn all_ids_are_unique() {
        let ids = all();
        let strings: HashSet<String> = ids.iter().map(ToString::to_string).collect();
        assert_eq!(
            ids.len(),
            strings.len(),
            "duplicate ServiceId string representations found"
        );
    }

    /// The `all()` list should not be empty and should include
    /// identifiers from both node families and common operations.
    #[test]
    fn all_covers_families() {
        let ids = all();
        assert!(!ids.is_empty());
        assert!(ids.contains(&NODE_POWER_REBOOT));
        assert!(ids.contains(&COMMON_RENEW_CERTIFICATE));
        assert!(ids.contains(&NODE_OBSERVATION_PROCESS_LIST));
    }
}
