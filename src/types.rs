//! Data types used by the protocol.

use std::{
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    time::Duration,
};

use ipnet::IpNet;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
pub use structured::ColumnStatistics;

/// The data source key, either a numeric ID or a name.
#[derive(Debug, Deserialize, Serialize)]
pub enum DataSourceKey<'a> {
    Id(u32),
    Name(&'a str),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataSource {
    pub id: u32,
    pub name: String,

    pub server_name: String,
    pub address: SocketAddr,

    pub data_type: DataType,
    pub source: String,
    pub kind: Option<String>,

    pub description: String,
}

/// The type of data that a data source provides.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, IntoPrimitive, TryFromPrimitive)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum DataType {
    /// comma-separated values
    Csv = 0,
    /// line-based text data
    Log = 1,
    /// time series data
    TimeSeries = 2,
}

/// CPU, memory, and disk usage.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResourceUsage {
    /// The average CPU usage in percent.
    pub cpu_usage: f32,

    /// The RAM size in bytes.
    pub total_memory: u64,

    /// The amount of used RAM in bytes.
    pub used_memory: u64,

    /// The disk space in bytes that is currently used.
    pub disk_used_bytes: u64,

    /// The disk space in bytes that is available to non-root users.
    pub disk_available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Process {
    pub user: String,
    pub cpu_usage: f32,
    pub mem_usage: f64,
    pub start_time: i64,
    pub command: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    pub hosts: Vec<IpAddr>,
    pub networks: Vec<IpNet>,
    pub ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum SamplingKind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

// A policy for time series sampling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SamplingPolicy {
    pub id: u32,
    pub kind: SamplingKind,
    pub interval: Duration,
    pub period: Duration,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

// IP address, port numbers, and protocols.
pub type TrafficFilterRule = (IpNet, Option<Vec<u16>>, Option<Vec<u16>>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum EventCategory {
    Reconnaissance = 1,
    InitialAccess = 2,
    Execution = 3,
    CredentialAccess = 4,
    Discovery = 5,
    LateralMovement = 6,
    CommandAndControl = 7,
    Exfiltration = 8,
    Impact = 9,
    Collection = 10,
    DefenseEvasion = 11,
    Persistence = 12,
    PrivilegeEscalation = 13,
    ResourceDevelopment = 14,
}

#[derive(Clone, Copy, Debug, Deserialize_repr, Eq, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum LabelDbKind {
    Ip = 0,
    Url = 1,
    Token = 2,
    Regex = 3,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RuleKind {
    Os,
    AgentSoftware,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserAgent {
    pub name: String,
    pub header: String,
    pub kind: RuleKind,
    pub last_modification_time: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LabelDbRule {
    pub rule_id: u32,
    pub category: Option<EventCategory>,
    pub name: String,
    pub kind: Option<RuleKind>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
    pub confidence: Option<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LabelDb {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: LabelDbKind,
    pub category: Option<EventCategory>,
    pub version: String,
    pub patterns: Vec<LabelDbRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Status {
    Ready,
    Idle,
}

/// Threat level of a detection event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ThreatLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ColumnStatisticsUpdate {
    pub cluster_id: u32,
    pub column_statistics: Vec<ColumnStatistics>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeCount {
    pub time: jiff::civil::DateTime,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeries {
    pub count_index: Option<usize>,
    pub series: Vec<TimeCount>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeriesUpdate {
    pub cluster_id: String,
    pub time_series: Vec<TimeSeries>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: i32,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<(i64, String)>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutlierInfo {
    pub id: i64,
    pub rank: i64,
    pub distance: f64,
    pub sensor: String,
}

#[derive(Serialize, Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub enum EventKind {
    DnsCovertChannel,
    HttpThreat,
    RdpBruteForce,
    RepeatedHttpSessions,
    ExtraThreat,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDdos,
    CryptocurrencyMiningPool,
    BlocklistConn,
    BlocklistDns,
    BlocklistDceRpc,
    BlocklistFtp,
    BlocklistHttp,
    BlocklistKerberos,
    BlocklistLdap,
    BlocklistMqtt,
    BlocklistNfs,
    BlocklistNtlm,
    BlocklistRdp,
    BlocklistSmb,
    BlocklistSmtp,
    BlocklistSsh,
    BlocklistTls,
    WindowsThreat,
    NetworkThreat,
    LockyRansomware,
    SuspiciousTlsTraffic,
    BlocklistBootp,
    BlocklistDhcp,
    TorConnectionConn,
    BlocklistRadius,
    BlocklistMalformedDns,
    UnusualDestinationPattern,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventMessage {
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub time: jiff::Timestamp,
    pub kind: EventKind,
    #[serde(with = "serde_bytes")]
    pub fields: Vec<u8>,
}

/// Types for the `node` agent family, grouping host-control and
/// host-observation functionality under stable feature families.
pub mod node {
    use serde::{Deserialize, Serialize};

    use super::Process;

    // ── service control ─────────────────────────────────────────

    /// Request for managing system services on a node.
    ///
    /// Each variant carries only the data its operation requires,
    /// making invalid combinations unrepresentable.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeServiceRequest {
        /// Start a service by name.
        Start { name: String },
        /// Stop a service by name.
        Stop { name: String },
        /// Restart a service by name.
        Restart { name: String },
        /// Query the status of a service by name.
        Status { name: String },
        /// List all known services.
        List,
    }

    /// Response from a service-control operation.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeServiceResponse {
        /// The operation completed successfully.
        Ok,
        /// Status of a single service.
        Status {
            name: String,
            active: bool,
            pid: Option<u32>,
            details: Option<String>,
        },
        /// A list of services on the node.
        List { services: Vec<ServiceInfo> },
    }

    /// Summary information for a single system service.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct ServiceInfo {
        pub name: String,
        pub active: bool,
        pub description: Option<String>,
    }

    // ── network interface management ────────────────────────────

    /// Request for managing network interfaces on a node.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeNetworkInterfaceRequest {
        /// List all network interfaces.
        List,
        /// Get status of a specific interface by name.
        Get { name: String },
        /// Apply configuration to a named interface.
        Configure {
            name: String,
            cfg: NetworkInterfaceConfig,
        },
        /// Bring an interface up.
        Up { name: String },
        /// Bring an interface down.
        Down { name: String },
    }

    /// Response from a network-interface operation.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeNetworkInterfaceResponse {
        /// A list of all interfaces.
        List {
            interfaces: Vec<NetworkInterfaceStatus>,
        },
        /// Status of a single interface.
        Get { status: NetworkInterfaceStatus },
        /// The operation completed successfully.
        Ok,
    }

    /// Configuration payload for a network interface.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub struct NetworkInterfaceConfig {
        /// IP addresses to assign (as strings to support CIDR
        /// notation).
        pub addresses: Vec<String>,
        /// Maximum transmission unit.
        pub mtu: Option<u32>,
        /// Whether DHCP should be enabled.
        pub dhcp: Option<bool>,
        /// MAC address override.
        pub mac: Option<String>,
    }

    /// Observed status of a network interface.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub struct NetworkInterfaceStatus {
        pub name: String,
        pub up: bool,
        /// Currently assigned addresses.
        pub addresses: Vec<String>,
        pub mtu: Option<u32>,
        pub mac: Option<String>,
    }

    // ── hostname management ─────────────────────────────────────

    /// Request for reading or setting the node hostname.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeHostnameRequest {
        /// Retrieve the current hostname.
        Get,
        /// Set the hostname to the given value.
        Set { hostname: String },
    }

    /// Response from a hostname operation.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeHostnameResponse {
        /// The current hostname.
        Get { hostname: String },
        /// The operation completed successfully.
        Ok,
    }

    // ── time synchronization management ─────────────────────────

    /// Request for managing NTP / time-synchronization settings.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeTimeSyncRequest {
        /// Retrieve the current time-sync configuration.
        Get,
        /// Replace the list of NTP servers.
        Set { servers: Vec<String> },
        /// Enable time synchronization.
        Enable,
        /// Disable time synchronization.
        Disable,
        /// Query synchronization status.
        Status,
    }

    /// Response from a time-synchronization operation.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeTimeSyncResponse {
        /// Current time-sync configuration.
        Get { servers: Vec<String>, enabled: bool },
        /// Current synchronization status.
        Status {
            synced: bool,
            offset_seconds: Option<f64>,
        },
        /// The operation completed successfully.
        Ok,
    }

    // ── logging configuration ───────────────────────────────────

    /// Request for managing logging configuration on a node.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeLoggingRequest {
        /// Retrieve the current logging configuration.
        GetConfig,
        /// Replace the entire logging configuration.
        SetConfig { cfg: LoggingConfig },
        /// Set the log level, optionally scoped to a facility.
        SetLevel {
            facility: Option<String>,
            level: LogLevel,
        },
    }

    /// Response from a logging-configuration operation.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeLoggingResponse {
        /// The current logging configuration.
        Config { cfg: LoggingConfig },
        /// The operation completed successfully.
        Ok,
    }

    /// Full logging configuration for a node.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct LoggingConfig {
        pub default_level: LogLevel,
        pub rules: Vec<LoggingRule>,
    }

    /// A per-target log-level override.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct LoggingRule {
        pub target: String,
        pub level: LogLevel,
    }

    /// Standard log severity levels.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum LogLevel {
        Trace,
        Debug,
        Info,
        Warn,
        Error,
    }

    // ── remote access configuration ─────────────────────────────

    /// Request for managing remote-access (e.g. SSH) settings.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeRemoteAccessRequest {
        /// Retrieve the current remote-access configuration.
        GetConfig,
        /// Replace the remote-access configuration.
        SetConfig { cfg: RemoteAccessConfig },
        /// Enable remote access.
        Enable,
        /// Disable remote access.
        Disable,
        /// List authorized public keys.
        ListAuthorizedKeys,
    }

    /// Response from a remote-access operation.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeRemoteAccessResponse {
        /// The current remote-access configuration.
        Config { cfg: RemoteAccessConfig },
        /// List of authorized public keys.
        AuthorizedKeys { keys: Vec<String> },
        /// The operation completed successfully.
        Ok,
    }

    /// Remote-access (SSH) configuration for a node.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct RemoteAccessConfig {
        pub ssh_enabled: bool,
        pub port: Option<u16>,
        pub authorized_keys: Vec<String>,
    }

    // ── power control ───────────────────────────────────────────

    /// Request for node power-control operations.
    ///
    /// Maps the existing flat `reboot` and `shutdown` APIs into the
    /// `node` domain.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePowerRequest {
        /// Reboot the node.
        Reboot {
            force: bool,
            delay_seconds: Option<u32>,
        },
        /// Shut down the node.
        Shutdown {
            force: bool,
            delay_seconds: Option<u32>,
        },
        /// Halt the node immediately.
        Halt { force: bool },
    }

    /// Response from a power-control operation.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePowerResponse {
        /// The operation completed (or was accepted) successfully.
        Ok,
        /// A power operation has been scheduled.
        Status { scheduled_in_seconds: Option<u32> },
    }

    // ── host observation ────────────────────────────────────────

    /// Request for observing host state.
    ///
    /// Maps the existing flat `process_list` and `resource_usage`
    /// APIs into the `node` domain.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeObservationRequest {
        /// List all running processes.
        ProcessList,
        /// Get aggregate resource usage (CPU, memory, disk).
        ResourceUsage,
        /// Get information about a specific process by PID.
        ProcessInfo { pid: u32 },
    }

    /// Response from a host-observation operation.
    ///
    /// Reuses the existing [`Process`] and [`ResourceUsage`] types.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeObservationResponse {
        /// List of running processes.
        ProcessList { processes: Vec<Process> },
        /// Aggregate resource usage.
        ResourceUsage { usage: super::ResourceUsage },
        /// Information about a single process, or `None` if the PID
        /// was not found.
        ProcessInfo { process: Option<Process> },
    }

    // ── version management ──────────────────────────────────────

    /// Request for querying or updating the node software version.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeVersionRequest {
        /// Get the currently running version.
        Get,
        /// Check whether an update is available.
        CheckUpdate,
        /// Apply an available update.
        Update,
    }

    /// Response from a version-management operation.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeVersionResponse {
        /// The current version string.
        Version { version: String },
        /// An update is available.
        UpdateAvailable { latest: String },
        /// The operation completed successfully.
        Ok,
    }

    #[cfg(test)]
    mod tests {
        use super::super::ResourceUsage;
        use super::*;

        /// Helper: bincode round-trip for any `Serialize + Deserialize`
        /// type.
        fn roundtrip<T>(value: &T) -> T
        where
            T: Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
        {
            let bytes = bincode::serde::encode_to_vec(
                value,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");
            let (decoded, _): (T, usize) = bincode::serde::decode_from_slice(
                &bytes,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");
            decoded
        }

        #[test]
        fn serde_roundtrip_node_service() {
            let req = NodeServiceRequest::Start {
                name: "nginx".into(),
            };
            assert_eq!(req, roundtrip(&req));

            let req = NodeServiceRequest::List;
            assert_eq!(req, roundtrip(&req));

            let resp = NodeServiceResponse::Status {
                name: "nginx".into(),
                active: true,
                pid: Some(1234),
                details: None,
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeServiceResponse::List {
                services: vec![ServiceInfo {
                    name: "sshd".into(),
                    active: true,
                    description: Some("OpenSSH server".into()),
                }],
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_network_interface() {
            let req = NodeNetworkInterfaceRequest::Configure {
                name: "eth0".into(),
                cfg: NetworkInterfaceConfig {
                    addresses: vec!["192.168.1.10/24".into()],
                    mtu: Some(1500),
                    dhcp: Some(false),
                    mac: None,
                },
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeNetworkInterfaceResponse::Get {
                status: NetworkInterfaceStatus {
                    name: "eth0".into(),
                    up: true,
                    addresses: vec!["192.168.1.10".into()],
                    mtu: Some(1500),
                    mac: Some("00:11:22:33:44:55".into()),
                },
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_hostname() {
            let req = NodeHostnameRequest::Set {
                hostname: "node-1".into(),
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeHostnameResponse::Get {
                hostname: "node-1".into(),
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_time_sync() {
            let req = NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into(), "1.pool.ntp.org".into()],
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeTimeSyncResponse::Get {
                servers: vec!["0.pool.ntp.org".into()],
                enabled: true,
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeTimeSyncResponse::Status {
                synced: true,
                offset_seconds: Some(0.003),
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_logging() {
            let req = NodeLoggingRequest::SetConfig {
                cfg: LoggingConfig {
                    default_level: LogLevel::Info,
                    rules: vec![LoggingRule {
                        target: "network".into(),
                        level: LogLevel::Debug,
                    }],
                },
            };
            assert_eq!(req, roundtrip(&req));

            let req = NodeLoggingRequest::SetLevel {
                facility: Some("auth".into()),
                level: LogLevel::Warn,
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeLoggingResponse::Ok;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_remote_access() {
            let req = NodeRemoteAccessRequest::SetConfig {
                cfg: RemoteAccessConfig {
                    ssh_enabled: true,
                    port: Some(22),
                    authorized_keys: vec!["ssh-ed25519 AAAA...".into()],
                },
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeRemoteAccessResponse::AuthorizedKeys {
                keys: vec!["ssh-ed25519 AAAA...".into()],
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_power() {
            let req = NodePowerRequest::Reboot {
                force: false,
                delay_seconds: Some(30),
            };
            assert_eq!(req, roundtrip(&req));

            let req = NodePowerRequest::Shutdown {
                force: true,
                delay_seconds: None,
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodePowerResponse::Status {
                scheduled_in_seconds: Some(30),
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_observation() {
            let req = NodeObservationRequest::ProcessInfo { pid: 42 };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeObservationResponse::ProcessList {
                processes: vec![Process {
                    user: "root".into(),
                    cpu_usage: 1.5,
                    mem_usage: 0.8,
                    start_time: 1_700_000_000,
                    command: "/usr/sbin/sshd".into(),
                }],
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeObservationResponse::ResourceUsage {
                usage: ResourceUsage {
                    cpu_usage: 45.2,
                    total_memory: 16_000_000_000,
                    used_memory: 8_000_000_000,
                    disk_used_bytes: 100_000_000_000,
                    disk_available_bytes: 400_000_000_000,
                },
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_version() {
            let req = NodeVersionRequest::CheckUpdate;
            assert_eq!(req, roundtrip(&req));

            let resp = NodeVersionResponse::UpdateAvailable {
                latest: "2.1.0".into(),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeVersionResponse::Version {
                version: "2.0.0".into(),
            };
            assert_eq!(resp, roundtrip(&resp));
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "client", feature = "server"))]
    use super::*;

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn event_kind_serialization_round_trip() {
        // Test that all EventKind variants can be serialized and deserialized
        let test_cases = vec![
            EventKind::DnsCovertChannel,
            EventKind::HttpThreat,
            EventKind::RdpBruteForce,
            EventKind::RepeatedHttpSessions,
            EventKind::ExtraThreat,
            EventKind::TorConnection,
            EventKind::DomainGenerationAlgorithm,
            EventKind::FtpBruteForce,
            EventKind::FtpPlainText,
            EventKind::PortScan,
            EventKind::MultiHostPortScan,
            EventKind::NonBrowser,
            EventKind::LdapBruteForce,
            EventKind::LdapPlainText,
            EventKind::ExternalDdos,
            EventKind::CryptocurrencyMiningPool,
            EventKind::BlocklistConn,
            EventKind::BlocklistDns,
            EventKind::BlocklistDceRpc,
            EventKind::BlocklistFtp,
            EventKind::BlocklistHttp,
            EventKind::BlocklistKerberos,
            EventKind::BlocklistLdap,
            EventKind::BlocklistMqtt,
            EventKind::BlocklistNfs,
            EventKind::BlocklistNtlm,
            EventKind::BlocklistRdp,
            EventKind::BlocklistSmb,
            EventKind::BlocklistSmtp,
            EventKind::BlocklistSsh,
            EventKind::BlocklistTls,
            EventKind::WindowsThreat,
            EventKind::NetworkThreat,
            EventKind::LockyRansomware,
            EventKind::SuspiciousTlsTraffic,
            EventKind::BlocklistBootp,
            EventKind::BlocklistDhcp,
            EventKind::TorConnectionConn,
            EventKind::BlocklistRadius,
            EventKind::BlocklistMalformedDns,
            EventKind::UnusualDestinationPattern,
        ];

        for kind in test_cases {
            // Serialize with bincode (used in the protocol)
            let serialized = bincode::serde::encode_to_vec(
                kind,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");

            // Deserialize back
            let (deserialized, _len): (EventKind, usize) = bincode::serde::decode_from_slice(
                &serialized,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");

            // Verify round-trip
            assert_eq!(kind, deserialized, "EventKind {kind:?} failed round-trip");
        }
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn event_message_with_blocklist_radius_serialization() {
        // Test EventMessage with BlocklistRadius variant
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::BlocklistRadius,
            fields: vec![1, 2, 3, 4, 5],
        };

        // Serialize with bincode (used in the protocol)
        let serialized = bincode::serde::encode_to_vec(
            &event,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("serialization should succeed");

        // Deserialize back
        let (deserialized, _len): (EventMessage, usize) = bincode::serde::decode_from_slice(
            &serialized,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("deserialization should succeed");

        // Verify the kind matches
        assert_eq!(
            event.kind, deserialized.kind,
            "EventKind should match after round-trip"
        );
        assert_eq!(
            event.fields, deserialized.fields,
            "Fields should match after round-trip"
        );
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn threat_level_serialization_round_trip() {
        // Test that all ThreatLevel variants can be serialized and deserialized
        let test_cases = vec![
            ThreatLevel::VeryLow,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::VeryHigh,
        ];

        for level in test_cases {
            // Serialize with bincode (used in the protocol)
            let serialized = bincode::serde::encode_to_vec(
                level,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");

            // Deserialize back
            let (deserialized, _len): (ThreatLevel, usize) = bincode::serde::decode_from_slice(
                &serialized,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");

            // Verify round-trip
            assert_eq!(
                level, deserialized,
                "ThreatLevel {level:?} failed round-trip"
            );
        }
    }
}
