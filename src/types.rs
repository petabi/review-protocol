//! Data types used by the protocol.

use std::{net::IpAddr, ops::RangeInclusive};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// CPU, memory, and disk usage.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResourceUsage {
    /// The average CPU usage in percent.
    pub cpu_usage: f32,

    /// The RAM size in KB.
    pub total_memory: u64,

    /// The amount of used RAM in KB.
    pub used_memory: u64,

    /// The total disk space in bytes.
    pub total_disk_space: u64,

    /// The total disk space in bytes that is currently used.
    pub used_disk_space: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Process {
    pub user: String,
    pub cpu_usage: f32,
    pub mem_usage: f64,
    pub start_time: i64,
    pub command: String,
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    pub hosts: Vec<IpAddr>,
    pub networks: Vec<IpNet>,
    pub ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

// IP address, port numbers, and protocols.
pub type TrafficFilterRule = (IpNet, Option<Vec<u16>>, Option<Vec<u16>>);

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum EventCategory {
    Unknown = 0,
    Reconnaissance = 1,
    InitialAccess,
    Execution,
    CredentialAccess,
    Discovery,
    LateralMovement,
    CommandAndControl,
    Exfiltration,
    Impact,
}
