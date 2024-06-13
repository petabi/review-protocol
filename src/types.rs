//! Data types used by the protocol.

use std::{
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
};

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

#[derive(Debug, Deserialize, Serialize)]
pub enum Config {
    Hog(HogConfig),
    Piglet(PigletConfig),
    Crusher(CrusherConfig),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HogConfig {
    pub giganto_address: Option<SocketAddr>,
    pub active_protocols: Option<Vec<String>>,
    pub active_sources: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PigletConfig {
    pub giganto_address: Option<SocketAddr>,
    pub log_options: Option<Vec<String>>,
    pub http_file_types: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CrusherConfig {
    pub giganto_ingest_address: Option<SocketAddr>,
    pub giganto_publish_address: Option<SocketAddr>,
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    pub hosts: Vec<IpAddr>,
    pub networks: Vec<IpNet>,
    pub ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

// IP address, port numbers, and protocols.
pub type TrafficFilterRule = (IpNet, Option<Vec<u16>>, Option<Vec<u16>>);
