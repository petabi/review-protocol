use std::io;

use serde::{de::DeserializeOwned, Serialize};

use super::Connection;
use crate::{server, types::HostNetworkGroup, unary_request};

/// The client API.
impl Connection {
    /// Fetches the configuration from the server.
    ///
    /// The format of the configuration is up to the caller to interpret.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_config(&self) -> io::Result<String> {
        let res: Result<String, String> = request(self, server::RequestCode::GetConfig, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of allowed networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_allow_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetAllowList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of blocked networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_block_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetBlockList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of internal networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_internal_network_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetInternalNetworkList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of Tor exit nodes from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_tor_exit_node_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTorExitNodeList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of trusted domains from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_domain_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedDomainList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of trusted user agents from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_user_agent_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedUserAgentList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

async fn request<I, O>(conn: &Connection, code: server::RequestCode, input: I) -> io::Result<O>
where
    I: Serialize,
    O: DeserializeOwned,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    unary_request(&mut send, &mut recv, u32::from(code), input).await
}
