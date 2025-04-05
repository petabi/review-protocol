use anyhow::anyhow;
use bincode::Options;
use oinq::frame;

use super::Connection;
use crate::{
    client,
    types::{HostNetworkGroup, Process, ResourceUsage, SamplingPolicy, TrafficFilterRule},
};

/// The server API.
impl Connection {
    /// Fetches the list of processes running on the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn get_process_list(&self) -> anyhow::Result<Vec<Process>> {
        self.send_request(client::RequestCode::ProcessList, &())
            .await
    }

    /// Fetches the resource usage of an agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn get_resource_usage(&self) -> anyhow::Result<ResourceUsage> {
        self.send_request::<(), (String, ResourceUsage)>(client::RequestCode::ResourceUsage, &())
            .await
            .map(|(_, usage)| usage)
    }

    /// Sends the allowlist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_allowlist(&self, allowlist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Allowlist, allowlist)
            .await
    }

    /// Sends the blocklist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_blocklist(&self, blocklist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Blocklist, blocklist)
            .await
    }

    /// Sends the config-update command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_config_update_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::UpdateConfig, &())
            .await
    }

    /// Sends the traffic filtering rules.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_filtering_rules(&self, list: &[TrafficFilterRule]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::ReloadFilterRule, list)
            .await
    }

    /// Sends the internal network list.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_internal_network_list(&self, list: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::InternalNetworkList, list)
            .await
    }

    /// Sends the ping message.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_ping(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::EchoRequest, &())
            .await
    }

    /// Sends the reboot command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_reboot_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Reboot, &()).await
    }

    /// Sends the sampling policies.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_sampling_policies(&self, list: &[SamplingPolicy]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::SamplingPolicyList, list)
            .await
    }

    /// Sends the shutdown command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_shutdown_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Shutdown, &()).await
    }

    /// Sends a list of Tor exit nodes to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_tor_exit_node_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TorExitNodeList, list)
            .await
    }

    /// Sends a list of trusted domains to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_domain_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TrustedDomainList, list)
            .await
    }

    /// Sends a list of trusted user-agents to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_user_agent_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TrustedUserAgentList, list)
            .await
    }

    /// Sends the given payload to the client.
    async fn send_request<T: serde::Serialize + ?Sized, S: serde::de::DeserializeOwned>(
        &self,
        request_code: client::RequestCode,
        payload: &T,
    ) -> anyhow::Result<S> {
        let Ok(mut buf) = bincode::serialize::<u32>(&request_code.into()) else {
            unreachable!("serialization of u32 into memory buffer should not fail")
        };
        let ser = bincode::DefaultOptions::new();
        buf.extend(ser.serialize(payload)?);

        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &buf).await?;

        frame::recv::<Result<S, String>>(&mut recv, &mut buf)
            .await?
            .map_err(|e| anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use {
        crate::{test::TEST_ENV, types::HostNetworkGroup},
        std::net::{IpAddr, Ipv4Addr},
    };

    #[cfg(all(feature = "client", feature = "server"))]
    // Define a constant IP address for tests
    const IP_ADDR_1: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    #[cfg(all(feature = "client", feature = "server"))]
    // Shared handler for all tests
    struct TestHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for TestHandler {
        async fn allowlist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected domain list".to_string())
            }
        }

        async fn resource_usage(&mut self) -> Result<(String, super::ResourceUsage), String> {
            Ok((
                "test-host".to_string(),
                super::ResourceUsage {
                    cpu_usage: 0.5,
                    total_memory: 100,
                    used_memory: 50,
                    total_disk_space: 1000,
                    used_disk_space: 500,
                },
            ))
        }

        async fn reboot(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn get_resource_usage() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.get_resource_usage().await;
        assert!(server_res.is_ok());
        let usage = server_res.unwrap();
        assert_eq!(usage.total_memory, 100);
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_allowlist() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let allowlist_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_allowlist(&allowlist_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_reboot_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_reboot_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }
}
