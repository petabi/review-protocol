use anyhow::anyhow;
use oinq::frame;

use super::Connection;
use crate::{
    client,
    types::{
        HostNetworkGroup, Process, ResourceUsage, SamplingPolicy, TrafficFilterRule,
        node::{
            NodeHostnameRequest, NodeHostnameResponse, NodeLoggingRequest, NodeLoggingResponse,
            NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse, NodeObservationRequest,
            NodeObservationResponse, NodePowerRequest, NodePowerResponse, NodeRemoteAccessRequest,
            NodeRemoteAccessResponse, NodeServiceRequest, NodeServiceResponse, NodeTimeSyncRequest,
            NodeTimeSyncResponse, NodeVersionRequest, NodeVersionResponse,
        },
    },
};

/// The server API.
impl Connection {
    /// Fetches the list of processes running on the agent.
    ///
    /// This is a compatibility wrapper that routes through
    /// [`node_observation`](Self::node_observation) internally.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn get_process_list(&self) -> anyhow::Result<Vec<Process>> {
        match self
            .node_observation(NodeObservationRequest::ProcessList)
            .await?
        {
            NodeObservationResponse::ProcessList { processes } => Ok(processes),
            other => Err(anyhow!("unexpected node_observation response: {other:?}")),
        }
    }

    /// Fetches the resource usage of an agent.
    ///
    /// This is a compatibility wrapper that routes through
    /// [`node_observation`](Self::node_observation) internally.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn get_resource_usage(&self) -> anyhow::Result<ResourceUsage> {
        match self
            .node_observation(NodeObservationRequest::ResourceUsage)
            .await?
        {
            NodeObservationResponse::ResourceUsage { resource_usage, .. } => Ok(resource_usage),
            other => Err(anyhow!("unexpected node_observation response: {other:?}")),
        }
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
    /// This is a compatibility wrapper that routes through
    /// [`node_power`](Self::node_power) internally.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn send_reboot_cmd(&self) -> anyhow::Result<()> {
        self.node_power(NodePowerRequest::Reboot).await.map(|_| ())
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
    /// This is a compatibility wrapper that routes through
    /// [`node_power`](Self::node_power) internally.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn send_shutdown_cmd(&self) -> anyhow::Result<()> {
        self.node_power(NodePowerRequest::Shutdown)
            .await
            .map(|_| ())
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

    // ── node feature-family methods ──────────────────────────────
    //
    // One method per node feature family. Each accepts the
    // corresponding typed `Node*Request` and returns the matching
    // `Node*Response`, routing through the internal `RequestCode`
    // mapping.

    /// Sends a node service-control request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_service(
        &self,
        req: NodeServiceRequest,
    ) -> anyhow::Result<NodeServiceResponse> {
        self.send_request(client::RequestCode::NodeService, &req)
            .await
    }

    /// Sends a node network-interface management request to the
    /// agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_network_interface(
        &self,
        req: NodeNetworkInterfaceRequest,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.send_request(client::RequestCode::NodeNetworkInterface, &req)
            .await
    }

    /// Sends a node hostname management request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_hostname(
        &self,
        req: NodeHostnameRequest,
    ) -> anyhow::Result<NodeHostnameResponse> {
        self.send_request(client::RequestCode::NodeHostname, &req)
            .await
    }

    /// Sends a node time-synchronization request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_time_sync(
        &self,
        req: NodeTimeSyncRequest,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.send_request(client::RequestCode::NodeTimeSync, &req)
            .await
    }

    /// Sends a node logging-configuration request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_logging(
        &self,
        req: NodeLoggingRequest,
    ) -> anyhow::Result<NodeLoggingResponse> {
        self.send_request(client::RequestCode::NodeLogging, &req)
            .await
    }

    /// Sends a node remote-access configuration request to the
    /// agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_remote_access(
        &self,
        req: NodeRemoteAccessRequest,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.send_request(client::RequestCode::NodeRemoteAccess, &req)
            .await
    }

    /// Sends a node power-control request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_power(&self, req: NodePowerRequest) -> anyhow::Result<NodePowerResponse> {
        self.send_request(client::RequestCode::NodePower, &req)
            .await
    }

    /// Sends a node host-observation request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_observation(
        &self,
        req: NodeObservationRequest,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.send_request(client::RequestCode::NodeObservation, &req)
            .await
    }

    /// Sends a node version-management request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_version(
        &self,
        req: NodeVersionRequest,
    ) -> anyhow::Result<NodeVersionResponse> {
        self.send_request(client::RequestCode::NodeVersion, &req)
            .await
    }

    // ── authorized node feature-family methods ───────────────────
    //
    // Like the un-authorized node methods above, but each checks
    // the provided `Authorizer` before sending the request.

    /// Sends a node service-control request to the agent with
    /// authorization.
    ///
    /// Like [`node_service`](Self::node_service), but checks the
    /// `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_service_authorized(
        &self,
        req: NodeServiceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeServiceResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodeService, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends a node network-interface management request to the
    /// agent with authorization.
    ///
    /// Like [`node_network_interface`](Self::node_network_interface),
    /// but checks the `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_network_interface_authorized(
        &self,
        req: NodeNetworkInterfaceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeNetworkInterface,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node hostname management request to the agent with
    /// authorization.
    ///
    /// Like [`node_hostname`](Self::node_hostname), but checks the
    /// `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_hostname_authorized(
        &self,
        req: NodeHostnameRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeHostnameResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodeHostname, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends a node time-synchronization request to the agent with
    /// authorization.
    ///
    /// Like [`node_time_sync`](Self::node_time_sync), but checks
    /// the `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_time_sync_authorized(
        &self,
        req: NodeTimeSyncRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodeTimeSync, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends a node logging-configuration request to the agent with
    /// authorization.
    ///
    /// Like [`node_logging`](Self::node_logging), but checks the
    /// `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_logging_authorized(
        &self,
        req: NodeLoggingRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeLoggingResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodeLogging, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends a node remote-access configuration request to the
    /// agent with authorization.
    ///
    /// Like [`node_remote_access`](Self::node_remote_access), but
    /// checks the `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_remote_access_authorized(
        &self,
        req: NodeRemoteAccessRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeRemoteAccess,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node power-control request to the agent with
    /// authorization.
    ///
    /// Like [`node_power`](Self::node_power), but checks the
    /// `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_power_authorized(
        &self,
        req: NodePowerRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodePowerResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodePower, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends a node host-observation request to the agent with
    /// authorization.
    ///
    /// Like [`node_observation`](Self::node_observation), but
    /// checks the `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_observation_authorized(
        &self,
        req: NodeObservationRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeObservationResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodeObservation, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends a node version-management request to the agent with
    /// authorization.
    ///
    /// Like [`node_version`](Self::node_version), but checks the
    /// `Authorizer` before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_version_authorized(
        &self,
        req: NodeVersionRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeVersionResponse> {
        let sid = req.service_id();
        self.send_request_authorized(client::RequestCode::NodeVersion, &req, &sid, peer, authorizer)
            .await
    }

    /// Sends the given payload to the client.
    async fn send_request<T: serde::Serialize + ?Sized, S: serde::de::DeserializeOwned>(
        &self,
        request_code: client::RequestCode,
        payload: &T,
    ) -> anyhow::Result<S> {
        let code: u32 = request_code.into();
        let Ok(mut buf) = bincode::serde::encode_to_vec(
            code,
            bincode::config::standard().with_fixed_int_encoding(),
        ) else {
            unreachable!("serialization of u32 into memory buffer should not fail")
        };
        bincode::serde::encode_into_std_write(payload, &mut buf, bincode::config::standard())?;

        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &buf).await?;

        frame::recv::<Result<S, String>>(&mut recv, &mut buf)
            .await?
            .map_err(|e| anyhow!(e))
    }

    /// Checks authorization then sends the given payload to the
    /// client.
    async fn send_request_authorized<
        T: serde::Serialize + ?Sized,
        S: serde::de::DeserializeOwned,
    >(
        &self,
        request_code: client::RequestCode,
        payload: &T,
        service_id: &crate::service_id::ServiceId,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<S> {
        authorizer
            .authorize(peer, service_id)
            .map_err(|e| anyhow!(e))?;
        self.send_request(request_code, payload).await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use {
        crate::{
            test::TEST_ENV,
            types::{HostNetworkGroup, SamplingKind, SamplingPolicy},
        },
        ipnet::IpNet,
        std::{
            net::{IpAddr, Ipv4Addr},
            time::Duration,
        },
    };

    #[cfg(all(feature = "client", feature = "server"))]
    // Define a constant IP address for tests
    const IP_ADDR_1: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[cfg(all(feature = "client", feature = "server"))]
    // Shared handler for all tests
    struct TestHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for TestHandler {
        async fn node_service(
            &mut self,
            _req: super::NodeServiceRequest,
        ) -> Result<super::NodeServiceResponse, String> {
            Ok(super::NodeServiceResponse::Status { active: true })
        }

        async fn node_network_interface(
            &mut self,
            _req: super::NodeNetworkInterfaceRequest,
        ) -> Result<super::NodeNetworkInterfaceResponse, String> {
            Ok(super::NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            })
        }

        async fn node_hostname(
            &mut self,
            _req: super::NodeHostnameRequest,
        ) -> Result<super::NodeHostnameResponse, String> {
            Ok(super::NodeHostnameResponse::Get {
                hostname: "test-node".into(),
            })
        }

        async fn node_time_sync(
            &mut self,
            _req: super::NodeTimeSyncRequest,
        ) -> Result<super::NodeTimeSyncResponse, String> {
            Ok(super::NodeTimeSyncResponse::Done)
        }

        async fn node_logging(
            &mut self,
            _req: super::NodeLoggingRequest,
        ) -> Result<super::NodeLoggingResponse, String> {
            Ok(super::NodeLoggingResponse::Done)
        }

        async fn node_remote_access(
            &mut self,
            _req: super::NodeRemoteAccessRequest,
        ) -> Result<super::NodeRemoteAccessResponse, String> {
            Ok(super::NodeRemoteAccessResponse::Done)
        }

        async fn node_power(
            &mut self,
            _req: super::NodePowerRequest,
        ) -> Result<super::NodePowerResponse, String> {
            Ok(super::NodePowerResponse::Initiated)
        }

        async fn node_observation(
            &mut self,
            req: super::NodeObservationRequest,
        ) -> Result<super::NodeObservationResponse, String> {
            match req {
                super::NodeObservationRequest::ProcessList => {
                    Ok(super::NodeObservationResponse::ProcessList {
                        processes: vec![super::Process {
                            user: "test-user".to_string(),
                            cpu_usage: 10.0,
                            mem_usage: 20.0,
                            start_time: 1_234_567_890,
                            command: "test-command".to_string(),
                        }],
                    })
                }
                super::NodeObservationRequest::ResourceUsage => {
                    Ok(super::NodeObservationResponse::ResourceUsage {
                        hostname: "test-host".into(),
                        resource_usage: super::ResourceUsage {
                            cpu_usage: 0.5,
                            total_memory: 100,
                            used_memory: 50,
                            disk_used_bytes: 500,
                            disk_available_bytes: 500,
                        },
                    })
                }
                super::NodeObservationRequest::Uptime => Err("not supported".to_string()),
            }
        }

        async fn node_version(
            &mut self,
            _req: super::NodeVersionRequest,
        ) -> Result<super::NodeVersionResponse, String> {
            Ok(super::NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "1.0.0".into(),
            })
        }

        async fn allowlist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected domain list".to_string())
            }
        }

        async fn blocklist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected blocklist".to_string())
            }
        }

        async fn update_config(&mut self) -> Result<(), String> {
            Ok(())
        }

        async fn update_traffic_filter_rules(
            &mut self,
            rules: &[super::TrafficFilterRule],
        ) -> Result<(), String> {
            if rules.len() == 1 {
                Ok(())
            } else {
                Err("unexpected filtering rules".to_string())
            }
        }

        async fn internal_network_list(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected internal network list".to_string())
            }
        }

        async fn sampling_policy_list(
            &mut self,
            policies: &[super::SamplingPolicy],
        ) -> Result<(), String> {
            if policies.len() == 1 && policies[0].id == 42 {
                Ok(())
            } else {
                Err("unexpected sampling policies".to_string())
            }
        }

        async fn tor_exit_node_list(&mut self, nodes: &[&str]) -> Result<(), String> {
            if nodes == ["192.168.1.1", "10.0.0.1"] {
                Ok(())
            } else {
                Err("unexpected tor exit node list".to_string())
            }
        }

        async fn trusted_domain_list(&mut self, domains: &[&str]) -> Result<(), String> {
            if domains == ["example.com", "test.org"] {
                Ok(())
            } else {
                Err("unexpected trusted domain list".to_string())
            }
        }

        async fn trusted_user_agent_list(&mut self, agents: &[&str]) -> Result<(), String> {
            if agents == ["Mozilla/5.0", "Chrome/91.0"] {
                Ok(())
            } else {
                Err("unexpected trusted user agent list".to_string())
            }
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
    async fn get_process_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.get_process_list().await;
        assert!(server_res.is_ok());
        let processes = server_res.unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].user, "test-user");
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

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_blocklist() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let blocklist_to_send = HostNetworkGroup {
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
        let server_res = server_conn.send_blocklist(&blocklist_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_config_update_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_config_update_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_filtering_rules() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let filtering_rules_to_send = vec![(
            "0.0.0.0/0".parse::<IpNet>().unwrap(),
            Some(vec![80]),
            Some(vec![6]),
        )];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_filtering_rules(&filtering_rules_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_internal_network_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let internal_network_list_to_send = HostNetworkGroup {
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
        let server_res = server_conn
            .send_internal_network_list(&internal_network_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_sampling_policies() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let sampling_policies_to_send = vec![SamplingPolicy {
            id: 42,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(60),
            period: Duration::from_secs(3600),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: None,
            column: None,
        }];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_sampling_policies(&sampling_policies_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_tor_exit_node_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let tor_exit_node_list_to_send = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_tor_exit_node_list(&tor_exit_node_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_trusted_domain_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let trusted_domain_list_to_send = vec!["example.com".to_string(), "test.org".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_trusted_domain_list(&trusted_domain_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_trusted_user_agent_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let trusted_user_agent_list_to_send =
            vec!["Mozilla/5.0".to_string(), "Chrome/91.0".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_trusted_user_agent_list(&trusted_user_agent_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_ping() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_ping().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_shutdown_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_shutdown_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    // ── node feature-family round-trip tests ──────────────────────

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_service() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeServiceRequest::Status {
            service: "nginx".into(),
        };
        let resp = server_conn.node_service(req).await.unwrap();
        assert_eq!(resp, NodeServiceResponse::Status { active: true });

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_network_interface() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeNetworkInterfaceRequest::List {
            prefix: Some("eth".into()),
        };
        let resp = server_conn.node_network_interface(req).await.unwrap();
        assert_eq!(
            resp,
            NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_hostname() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeHostnameRequest::Get;
        let resp = server_conn.node_hostname(req).await.unwrap();
        assert_eq!(
            resp,
            NodeHostnameResponse::Get {
                hostname: "test-node".into(),
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_time_sync() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeTimeSyncRequest::Set {
            servers: vec!["0.pool.ntp.org".into()],
        };
        let resp = server_conn.node_time_sync(req).await.unwrap();
        assert_eq!(resp, NodeTimeSyncResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_logging() {
        use crate::types::node::{NodeLoggingRequest, NodeLoggingResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeLoggingRequest::Get;
        let resp = server_conn.node_logging(req).await.unwrap();
        assert_eq!(resp, NodeLoggingResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_remote_access() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeRemoteAccessRequest::Set {
            config: NodeRemoteAccessConfig { port: 22 },
        };
        let resp = server_conn.node_remote_access(req).await.unwrap();
        assert_eq!(resp, NodeRemoteAccessResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodePowerRequest::GracefulReboot;
        let resp = server_conn.node_power(req).await.unwrap();
        assert_eq!(resp, NodePowerResponse::Initiated);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_observation() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeObservationRequest::ResourceUsage;
        let resp = server_conn.node_observation(req).await.unwrap();
        assert_eq!(
            resp,
            NodeObservationResponse::ResourceUsage {
                hostname: "test-host".into(),
                resource_usage: super::ResourceUsage {
                    cpu_usage: 0.5,
                    total_memory: 100,
                    used_memory: 50,
                    disk_used_bytes: 500,
                    disk_available_bytes: 500,
                },
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power_authorization_allowed() {
        use crate::auth::{NoopAuthorizer, PeerContext};
        use crate::types::node::{NodePowerRequest, NodePowerResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let peer = PeerContext::new("test-agent");
        let authorizer = NoopAuthorizer;
        let req = NodePowerRequest::Reboot;
        let resp = server_conn
            .node_power_authorized(req, &peer, &authorizer)
            .await
            .unwrap();
        assert_eq!(resp, NodePowerResponse::Initiated);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power_authorization_denied() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;
        use crate::types::node::NodePowerRequest;

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

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let authorizer = DenyAll;
        let req = NodePowerRequest::Reboot;
        let result = server_conn
            .node_power_authorized(req, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        // No client handler needed — request should not be sent.
        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_observation_authorization_selective() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;
        use crate::types::node::{
            NodeObservationRequest, NodeObservationResponse, NodePowerRequest,
        };

        /// Allows observation but denies power operations.
        struct ObservationOnly;
        impl Authorizer for ObservationOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if service.family == "node.observation" {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("only observation allowed"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let authorizer = ObservationOnly;

        // Observation should be allowed.
        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let resp = server_conn
            .node_observation_authorized(NodeObservationRequest::ResourceUsage, &peer, &authorizer)
            .await
            .unwrap();
        assert_eq!(
            resp,
            NodeObservationResponse::ResourceUsage {
                hostname: "test-host".into(),
                resource_usage: super::ResourceUsage {
                    cpu_usage: 0.5,
                    total_memory: 100,
                    used_memory: 50,
                    disk_used_bytes: 500,
                    disk_available_bytes: 500,
                },
            }
        );
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        // Power should be denied.
        let result = server_conn
            .node_power_authorized(NodePowerRequest::Reboot, &peer, &authorizer)
            .await;
        assert!(result.is_err());

        test_env.teardown(&server_conn);
    }

    /// Verifies that authorized node methods discriminate at the
    /// method level within a single family.  For example, an
    /// authorizer can allow `node.power.reboot` while denying
    /// `node.power.shutdown`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power_authorization_method_level() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::{self, ServiceId};
        use crate::types::node::{NodePowerRequest, NodePowerResponse};

        /// Allows only `node.power.reboot`, denies everything else.
        struct RebootOnly;
        impl Authorizer for RebootOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if *service == service_id::NODE_POWER_REBOOT {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("only reboot allowed"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let authorizer = RebootOnly;

        // Reboot should be allowed.
        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let resp = server_conn
            .node_power_authorized(NodePowerRequest::Reboot, &peer, &authorizer)
            .await
            .unwrap();
        assert_eq!(resp, NodePowerResponse::Initiated);
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        // Shutdown (same family, different method) should be denied.
        let result = server_conn
            .node_power_authorized(NodePowerRequest::Shutdown, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only reboot allowed")
        );

        // GracefulReboot should also be denied.
        let result = server_conn
            .node_power_authorized(NodePowerRequest::GracefulReboot, &peer, &authorizer)
            .await;
        assert!(result.is_err());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_version() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeVersionRequest::Get;
        let resp = server_conn.node_version(req).await.unwrap();
        assert_eq!(
            resp,
            NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "1.0.0".into(),
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }
}
