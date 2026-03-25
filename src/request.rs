//! Request handling for the agent.

use std::io;

use async_trait::async_trait;
use num_enum::FromPrimitive;
pub use oinq::request::{parse_args, send_response};
use thiserror::Error;

use crate::{
    client::RequestCode,
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

/// The error type for handling a request.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to receive request")]
    RecvError(io::Error),
    #[error("failed to send response")]
    SendError(io::Error),
}

/// A request handler that can handle a request to an agent.
#[async_trait]
pub trait Handler: Send {
    async fn dns_start(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn dns_stop(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn forward(&mut self, _target: &str, _msg: &[u8]) -> Result<Vec<u8>, String> {
        return Err("not supported".to_string());
    }

    /// Reboots the system
    async fn reboot(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    #[deprecated(since = "0.4.1", note = "Use `update_config` instead")]
    async fn reload_config(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn update_config(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn reload_ti(&mut self, _version: &str) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    /// Returns the hostname and the cpu, memory, and disk usage.
    async fn resource_usage(&mut self) -> Result<(String, ResourceUsage), String> {
        return Err("not supported".to_string());
    }

    async fn tor_exit_node_list(&mut self, _nodes: &[&str]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn trusted_domain_list(&mut self, _domains: &[&str]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    /// Updates the list of sampling policies.
    async fn sampling_policy_list(&mut self, _policies: &[SamplingPolicy]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn update_traffic_filter_rules(
        &mut self,
        _rules: &[TrafficFilterRule],
    ) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn delete_sampling_policy(&mut self, _policies_ids: &[u32]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn internal_network_list(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn allowlist(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn blocklist(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn trusted_user_agent_list(&mut self, _list: &[&str]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn process_list(&mut self) -> Result<Vec<Process>, String> {
        return Err("not supported".to_string());
    }

    async fn update_semi_supervised_models(&mut self, _list: &[u8]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }
}

/// Handles requests to an agent.
///
/// # Errors
///
/// * `HandlerError::RecvError` if the request could not be received
/// * `HandlerError::SendError` if the response could not be sent
#[allow(clippy::too_many_lines)]
pub async fn handle<H: Handler>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<(), HandlerError> {
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(HandlerError::RecvError(e));
            }
        };

        let req = RequestCode::from_primitive(code);
        match req {
            RequestCode::DnsStart => {
                send_response(send, &mut buf, handler.dns_start().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::DnsStop => {
                send_response(send, &mut buf, handler.dns_stop().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::Reboot => {
                send_response(send, &mut buf, handler.reboot().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ReloadConfig => {
                #[allow(deprecated)]
                send_response(send, &mut buf, handler.reload_config().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ReloadTi => {
                let version = parse_args::<&str>(body).map_err(HandlerError::RecvError)?;
                let result = handler.reload_ti(version).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ResourceUsage => {
                send_response(send, &mut buf, handler.resource_usage().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::TorExitNodeList => {
                let nodes = parse_args::<Vec<&str>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.tor_exit_node_list(&nodes).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::SamplingPolicyList => {
                let list =
                    parse_args::<Vec<SamplingPolicy>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.sampling_policy_list(&list).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::DeleteSamplingPolicy => {
                let policy_ids = parse_args::<Vec<u32>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.delete_sampling_policy(&policy_ids).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::TrustedDomainList => {
                let domains = parse_args::<Vec<&str>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.trusted_domain_list(&domains).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::InternalNetworkList => {
                let network_list =
                    parse_args::<HostNetworkGroup>(body).map_err(HandlerError::RecvError)?;
                let result = handler.internal_network_list(network_list).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::Allowlist => {
                let allowlist =
                    parse_args::<HostNetworkGroup>(body).map_err(HandlerError::RecvError)?;
                let result = handler.allowlist(allowlist).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::Blocklist => {
                let blocklist =
                    parse_args::<HostNetworkGroup>(body).map_err(HandlerError::RecvError)?;
                let result = handler.blocklist(blocklist).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::EchoRequest => {
                send_response(send, &mut buf, Ok::<(), String>(()))
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::TrustedUserAgentList => {
                let user_agent_list =
                    parse_args::<Vec<&str>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.trusted_user_agent_list(&user_agent_list).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ReloadFilterRule => {
                let rules =
                    parse_args::<Vec<TrafficFilterRule>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.update_traffic_filter_rules(&rules).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::UpdateConfig => {
                let result = handler.update_config().await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ProcessList => {
                send_response(send, &mut buf, handler.process_list().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::SemiSupervisedModels => {
                let result = handler.update_semi_supervised_models(body).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::Shutdown => {
                send_response(send, &mut buf, handler.shutdown().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }

            // ── node feature-family dispatch ───────────────────
            //
            // Each arm deserializes the typed request payload to
            // validate the wire mapping. Handler methods for these
            // families will be added in a follow-up issue; until
            // then, every node request responds with "not supported".
            RequestCode::NodeService => {
                let _req =
                    parse_args::<NodeServiceRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeServiceResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeNetworkInterface => {
                let _req = parse_args::<NodeNetworkInterfaceRequest>(body)
                    .map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeNetworkInterfaceResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeHostname => {
                let _req =
                    parse_args::<NodeHostnameRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeHostnameResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeTimeSync => {
                let _req =
                    parse_args::<NodeTimeSyncRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeTimeSyncResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeLogging => {
                let _req =
                    parse_args::<NodeLoggingRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeLoggingResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeRemoteAccess => {
                let _req =
                    parse_args::<NodeRemoteAccessRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeRemoteAccessResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodePower => {
                let _req = parse_args::<NodePowerRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodePowerResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeObservation => {
                let _req =
                    parse_args::<NodeObservationRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeObservationResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeVersion => {
                let _req =
                    parse_args::<NodeVersionRequest>(body).map_err(HandlerError::RecvError)?;
                send_response(
                    send,
                    &mut buf,
                    Err::<NodeVersionResponse, String>("not supported".to_string()),
                )
                .await
                .map_err(HandlerError::SendError)?;
            }

            RequestCode::Unknown => {
                let err_msg = format!("unknown request code: {code}");
                oinq::message::send_err(send, &mut buf, err_msg)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_enum::FromPrimitive;

    use super::RequestCode;

    #[test]
    fn request_code_serde() {
        assert_eq!(7u32, u32::from(RequestCode::ResourceUsage));
        assert_eq!(RequestCode::ResourceUsage, RequestCode::from_primitive(7));
    }

    /// Verify that every node feature-family request code maps to a
    /// stable numeric value and round-trips through `FromPrimitive`.
    #[test]
    fn node_request_code_mapping() {
        let cases: &[(RequestCode, u32)] = &[
            (RequestCode::NodeService, 100),
            (RequestCode::NodeNetworkInterface, 101),
            (RequestCode::NodeHostname, 102),
            (RequestCode::NodeTimeSync, 103),
            (RequestCode::NodeLogging, 104),
            (RequestCode::NodeRemoteAccess, 105),
            (RequestCode::NodePower, 106),
            (RequestCode::NodeObservation, 107),
            (RequestCode::NodeVersion, 108),
        ];
        for &(code, num) in cases {
            assert_eq!(u32::from(code), num);
            assert_eq!(RequestCode::from_primitive(num), code);
        }
    }

    /// Verify that node request codes do not collide with existing
    /// (non-node) codes and that unknown values still map to `Unknown`.
    #[test]
    fn node_request_codes_no_collision() {
        // All existing non-node codes live in 0..=21; node codes
        // start at 100. Verify that the gap maps to Unknown.
        assert_eq!(RequestCode::from_primitive(50), RequestCode::Unknown);
        assert_eq!(RequestCode::from_primitive(99), RequestCode::Unknown);
        assert_eq!(RequestCode::from_primitive(109), RequestCode::Unknown);
    }

    #[cfg(feature = "server")]
    struct NoopHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for NoopHandler {}

    /// Dispatch round-trip test helper: sends a typed node request
    /// through `request::handle` and verifies that the new request-code
    /// arm accepts the typed payload and returns the current
    /// `Err("not supported")` placeholder until grouped handler
    /// methods are introduced.
    #[cfg(feature = "server")]
    async fn node_dispatch_roundtrip<Req, Resp>(code: RequestCode, req: Req)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::de::DeserializeOwned + std::fmt::Debug,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.unwrap_err(),
            "not supported",
            "node handler should respond with 'not supported'"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// Success-path round-trip test helper: sends a typed node request
    /// through the wire, responds with an `Ok(expected)` payload on
    /// the server side, and verifies that the client decodes the
    /// concrete response correctly.
    #[cfg(feature = "server")]
    async fn node_success_roundtrip<Req, Resp>(code: RequestCode, req: Req, expected: Resp)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + PartialEq
            + Clone
            + Send
            + 'static,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let resp_to_send = expected.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let (_code, _body) = oinq::message::recv_request_raw(&mut server_recv, &mut buf)
                .await
                .expect("should receive request");
            super::send_response(&mut server_send, &mut buf, Ok::<Resp, String>(resp_to_send))
                .await
                .expect("should send response");
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.expect("response should be Ok"),
            expected,
            "decoded response should match the sent payload"
        );

        drop(client_send);
        drop(client_recv);

        server_task.await.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_service_wire_roundtrip() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};
        node_dispatch_roundtrip::<_, NodeServiceResponse>(
            RequestCode::NodeService,
            NodeServiceRequest::Status {
                service: "nginx".into(),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_network_interface_wire_roundtrip() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};
        node_dispatch_roundtrip::<_, NodeNetworkInterfaceResponse>(
            RequestCode::NodeNetworkInterface,
            NodeNetworkInterfaceRequest::List {
                prefix: Some("eth".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_hostname_wire_roundtrip() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};
        node_dispatch_roundtrip::<_, NodeHostnameResponse>(
            RequestCode::NodeHostname,
            NodeHostnameRequest::Get,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_time_sync_wire_roundtrip() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};
        node_dispatch_roundtrip::<_, NodeTimeSyncResponse>(
            RequestCode::NodeTimeSync,
            NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into()],
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_logging_wire_roundtrip() {
        use crate::types::node::{NodeLoggingRequest, NodeLoggingResponse};
        node_dispatch_roundtrip::<_, NodeLoggingResponse>(
            RequestCode::NodeLogging,
            NodeLoggingRequest::Get,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_remote_access_wire_roundtrip() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };
        node_dispatch_roundtrip::<_, NodeRemoteAccessResponse>(
            RequestCode::NodeRemoteAccess,
            NodeRemoteAccessRequest::Set {
                config: NodeRemoteAccessConfig { port: 22 },
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_wire_roundtrip() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};
        node_dispatch_roundtrip::<_, NodePowerResponse>(
            RequestCode::NodePower,
            NodePowerRequest::GracefulReboot,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_wire_roundtrip() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        node_dispatch_roundtrip::<_, NodeObservationResponse>(
            RequestCode::NodeObservation,
            NodeObservationRequest::ResourceUsage,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_version_wire_roundtrip() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};
        node_dispatch_roundtrip::<_, NodeVersionResponse>(
            RequestCode::NodeVersion,
            NodeVersionRequest::SetOsVersion {
                version: "22.04".into(),
            },
        )
        .await;
    }

    // ── success-path wire round-trip tests ─────────────────────
    //
    // These tests verify that a concrete `Ok(response)` payload for
    // each node family can be framed, sent, and decoded correctly
    // on the client side.

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_service_success_roundtrip() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};
        node_success_roundtrip(
            RequestCode::NodeService,
            NodeServiceRequest::Status {
                service: "nginx".into(),
            },
            NodeServiceResponse::Status { active: true },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_network_interface_success_roundtrip() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};
        node_success_roundtrip(
            RequestCode::NodeNetworkInterface,
            NodeNetworkInterfaceRequest::List {
                prefix: Some("eth".into()),
            },
            NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_hostname_success_roundtrip() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};
        node_success_roundtrip(
            RequestCode::NodeHostname,
            NodeHostnameRequest::Get,
            NodeHostnameResponse::Get {
                hostname: "node-1".into(),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_time_sync_success_roundtrip() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};
        node_success_roundtrip(
            RequestCode::NodeTimeSync,
            NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into()],
            },
            NodeTimeSyncResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_logging_success_roundtrip() {
        use crate::types::node::{
            NodeLoggingEndpoint, NodeLoggingProtocol, NodeLoggingRequest, NodeLoggingResponse,
        };
        node_success_roundtrip(
            RequestCode::NodeLogging,
            NodeLoggingRequest::Get,
            NodeLoggingResponse::Get {
                endpoints: Some(vec![NodeLoggingEndpoint {
                    protocol: NodeLoggingProtocol::Tcp,
                    address: "192.168.1.100".into(),
                    port: 514,
                }]),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_remote_access_success_roundtrip() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };
        node_success_roundtrip(
            RequestCode::NodeRemoteAccess,
            NodeRemoteAccessRequest::Set {
                config: NodeRemoteAccessConfig { port: 22 },
            },
            NodeRemoteAccessResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_success_roundtrip() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};
        node_success_roundtrip(
            RequestCode::NodePower,
            NodePowerRequest::GracefulReboot,
            NodePowerResponse::Initiated,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_success_roundtrip() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        node_success_roundtrip(
            RequestCode::NodeObservation,
            NodeObservationRequest::ResourceUsage,
            NodeObservationResponse::ResourceUsage {
                hostname: "node-1".into(),
                resource_usage: crate::types::ResourceUsage {
                    cpu_usage: 45.2,
                    total_memory: 16_000_000_000,
                    used_memory: 8_000_000_000,
                    disk_used_bytes: 100_000_000_000,
                    disk_available_bytes: 400_000_000_000,
                },
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_version_success_roundtrip() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};
        node_success_roundtrip(
            RequestCode::NodeVersion,
            NodeVersionRequest::SetOsVersion {
                version: "22.04".into(),
            },
            NodeVersionResponse::Done,
        )
        .await;
    }
}
