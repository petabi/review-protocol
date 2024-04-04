//! Request handling for the agent.

use async_trait::async_trait;
use num_enum::{FromPrimitive, IntoPrimitive};
pub use oinq::request::{parse_args, send_response};
use thiserror::Error;

use crate::types::{Config, HostNetworkGroup, Process, ResourceUsage, TrafficFilterRule};

/// Numeric representation of the message types.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
enum RequestCode {
    /// Start DNS filtering
    DnsStart = 1,

    /// Stop DNS filtering
    DnsStop = 2,

    /// Reboot the host
    Reboot = 4,

    /// Reload the configuration
    ReloadConfig = 6,

    /// Fetch the TI database and reload it
    ReloadTi = 5,

    /// Collect resource usage stats
    ResourceUsage = 7,

    /// Update the list of tor exit nodes
    TorExitNodeList = 8,

    /// Update the list of sampling policies
    SamplingPolicyList = 9,

    /// Update traffic filter rules
    ReloadFilterRule = 10,

    /// Get configuration
    GetConfig = 11,

    /// Set Configuration
    SetConfig = 12,

    /// Delete the list of sampling policies
    DeleteSamplingPolicy = 13,

    /// Update the list of Internal network
    InternalNetworkList = 14,

    /// Update the list of allow
    AllowList = 15,

    /// Update the list of block
    BlockList = 16,

    /// Request Echo (for ping)
    EchoRequest = 17,

    /// Update the list of trusted User-agent
    TrustedUserAgentList = 18,

    /// Update the list of trusted domains
    TrustedDomainList = 0,

    /// Collect process list
    ProcessList = 19,

    /// Update the semi-supervised models
    SemiSupervisedModels = 20,

    /// Shutdown the host
    Shutdown = 21,

    /// Unknown request
    #[num_enum(default)]
    Unknown = u32::MAX,
}
/// The error type for handling a request.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to receive request")]
    RecvError(#[from] oinq::frame::RecvError),
    #[error("failed to send response")]
    SendError(#[from] oinq::frame::SendError),
}

/// A request handler that can handle a request to an agent.
#[allow(clippy::diverging_sub_expression)]
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

    async fn reload_config(&mut self) -> Result<(), String> {
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
    async fn sampling_policy_list(&mut self, _policies: &[u8]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn update_traffic_filter_rules(
        &mut self,
        _rules: &[TrafficFilterRule],
    ) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn get_config(&mut self) -> Result<Config, String> {
        return Err("not supported".to_string());
    }

    async fn set_config(&mut self, _config: Config) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn delete_sampling_policy(&mut self, _policies_id: &[u8]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn internal_network_list(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn allow_list(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn block_list(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
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
            Err(oinq::frame::RecvError::ReadError(quinn::ReadExactError::FinishedEarly)) => {
                break;
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        let req = RequestCode::from_primitive(code);
        match req {
            RequestCode::DnsStart => {
                send_response(send, &mut buf, handler.dns_start().await).await?;
            }
            RequestCode::DnsStop => {
                send_response(send, &mut buf, handler.dns_stop().await).await?;
            }
            RequestCode::Reboot => {
                send_response(send, &mut buf, handler.reboot().await).await?;
            }
            RequestCode::ReloadConfig => {
                send_response(send, &mut buf, handler.reload_config().await).await?;
            }
            RequestCode::ReloadTi => {
                let version = parse_args::<&str>(body)?;
                let result = handler.reload_ti(version).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::ResourceUsage => {
                send_response(send, &mut buf, handler.resource_usage().await).await?;
            }
            RequestCode::TorExitNodeList => {
                let nodes = parse_args::<Vec<&str>>(body)?;
                let result = handler.tor_exit_node_list(&nodes).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::SamplingPolicyList => {
                let result = handler.sampling_policy_list(body).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::DeleteSamplingPolicy => {
                let result = handler.delete_sampling_policy(body).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::TrustedDomainList => {
                let domains = parse_args::<Result<Vec<&str>, String>>(body)?;
                let result = if let Ok(domains) = domains {
                    handler.trusted_domain_list(&domains).await
                } else {
                    Err("invalid request".to_string())
                };
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::InternalNetworkList => {
                let network_list = parse_args::<HostNetworkGroup>(body)?;
                let result = handler.internal_network_list(network_list).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::AllowList => {
                let allow_list = parse_args::<HostNetworkGroup>(body)?;
                let result = handler.allow_list(allow_list).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::BlockList => {
                let block_list = parse_args::<HostNetworkGroup>(body)?;
                let result = handler.block_list(block_list).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::EchoRequest => {
                send_response(send, &mut buf, Ok::<(), String>(())).await?;
            }
            RequestCode::TrustedUserAgentList => {
                let user_agent_list = parse_args::<Vec<&str>>(body)?;
                let result = handler.trusted_user_agent_list(&user_agent_list).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReloadFilterRule => {
                let rules = parse_args::<Vec<TrafficFilterRule>>(body)?;
                let result = handler.update_traffic_filter_rules(&rules).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetConfig => {
                send_response(send, &mut buf, handler.get_config().await).await?;
            }
            RequestCode::SetConfig => {
                let conf = parse_args::<Config>(body)?;
                let result = handler.set_config(conf).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::ProcessList => {
                send_response(send, &mut buf, handler.process_list().await).await?;
            }
            RequestCode::SemiSupervisedModels => {
                let result = handler.update_semi_supervised_models(body).await;
                send_response(send, &mut buf, result).await?;
            }
            RequestCode::Shutdown => {
                send_response(send, &mut buf, handler.shutdown().await).await?;
            }
            RequestCode::Unknown => {
                let err_msg = format!("unknown request code: {code}");
                oinq::message::send_err(send, &mut buf, err_msg).await?;
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
}
