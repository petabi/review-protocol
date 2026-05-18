//! Service-family entry point for node operations.
//!
//! This module provides a [`Node`] handle that groups all
//! REview-to-agent node API calls under a single,
//! discoverable namespace.  It is the recommended way to
//! interact with the node API family for new code.
//!
//! # Obtaining a handle
//!
//! A [`Node`] handle is obtained from a
//! [`Connection`](super::Connection) via
//! [`Connection::node()`](super::Connection::node):
//!
//! ```rust,no_run
//! # use review_protocol::server::Connection;
//! # async fn example(conn: Connection) -> anyhow::Result<()> {
//! use review_protocol::types::node::NodePowerRequest;
//!
//! let node = conn.node();
//! let resp = node.power(NodePowerRequest::GracefulReboot).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Immediate power operations
//!
//! [`Node::reboot`] and [`Node::shutdown`] send the request and
//! return immediately without waiting for a response.  The agent
//! may close the connection while processing the command:
//!
//! ```rust,no_run
//! # use review_protocol::server::Connection;
//! # async fn example(conn: Connection) -> anyhow::Result<()> {
//! let node = conn.node();
//! node.reboot().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Authorization
//!
//! Every method has an `_authorized` variant that checks an
//! [`Authorizer`](crate::auth::Authorizer) before sending the
//! request.  The method-level
//! [`ServiceId`](crate::service_id::ServiceId) is extracted
//! from the typed request automatically:
//!
//! ```rust,no_run
//! # use review_protocol::server::Connection;
//! # async fn example(
//! #     conn: Connection,
//! #     peer: review_protocol::auth::PeerContext,
//! #     authorizer: review_protocol::auth::NoopAuthorizer,
//! # ) -> anyhow::Result<()> {
//! use review_protocol::types::node::NodePowerRequest;
//!
//! let node = conn.node();
//! let resp = node.power_authorized(
//!     NodePowerRequest::GracefulReboot,
//!     &peer,
//!     &authorizer,
//! ).await?;
//! # Ok(())
//! # }
//! ```

use crate::types::node::{
    NodeHostnameRequest, NodeHostnameResponse, NodeLoggingRequest, NodeLoggingResponse,
    NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse, NodeObservationRequest,
    NodeObservationResponse, NodePowerRequest, NodePowerResponse, NodeRemoteAccessRequest,
    NodeRemoteAccessResponse, NodeServiceRequest, NodeServiceResponse, NodeTimeSyncRequest,
    NodeTimeSyncResponse, NodeVersionRequest, NodeVersionResponse,
};

/// Result of a node power-control operation.
///
/// Immediate operations ([`NodePowerRequest::Reboot`],
/// [`NodePowerRequest::Shutdown`]) return [`Sent`](Self::Sent) after
/// the request frame has been written and the send stream finished.
/// The agent may close the connection while processing the command,
/// so no response is awaited.
///
/// Graceful operations ([`NodePowerRequest::GracefulReboot`],
/// [`NodePowerRequest::GracefulShutdown`]) return
/// [`Response`](Self::Response) after receiving the agent's
/// acknowledgment.
#[derive(Debug)]
pub enum NodePowerOutcome {
    /// The request was sent successfully; no response is expected.
    Sent,
    /// The agent responded with a [`NodePowerResponse`].
    Response(NodePowerResponse),
}

/// A handle for issuing node-family requests over an existing
/// [`Connection`](super::Connection).
///
/// `Node` borrows the underlying connection and exposes one
/// method per node feature family (service, network-interface,
/// hostname, time-sync, logging, remote-access, power,
/// observation, version).  Each method accepts the
/// corresponding typed `Node*Request` and returns the matching
/// `Node*Response`.
///
/// See the [module-level documentation](self) for usage
/// examples.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    conn: &'a super::Connection,
}

impl<'a> Node<'a> {
    pub(crate) fn new(conn: &'a super::Connection) -> Self {
        Self { conn }
    }

    /// Sends a node service-control request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn service(&self, req: NodeServiceRequest) -> anyhow::Result<NodeServiceResponse> {
        self.conn.node_service(req).await
    }

    /// Sends a node service-control request with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn service_authorized(
        &self,
        req: NodeServiceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeServiceResponse> {
        self.conn
            .node_service_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node network-interface management request to the
    /// agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn network_interface(
        &self,
        req: NodeNetworkInterfaceRequest,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.conn.node_network_interface(req).await
    }

    /// Sends a node network-interface management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn network_interface_authorized(
        &self,
        req: NodeNetworkInterfaceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.conn
            .node_network_interface_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node hostname management request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn hostname(&self, req: NodeHostnameRequest) -> anyhow::Result<NodeHostnameResponse> {
        self.conn.node_hostname(req).await
    }

    /// Sends a node hostname management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn hostname_authorized(
        &self,
        req: NodeHostnameRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeHostnameResponse> {
        self.conn
            .node_hostname_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node time-synchronization request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn time_sync(
        &self,
        req: NodeTimeSyncRequest,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.conn.node_time_sync(req).await
    }

    /// Sends a node time-synchronization request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn time_sync_authorized(
        &self,
        req: NodeTimeSyncRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.conn
            .node_time_sync_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node logging-configuration request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn logging(&self, req: NodeLoggingRequest) -> anyhow::Result<NodeLoggingResponse> {
        self.conn.node_logging(req).await
    }

    /// Sends a node logging-configuration request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn logging_authorized(
        &self,
        req: NodeLoggingRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeLoggingResponse> {
        self.conn
            .node_logging_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node remote-access configuration request to the
    /// agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn remote_access(
        &self,
        req: NodeRemoteAccessRequest,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.conn.node_remote_access(req).await
    }

    /// Sends a node remote-access configuration request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn remote_access_authorized(
        &self,
        req: NodeRemoteAccessRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.conn
            .node_remote_access_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node power-control request to the agent.
    ///
    /// Immediate operations (`Reboot`, `Shutdown`) return
    /// [`NodePowerOutcome::Sent`] after the request frame has been
    /// queued and the send stream finished.  The agent may close the
    /// connection while processing the command, so no response is
    /// awaited.
    ///
    /// Graceful operations (`GracefulReboot`, `GracefulShutdown`)
    /// return [`NodePowerOutcome::Response`] after receiving the
    /// agent's acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn power(&self, req: NodePowerRequest) -> anyhow::Result<NodePowerOutcome> {
        self.conn.node_power(req).await
    }

    /// Sends a node power-control request with authorization.
    ///
    /// See [`power`](Self::power) for the semantics of immediate
    /// vs graceful operations.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn power_authorized(
        &self,
        req: NodePowerRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodePowerOutcome> {
        self.conn.node_power_authorized(req, peer, authorizer).await
    }

    /// Reboots the node immediately.
    ///
    /// The request is sent and the send stream is finished without
    /// waiting for a response.  The agent may close the connection
    /// while processing the reboot command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn reboot(&self) -> anyhow::Result<()> {
        match self.power(NodePowerRequest::Reboot).await? {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Reboots the node immediately with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn reboot_authorized(
        &self,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<()> {
        match self
            .power_authorized(NodePowerRequest::Reboot, peer, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Shuts down the node immediately.
    ///
    /// The request is sent and the send stream is finished without
    /// waiting for a response.  The agent may close the connection
    /// while processing the shutdown command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        match self.power(NodePowerRequest::Shutdown).await? {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Shuts down the node immediately with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn shutdown_authorized(
        &self,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<()> {
        match self
            .power_authorized(NodePowerRequest::Shutdown, peer, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Sends a node host-observation request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn observation(
        &self,
        req: NodeObservationRequest,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.conn.node_observation(req).await
    }

    /// Sends a node host-observation request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn observation_authorized(
        &self,
        req: NodeObservationRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.conn
            .node_observation_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node version-management request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn version(&self, req: NodeVersionRequest) -> anyhow::Result<NodeVersionResponse> {
        self.conn.node_version(req).await
    }

    /// Sends a node version-management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn version_authorized(
        &self,
        req: NodeVersionRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeVersionResponse> {
        self.conn
            .node_version_authorized(req, peer, authorizer)
            .await
    }

    // -- _with_context variants (AuthorizerV2) -----------------

    /// Sends a node service-control request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn service_with_context(
        &self,
        req: NodeServiceRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeServiceResponse> {
        self.conn
            .node_service_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node network-interface request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn network_interface_with_context(
        &self,
        req: NodeNetworkInterfaceRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.conn
            .node_network_interface_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node hostname request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn hostname_with_context(
        &self,
        req: NodeHostnameRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeHostnameResponse> {
        self.conn
            .node_hostname_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node time-synchronization request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn time_sync_with_context(
        &self,
        req: NodeTimeSyncRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.conn
            .node_time_sync_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node logging-configuration request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn logging_with_context(
        &self,
        req: NodeLoggingRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeLoggingResponse> {
        self.conn
            .node_logging_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node remote-access request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn remote_access_with_context(
        &self,
        req: NodeRemoteAccessRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.conn
            .node_remote_access_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node power-control request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// See [`power`](Self::power) for the semantics of immediate
    /// vs graceful operations.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn power_with_context(
        &self,
        req: NodePowerRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodePowerOutcome> {
        self.conn
            .node_power_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Reboots the node immediately with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn reboot_with_context(
        &self,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<()> {
        match self
            .power_with_context(NodePowerRequest::Reboot, auth_ctx, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Shuts down the node immediately with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn shutdown_with_context(
        &self,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<()> {
        match self
            .power_with_context(NodePowerRequest::Shutdown, auth_ctx, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Sends a node host-observation request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn observation_with_context(
        &self,
        req: NodeObservationRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.conn
            .node_observation_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node version-management request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn version_with_context(
        &self,
        req: NodeVersionRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeVersionResponse> {
        self.conn
            .node_version_with_context(req, auth_ctx, authorizer)
            .await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use super::NodePowerOutcome;
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::test::TEST_ENV;
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::types::node::*;

    #[cfg(all(feature = "client", feature = "server"))]
    struct TestHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for TestHandler {
        async fn node_power(
            &mut self,
            _req: NodePowerRequest,
        ) -> Result<NodePowerResponse, String> {
            Ok(NodePowerResponse::Initiated)
        }

        async fn node_observation(
            &mut self,
            req: NodeObservationRequest,
        ) -> Result<NodeObservationResponse, String> {
            match req {
                NodeObservationRequest::ProcessList => Ok(NodeObservationResponse::ProcessList {
                    processes: vec![crate::types::Process {
                        user: "test-user".to_string(),
                        cpu_usage: 10.0,
                        mem_usage: 20.0,
                        start_time: 1_234_567_890,
                        command: "test-command".to_string(),
                    }],
                }),
                NodeObservationRequest::ResourceUsage => {
                    Ok(NodeObservationResponse::ResourceUsage {
                        hostname: "test-host".into(),
                        resource_usage: crate::types::ResourceUsage {
                            cpu_usage: 0.5,
                            total_memory: 100,
                            used_memory: 50,
                            disk_used_bytes: 500,
                            disk_available_bytes: 500,
                        },
                    })
                }
                NodeObservationRequest::Uptime => Err("not supported".to_string()),
            }
        }

        async fn node_service(
            &mut self,
            _req: NodeServiceRequest,
        ) -> Result<NodeServiceResponse, String> {
            Ok(NodeServiceResponse::Status { active: true })
        }
    }

    /// Verifies that `Node::power` produces the same result as
    /// `Connection::node_power`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let node = server_conn.node();
        let resp = node.power(NodePowerRequest::GracefulReboot).await.unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_authorized` checks
    /// authorization and produces the same result as
    /// `Connection::node_power_authorized`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_authorized_via_node_handle() {
        use crate::auth::{NoopAuthorizer, PeerContext};

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
        let node = server_conn.node();
        let resp = node
            .power_authorized(NodePowerRequest::GracefulReboot, &peer, &authorizer)
            .await
            .unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_authorized` returns an error
    /// when the authorizer denies the request.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_authorized_denied_via_node_handle() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;

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
        let node = server_conn.node();
        let result = node
            .power_authorized(NodePowerRequest::Reboot, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::observation` produces the same
    /// result as `Connection::node_observation`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn observation_via_node_handle() {
        use crate::types::ResourceUsage;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let node = server_conn.node();
        let resp = node
            .observation(NodeObservationRequest::ResourceUsage)
            .await
            .unwrap();
        assert_eq!(
            resp,
            NodeObservationResponse::ResourceUsage {
                hostname: "test-host".into(),
                resource_usage: ResourceUsage {
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

    /// Verifies that `Node::power_with_context` allows a request
    /// when the `AuthorizerV2` permits it.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_with_context_via_node_handle() {
        use crate::auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = AuthorizerV2Adapter::new(NoopAuthorizer);
        let node = server_conn.node();
        let resp = node
            .power_with_context(NodePowerRequest::GracefulReboot, &auth_ctx, &authorizer)
            .await
            .unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_with_context` denies a request
    /// when an `AuthorizerV2` checks roles.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_with_context_denied_by_role() {
        use crate::auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext};
        use crate::service_id::ServiceId;

        struct RequireAdmin;
        impl AuthorizerV2 for RequireAdmin {
            fn authorize_with_context(
                &self,
                ctx: &AuthorizationContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if ctx.roles().is_some_and(|r| r.iter().any(|s| s == "admin")) {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("admin required"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = RequireAdmin;
        let node = server_conn.node();
        let result = node
            .power_with_context(NodePowerRequest::Reboot, &auth_ctx, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::service` works via the node handle.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn service_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let node = server_conn.node();
        let resp = node
            .service(NodeServiceRequest::Status {
                service: "nginx".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp, NodeServiceResponse::Status { active: true });

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power` with `Reboot` returns `Sent`
    /// and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_reboot_returns_sent() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        // Client accepts the stream but closes it immediately without
        // sending a response, simulating an agent that reboots.
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            // Read the request frame
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            // Close the send side without sending a response
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.power(NodePowerRequest::Reboot).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), NodePowerOutcome::Sent));

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power` with `Shutdown` returns `Sent`
    /// and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_shutdown_returns_sent() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.power(NodePowerRequest::Shutdown).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), NodePowerOutcome::Sent));

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::reboot` succeeds without waiting for a
    /// response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn reboot_no_response() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.reboot().await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::shutdown` succeeds without waiting for a
    /// response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn shutdown_no_response() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.shutdown().await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::reboot_authorized` succeeds when
    /// authorized and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn reboot_authorized_no_response() {
        use crate::auth::{NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let peer = PeerContext::new("test-agent");
        let authorizer = NoopAuthorizer;
        let node = server_conn.node();
        let result = node.reboot_authorized(&peer, &authorizer).await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::shutdown_authorized` succeeds when
    /// authorized and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn shutdown_authorized_no_response() {
        use crate::auth::{NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let peer = PeerContext::new("test-agent");
        let authorizer = NoopAuthorizer;
        let node = server_conn.node();
        let result = node.shutdown_authorized(&peer, &authorizer).await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }
}
