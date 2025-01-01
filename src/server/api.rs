use anyhow::anyhow;
use bincode::Options;
use oinq::frame;

use super::Connection;
use crate::{client, types::HostNetworkGroup};

/// The server API.
impl Connection {
    /// Sends the allowlist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_allowlist(&self, allowlist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_list(client::RequestCode::AllowList, allowlist)
            .await
    }

    /// Sends the blocklist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_blocklist(&self, blocklist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_list(client::RequestCode::BlockList, blocklist)
            .await
    }

    /// Sends the internal network list.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_internal_network_list(&self, list: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_list(client::RequestCode::InternalNetworkList, list)
            .await
    }

    /// Sends a list of Tor exit nodes to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_tor_exit_node_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_list(client::RequestCode::TorExitNodeList, list)
            .await
    }

    /// Sends a list of trusted domains to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_domain_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_list(client::RequestCode::TrustedDomainList, list)
            .await
    }

    /// Sends the given payload to the client.
    async fn send_list<T: serde::Serialize + ?Sized>(
        &self,
        request_code: client::RequestCode,
        payload: &T,
    ) -> anyhow::Result<()> {
        let Ok(mut msg) = bincode::serialize::<u32>(&request_code.into()) else {
            unreachable!("serialization of u32 into memory buffer should not fail")
        };
        let ser = bincode::DefaultOptions::new();
        msg.extend(ser.serialize(payload)?);

        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &msg).await?;

        let mut response = vec![];
        frame::recv::<Result<(), String>>(&mut recv, &mut response)
            .await?
            .map_err(|e| anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_allowlist() {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::{test::TEST_ENV, types::HostNetworkGroup};

        struct Handler {}

        #[async_trait::async_trait]
        impl crate::request::Handler for Handler {
            async fn allow_list(&mut self, list: HostNetworkGroup) -> Result<(), String> {
                if list.hosts == [IP_ADDR_1] {
                    Ok(())
                } else {
                    Err("unexpected domain list".to_string())
                }
            }
        }

        const IP_ADDR_1: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let allowlist_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = Handler {};
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
}
