use std::{collections::HashSet, io};

use serde::{Serialize, de::DeserializeOwned};

use super::Connection;
use crate::{
    server,
    types::{DataSource, DataSourceKey, HostNetworkGroup},
    unary_request,
};

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
            request(self, server::RequestCode::GetAllowlist, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of blocked networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_block_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetBlocklist, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches a data source from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_data_source(&self, key: &DataSourceKey<'_>) -> io::Result<DataSource> {
        let res: Result<Option<DataSource>, String> =
            request(self, server::RequestCode::GetDataSource, key).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .and_then(|res| res.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
    }

    /// Fetches an indicator from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_indicator(&self, name: &str) -> io::Result<HashSet<Vec<String>>> {
        let res: Result<HashSet<Vec<String>>, String> =
            request(self, server::RequestCode::GetIndicator, name).await?;
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

    /// Fetches the patterns from the threat-intelligence database.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_tidb_patterns(
        &self,
        tidbs: &[(&str, &str)],
    ) -> io::Result<Vec<(String, Option<crate::types::Tidb>)>> {
        let res: Result<Vec<(String, Option<crate::types::Tidb>)>, String> =
            request(self, server::RequestCode::GetTidbPatterns, tidbs).await?;
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

    /// Fetches the pretrained model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_pretrained_model(&self, name: &str) -> io::Result<Vec<u8>> {
        let res: Result<Vec<u8>, String> =
            request(self, server::RequestCode::GetPretrainedModel, name).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Obtain a new certificate from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn renew_certificate(&self, cert: &[u8]) -> io::Result<(String, String)> {
        let res: Result<(String, String), String> =
            request(self, server::RequestCode::RenewCertificate, cert).await?;
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

#[cfg(all(test, feature = "server"))]
mod tests {
    use crate::{
        server::handle,
        test::{TEST_ENV, TestServerHandler},
        types::DataSourceKey,
    };

    #[tokio::test]
    async fn get_data_source() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            let mut handler = TestServerHandler;
            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            handle(&mut handler, &mut send, &mut recv).await?;
            Ok(()) as std::io::Result<()>
        });

        let client_res = client_conn.get_data_source(&DataSourceKey::Id(5)).await;
        assert!(client_res.is_ok());
        let received_data_source = client_res.unwrap();
        assert_eq!(received_data_source.name, "name5");

        let server_res = server_handle.await.unwrap();
        assert!(server_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    async fn get_tidb_patterns() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            let mut handler = TestServerHandler;
            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            handle(&mut handler, &mut send, &mut recv).await?;
            Ok(()) as std::io::Result<()>
        });

        let db_names = vec![("db1", "1.0.0"), ("db2", "2.0.0")];
        let client_res = client_conn.get_tidb_patterns(&db_names).await;
        assert!(client_res.is_ok());
        let received_patterns = client_res.unwrap();
        assert_eq!(received_patterns.len(), db_names.len());
        assert_eq!(received_patterns[0].0, "db1");
        assert!(received_patterns[0].1.is_some());
        assert_eq!(received_patterns[1].0, "db2");
        assert!(received_patterns[1].1.is_none());
        let server_res = server_handle.await.unwrap();
        assert!(server_res.is_ok());

        test_env.teardown(&server_conn);
    }
}
