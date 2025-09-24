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
        res.map_err(io::Error::other)
    }

    /// Fetches the list of allowed networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_allowlist(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetAllowlist, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of blocked networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_blocklist(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetBlocklist, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches a data source from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_data_source(&self, key: &DataSourceKey<'_>) -> io::Result<DataSource> {
        let res: Result<Option<DataSource>, String> =
            request(self, server::RequestCode::GetDataSource, key).await?;
        res.map_err(io::Error::other)
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
        res.map_err(io::Error::other)
    }

    /// Fetches the list of internal networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_internal_network_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetInternalNetworkList, ()).await?;
        res.map_err(io::Error::other)
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
        res.map_err(io::Error::other)
    }

    /// Fetches the list of Tor exit nodes from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_tor_exit_node_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTorExitNodeList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of trusted domains from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_domain_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedDomainList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of trusted user agents from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_user_agent_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedUserAgentList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the pretrained model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_pretrained_model(&self, name: &str) -> io::Result<Vec<u8>> {
        let res: Result<Vec<u8>, String> =
            request(self, server::RequestCode::GetPretrainedModel, name).await?;
        res.map_err(io::Error::other)
    }

    /// Obtains a new certificate from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn renew_certificate(&self) -> io::Result<(String, String)> {
        let res: Result<(String, String), String> =
            request(self, server::RequestCode::RenewCertificate, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches a model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_model(&self, name: &str) -> io::Result<Vec<u8>> {
        let res: Result<Vec<u8>, String> =
            request(self, server::RequestCode::GetModel, name).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of model names from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_model_names(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetModelNames, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Inserts column statistics into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_column_statistics(
        &self,
        statistics: &[crate::types::ColumnStatisticsUpdate],
        model_id: i32,
        batch_ts: i64,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::InsertColumnStatistics,
            &(statistics, model_id, batch_ts),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Inserts a model into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_model(&self, model: &[u8]) -> io::Result<i32> {
        let res: Result<i32, String> =
            request(self, server::RequestCode::InsertModel, model).await?;
        res.map_err(io::Error::other)
    }

    /// Inserts time series data into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_time_series(
        &self,
        time_series: &[crate::types::TimeSeriesUpdate],
        model_id: i32,
        batch_ts: i64,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::InsertTimeSeries,
            &(time_series, model_id, batch_ts),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Removes a model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn remove_model(&self, name: &str) -> io::Result<()> {
        let res: Result<(), String> = request(self, server::RequestCode::RemoveModel, name).await?;
        res.map_err(io::Error::other)
    }

    /// Updates clusters on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn update_clusters(
        &self,
        input: &[crate::types::UpdateClusterRequest],
        model_id: i32,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::UpdateClusters,
            &(input, model_id),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Updates a model on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn update_model(&self, model: &[u8]) -> io::Result<i32> {
        let res: Result<i32, String> =
            request(self, server::RequestCode::UpdateModel, model).await?;
        res.map_err(io::Error::other)
    }

    /// Updates outliers on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn update_outliers(
        &self,
        outliers: &[crate::types::OutlierInfo],
        model_id: i32,
        timestamp: i64,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::UpdateOutliers,
            &(outliers, model_id, timestamp),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Inserts event labels into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_event_labels(
        &self,
        model_id: i32,
        round: u32,
        event_labels: &[crate::types::EventMessage],
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::InsertEventLabels,
            &(model_id, round, event_labels),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Inserts a data source into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_data_source(
        &self,
        data_source: &crate::types::DataSource,
    ) -> io::Result<u32> {
        let res: Result<u32, String> =
            request(self, server::RequestCode::InsertDataSource, data_source).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches outliers from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_outliers(
        &self,
        model_id: i32,
        timestamp: i64,
    ) -> io::Result<Vec<(String, Vec<i64>)>> {
        let res: Result<Vec<(String, Vec<i64>)>, String> = request(
            self,
            server::RequestCode::GetOutliers,
            &(model_id, timestamp),
        )
        .await?;
        res.map_err(io::Error::other)
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
    #![allow(clippy::unwrap_used)]

    use crate::{
        server::handle,
        test::{TEST_ENV, TestServerHandler},
        types::DataSourceKey,
    };

    async fn run_test<F, Fut>(client_logic: F)
    where
        F: FnOnce(crate::client::Connection) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            let mut handler = TestServerHandler;
            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            handle(&mut handler, &mut send, &mut recv, "test-peer").await?;
            Ok(()) as std::io::Result<()>
        });

        client_logic(client_conn).await;

        let server_res = server_handle.await.unwrap();
        match server_res {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                // Connection closed after client finished - this is expected
            }
            Err(e) => panic!("Unexpected server error: {e:?}"),
        }

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    async fn get_data_source() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_data_source(&DataSourceKey::Id(5)).await;
            assert!(client_res.is_ok());
            let received_data_source = client_res.unwrap();
            assert_eq!(received_data_source.name, "name5");
        })
        .await;
    }

    #[tokio::test]
    async fn get_tidb_patterns() {
        run_test(|client_conn| async move {
            let db_names = vec![("db1", "1.0.0"), ("db2", "2.0.0")];
            let client_res = client_conn.get_tidb_patterns(&db_names).await;
            assert!(client_res.is_ok());
            let received_patterns = client_res.unwrap();
            assert_eq!(received_patterns.len(), db_names.len());
            assert_eq!(received_patterns[0].0, "db1");
            assert!(received_patterns[0].1.is_some());
            assert_eq!(received_patterns[1].0, "db2");
            assert!(received_patterns[1].1.is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn get_config() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_config().await;
            assert!(client_res.is_ok());
            let received_config = client_res.unwrap();
            assert_eq!(received_config, "test-config");
        })
        .await;
    }

    #[tokio::test]
    async fn get_allowlist() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_allowlist().await;
            assert!(client_res.is_ok());
            let received_allowlist = client_res.unwrap();
            assert_eq!(received_allowlist.hosts.len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn get_blocklist() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_blocklist().await;
            assert!(client_res.is_ok());
            let received_blocklist = client_res.unwrap();
            assert_eq!(received_blocklist.hosts.len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn get_indicator() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_indicator("test-indicator").await;
            assert!(client_res.is_ok());
            let received_indicator = client_res.unwrap();
            assert_eq!(received_indicator.len(), 2);
        })
        .await;
    }

    #[tokio::test]
    async fn get_internal_network_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_internal_network_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.hosts.len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn get_tor_exit_node_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_tor_exit_node_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.len(), 2);
            assert_eq!(received_list[0], "192.168.1.10");
            assert_eq!(received_list[1], "192.168.1.11");
        })
        .await;
    }

    #[tokio::test]
    async fn get_trusted_domain_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_trusted_domain_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.len(), 2);
            assert_eq!(received_list[0], "trusted1.com");
            assert_eq!(received_list[1], "trusted2.com");
        })
        .await;
    }

    #[tokio::test]
    async fn get_trusted_user_agent_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_trusted_user_agent_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.len(), 2);
            assert_eq!(received_list[0], "Mozilla/5.0 (trusted)");
            assert_eq!(received_list[1], "Chrome/test");
        })
        .await;
    }

    #[tokio::test]
    async fn get_pretrained_model() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_pretrained_model("test-model").await;
            assert!(client_res.is_ok());
            let received_model = client_res.unwrap();
            assert_eq!(received_model, vec![0x01, 0x02, 0x03, 0x04]);
        })
        .await;
    }

    #[tokio::test]
    async fn renew_certificate() {
        run_test(|client_conn| async move {
            let client_res = client_conn.renew_certificate().await;
            assert!(client_res.is_ok());
            let (new_cert, new_key) = client_res.unwrap();
            assert_eq!(new_cert, "new-cert");
            assert_eq!(new_key, "new-key");
        })
        .await;
    }

    #[tokio::test]
    async fn get_model() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_model("test-model").await;
            assert!(client_res.is_ok());
            let model = client_res.unwrap();
            assert_eq!(model, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        })
        .await;
    }

    #[tokio::test]
    async fn get_model_names() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_model_names().await;
            assert!(client_res.is_ok());
            let names = client_res.unwrap();
            assert_eq!(names, vec!["model1", "model2", "model3"]);
        })
        .await;
    }

    #[tokio::test]
    async fn insert_column_statistics() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::ColumnStatisticsUpdate {
                cluster_id: "test-cluster".to_string(),
                column_statistics: vec![],
            }];
            let client_res = client_conn.insert_column_statistics(&data, 1, 1000).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn insert_model() {
        run_test(|client_conn| async move {
            let model_bytes = vec![0x01, 0x02, 0x03];
            let client_res = client_conn.insert_model(&model_bytes).await;
            assert!(client_res.is_ok());
            assert_eq!(client_res.unwrap(), 42);
        })
        .await;
    }

    #[tokio::test]
    async fn insert_time_series() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::TimeSeriesUpdate {
                cluster_id: "test-cluster".to_string(),
                time_series: vec![],
            }];
            let client_res = client_conn.insert_time_series(&data, 1, 1000).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn remove_model() {
        run_test(|client_conn| async move {
            let client_res = client_conn.remove_model("test-model").await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn update_clusters() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::UpdateClusterRequest {
                cluster_id: "test-cluster".to_string(),
                detector_id: 1,
                signature: "test-sig".to_string(),
                score: Some(0.5),
                size: 100,
                event_ids: vec![],
                status_id: 1,
                labels: None,
            }];
            let client_res = client_conn.update_clusters(&data, 1).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn update_model() {
        run_test(|client_conn| async move {
            let model_bytes = vec![0x01, 0x02, 0x03];
            let client_res = client_conn.update_model(&model_bytes).await;
            assert!(client_res.is_ok());
            assert_eq!(client_res.unwrap(), 55);
        })
        .await;
    }

    #[tokio::test]
    async fn update_outliers() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::OutlierInfo {
                id: 1,
                rank: 1,
                distance: 0.5,
                sensor: "test-sensor".to_string(),
            }];
            let client_res = client_conn.update_outliers(&data, 1, 1000).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn insert_event_labels() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::EventMessage {
                time: chrono::Utc::now(),
                kind: crate::types::EventKind::ExtraThreat,
                fields: vec![0x01, 0x02],
            }];
            let client_res = client_conn.insert_event_labels(1, 100, &data).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn insert_data_source() {
        run_test(|client_conn| async move {
            let data = crate::types::DataSource {
                id: 0,
                name: "test-source".to_string(),
                server_name: "test-server".to_string(),
                address: "127.0.0.1:8080".parse().unwrap(),
                data_type: crate::types::DataType::Log,
                source: "test".to_string(),
                kind: None,
                description: "test description".to_string(),
            };
            let client_res = client_conn.insert_data_source(&data).await;
            assert!(client_res.is_ok());
            assert_eq!(client_res.unwrap(), 123);
        })
        .await;
    }

    #[tokio::test]
    async fn get_outliers() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_outliers(10, 1000).await;
            assert!(client_res.is_ok());
            let outliers = client_res.unwrap();
            assert_eq!(outliers.len(), 2);
            assert_eq!(outliers[0].0, "sensor1");
            assert_eq!(outliers[0].1, vec![1, 2, 3]);
            assert_eq!(outliers[1].0, "sensor2");
            assert_eq!(outliers[1].1, vec![4, 5, 6]);
        })
        .await;
    }
}
