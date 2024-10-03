use oinq::frame;

use super::Connection;
use crate::client;

/// The server API.
impl Connection {
    /// Sends a list of trusted domains to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_domain_list(&self, list: &[String]) -> anyhow::Result<()> {
        use anyhow::anyhow;
        use bincode::Options;

        let Ok(mut msg) = bincode::serialize::<u32>(&client::RequestCode::TrustedDomainList.into())
        else {
            unreachable!("serialization of u32 into memory buffer should not fail")
        };
        let ser = bincode::DefaultOptions::new();
        msg.extend(ser.serialize(list)?);

        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &msg).await?;

        let mut response = vec![];
        frame::recv::<Result<(), String>>(&mut recv, &mut response)
            .await?
            .map_err(|e| anyhow!(e))
    }
}
