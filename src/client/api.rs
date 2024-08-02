use super::Connection;
use crate::server;

/// The client API.
impl Connection {
    /// Fetches the configuration from the server.
    ///
    /// The format of the configuration is up to the caller to interpret.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_config(&self) -> std::io::Result<String> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let mut buf = Vec::new();
        oinq::message::send_request(
            &mut send,
            &mut buf,
            u32::from(server::RequestCode::GetConfig),
            (),
        )
        .await?;
        oinq::frame::recv::<Result<String, String>>(&mut recv, &mut buf)
            .await?
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}
