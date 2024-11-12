//! Requset handler for the server.

use std::io;

use num_enum::FromPrimitive;
use oinq::request::parse_args;

use super::RequestCode;
use crate::types::{DataSource, DataSourceKey};

/// A request handler that can handle a request to the server.
#[async_trait::async_trait]
pub trait Handler {
    async fn get_data_source(
        &self,
        _key: &DataSourceKey<'_>,
    ) -> Result<Option<DataSource>, String> {
        Err("not supported".to_string())
    }
}

/// Handles requests to the server.
///
/// This handles only a subset of the requests that the server can receive. If
/// the request is not supported, the request code is returned to the caller.
///
/// # Errors
///
/// - There was an error reading from the stream.
/// - There was an error writing to the stream.
/// - An unknown request code was received.
/// - The arguments to the request were invalid.
pub async fn handle<H>(
    handler: &mut H,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> io::Result<Option<(u32, quinn::SendStream, quinn::RecvStream)>>
where
    H: Handler + Sync,
{
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(&mut recv, &mut buf).await {
            Ok(res) => res,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        match RequestCode::from_primitive(code) {
            RequestCode::GetDataSource => {
                let data_source_key = parse_args::<DataSourceKey>(body)?;
                let result = handler.get_data_source(&data_source_key).await;
                oinq::request::send_response(&mut send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    &mut send,
                    &mut buf,
                    Err("unknown request code") as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown request code",
                ));
            }
            _ => {
                return Ok(Some((code, send, recv)));
            }
        }
    }
    Ok(None)
}
