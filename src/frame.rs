use std::io;

use oinq::frame;
use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Receives a message as a stream.
///
/// # Errors
///
/// Returns an error if receiving the message failed.
pub async fn recv_msg<T>(recv: &mut RecvStream) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let mut buf = Vec::new();
    frame::recv(recv, &mut buf).await
}

/// The error type for sending a message as a frame.
#[derive(Debug, Error)]
pub enum SendMessageError {
    #[error("message is too large")]
    MessageTooLarge,
    #[error("failed to write to a stream")]
    WriteError(#[from] quinn::WriteError),
}

impl From<frame::SendError> for SendMessageError {
    fn from(e: frame::SendError) -> Self {
        match e {
            frame::SendError::MessageTooLarge => SendMessageError::MessageTooLarge,
            frame::SendError::WriteError(e) => SendMessageError::WriteError(e),
        }
    }
}

/// Sends a message as a stream.
///
/// # Errors
///
/// * `SendMessageError::MessageTooLarge`: if the message is too large
/// * `SendMessageError::WriteError`: if the message could not be written
pub async fn send_msg<T>(send: &mut SendStream, msg: T) -> Result<(), SendMessageError>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    frame::send(send, &mut buf, msg).await?;
    Ok(())
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn send_and_recv() {
        use crate::test::{channel, TOKEN};
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
        struct Msg {
            str_data: String,
            int_data: i32,
            float_data: f32,
        }

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let msg_one = Msg {
            str_data: "hello".to_string(),
            int_data: 10,
            float_data: 10.0,
        };

        super::send_msg(&mut channel.server.send, msg_one.clone())
            .await
            .unwrap();
        let received = super::recv_msg::<Msg>(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(received, msg_one);

        let msg_two = Msg {
            str_data: "world".to_string(),
            int_data: 20,
            float_data: 20.0,
        };

        super::send_msg(&mut channel.server.send, msg_two.clone())
            .await
            .unwrap();
        let received = super::recv_msg::<Msg>(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(received, msg_two);
    }
}
