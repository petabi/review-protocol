use std::io;

use oinq::frame;
use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};

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

/// Sends a message as a stream.
///
/// # Errors
///
/// Return an error if sending the message failed.
pub async fn send_msg<T>(send: &mut SendStream, msg: T) -> io::Result<()>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    frame::send(send, &mut buf, msg).await
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn send_and_recv() {
        use serde::{Deserialize, Serialize};

        use crate::test::{channel, TOKEN};

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
