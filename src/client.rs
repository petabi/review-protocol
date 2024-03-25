//! Client-specific protocol implementation.

pub use oinq::message::client_handshake as handshake;
pub use oinq::message::{send_err, send_ok, send_request};
