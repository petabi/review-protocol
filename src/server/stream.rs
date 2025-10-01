//! Low-level event stream processing implementation.

use std::io;

use anyhow::{Context, Result};
use bincode::Options;
use quinn::RecvStream;

use self::super::EventStreamHandler;
use crate::types::EventMessage;

/// Processes a unidirectional event stream with the given handler
///
/// Reads `EventMessage` objects from the stream and calls handler methods
/// appropriately. Handles protocol framing, deserialization, and errors.
///
/// # Protocol Format
/// - 2-byte header (version/reserved)
/// - Sequence of length-prefixed messages:
///   - 4-byte big-endian length
///   - Message payload (bincode-serialized `EventMessage`)
///
/// # Arguments
/// * `recv` - The unidirectional receive stream
/// * `handler` - Handler implementing `EventStreamHandler` trait
///
/// # Returns
/// * `Ok(())` - Stream processed successfully until EOF
/// * `Err(e)` - Network error, protocol error, or handler error
///
/// # Errors
///
/// This function will return an error if:
/// * Failed to read the protocol header (network or stream error)
/// * A handler error occurs during event processing
/// * A handler error occurs during error handling
/// * A handler error occurs during stream end handling
/// * A network error occurs while reading messages
pub async fn process_event_stream<H>(mut recv: RecvStream, mut handler: H) -> Result<()>
where
    H: EventStreamHandler + Send,
{
    // Read 2-byte protocol header
    let mut header_buf = vec![0_u8; 2];
    recv.read_exact(&mut header_buf)
        .await
        .context("failed to read protocol header")?;

    // Setup for message processing
    let codec = bincode::DefaultOptions::new();
    let mut message_buf = Vec::new();

    // Process messages until stream ends
    loop {
        // Read next message
        match recv_event_message(&mut recv, &mut message_buf).await {
            Ok(()) => {
                // Deserialize and handle message
                match codec.deserialize::<EventMessage>(&message_buf) {
                    Ok(msg) => {
                        if let Err(e) = handler.handle_event(msg).await {
                            return Err(anyhow::anyhow!("handler error: {e}"));
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("deserialization error: {e}");
                        if let Err(e) = handler.on_error(&error_msg).await {
                            return Err(anyhow::anyhow!(
                                "handler error during error handling: {e}"
                            ));
                        }
                        // Continue processing other messages
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Stream ended normally
                if let Err(e) = handler.on_stream_end().await {
                    return Err(anyhow::anyhow!("handler error during stream end: {e}"));
                }
                break;
            }
            Err(e) => {
                // Network or protocol error
                let error_msg = format!("failed to receive message: {e}");
                if let Err(handler_err) = handler.on_error(&error_msg).await {
                    return Err(anyhow::anyhow!(
                        "handler error during error handling: {handler_err}"
                    ));
                }
                return Err(anyhow::anyhow!("network error: {e}"));
            }
        }
    }

    Ok(())
}

/// Reads a single length-prefixed message from the stream
///
/// # Protocol Format
/// - 4-byte big-endian message length
/// - Message payload of specified length
///
/// # Arguments
/// * `recv` - The receive stream
/// * `buf` - Buffer to store the message (will be resized)
///
/// # Returns
/// * `Ok(())` - Message read successfully into buf
/// * `Err(e)` - IO error (including `UnexpectedEof` for stream end)
///
/// # Errors
///
/// This function will return an error if:
/// * Failed to read the length prefix (stream ended or network error)
/// * Message length exceeds maximum allowed size (10MB)
/// * Failed to read the message payload (stream ended or network error)
async fn recv_event_message(recv: &mut RecvStream, buf: &mut Vec<u8>) -> io::Result<()> {
    use std::mem;

    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB

    // Read 4-byte length prefix
    let mut len_buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(map_recv_error)?;

    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate message length (prevent DoS)
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }

    // Read message payload
    buf.resize(len, 0);
    recv.read_exact(buf.as_mut_slice())
        .await
        .map_err(map_recv_error)
}

/// Map Quinn read errors to standard `io::Error`
fn map_recv_error(e: quinn::ReadExactError) -> io::Error {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => {
            io::Error::new(io::ErrorKind::UnexpectedEof, "stream ended early")
        }
        quinn::ReadExactError::ReadError(read_err) => read_err.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    // Mock handler for testing
    struct TestHandler {
        events: Arc<Mutex<Vec<EventMessage>>>,
        errors: Arc<Mutex<Vec<String>>>,
        should_fail_on_event: bool,
        stream_ended: Arc<Mutex<bool>>,
    }

    impl TestHandler {
        #[allow(dead_code)]
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                errors: Arc::new(Mutex::new(Vec::new())),
                should_fail_on_event: false,
                stream_ended: Arc::new(Mutex::new(false)),
            }
        }

        #[allow(dead_code)]
        fn with_failure() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                errors: Arc::new(Mutex::new(Vec::new())),
                should_fail_on_event: true,
                stream_ended: Arc::new(Mutex::new(false)),
            }
        }
    }

    #[async_trait::async_trait]
    impl EventStreamHandler for TestHandler {
        async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
            if self.should_fail_on_event {
                return Err("test failure".to_string());
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }

        async fn on_error(&mut self, error: &str) -> Result<(), String> {
            self.errors.lock().unwrap().push(error.to_string());
            Ok(())
        }

        async fn on_stream_end(&mut self) -> Result<(), String> {
            *self.stream_ended.lock().unwrap() = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_recv_event_message_validates_length() {
        // TODO: Will be implemented in issue #93
        // Test that oversized messages are rejected
        // This would need mock stream implementation
        // The actual test implementation would require creating a mock RecvStream
        // with specific data to test the validation logic
    }

    #[tokio::test]
    async fn test_process_event_stream_handles_eof() {
        // TODO: Will be implemented in issue #93
        // Test normal stream termination
        // This would need mock stream implementation
        // The actual test implementation would require creating a mock RecvStream
        // that simulates EOF conditions
    }

    #[tokio::test]
    async fn test_process_event_stream_handles_handler_errors() {
        // TODO: Will be implemented in issue #93
        // Test that handler errors are properly propagated
        // This would need mock stream implementation
        // The actual test implementation would require creating a mock RecvStream
        // and a handler that returns errors
    }
}
