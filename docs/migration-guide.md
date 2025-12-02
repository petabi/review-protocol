# Migration Guide: Unidirectional Channel API

This guide helps applications migrate from direct unidirectional stream
handling to the new encapsulated API in review-protocol.

## Overview

The new API simplifies event stream handling by encapsulating protocol
details, framing, and deserialization behind a clean trait-based interface.
This reduces boilerplate code and ensures consistent error handling across
applications.

## Before (Direct Implementation)

```rust
// Old way - direct protocol handling
res = connection.accept_uni() => {
    if let Ok(recv) = res {
        tokio::spawn(async move {
            if let Err(e) = handle_event_stream(recv).await {
                error!("Stream error: {e}");
            }
        });
    }
}

async fn handle_event_stream(mut recv: RecvStream) -> Result<()> {
    let mut buf = vec![0_u8; 2];
    recv.read_exact(&mut buf).await?;

    let codec = bincode::DefaultOptions::new();
    let mut message_buf = Vec::new();

    loop {
        // Custom protocol implementation
        if let Err(e) = recv_raw(&mut recv, &mut message_buf).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e.into());
        }

        match codec.deserialize::<EventMessage>(&message_buf) {
            Ok(msg) => {
                // Handle event
                process_event(msg).await?;
            }
            Err(e) => warn!("Decode error: {}", e),
        }
    }
    Ok(())
}

async fn recv_raw(recv: &mut RecvStream, buf: &mut Vec<u8>) -> io::Result<()> {
    use std::mem;

    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

    let mut len_buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }

    buf.resize(len, 0);
    recv.read_exact(buf.as_mut_slice()).await?;
    Ok(())
}
```

## After (Encapsulated API)

```rust
// New way - use review-protocol API
res = connection.accept_event_stream(MyEventHandler::new()) => {
    if let Err(e) = res {
        error!("Stream error: {e}");
    }
}

struct MyEventHandler {
    // Your application state
}

#[async_trait::async_trait]
impl EventStreamHandler for MyEventHandler {
    async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
        // Your event processing logic (same as before)
        process_event(event).await.map_err(|e| e.to_string())
    }
}
```

## Migration Steps

### 1. Create Event Handler

Implement the `EventStreamHandler` trait for your event processing logic:

```rust
use review_protocol::{server::EventStreamHandler, types::EventMessage};

struct MyEventHandler {
    // Add any state your handler needs
    db_connection: DatabasePool,
    metrics: Arc<Metrics>,
}

#[async_trait::async_trait]
impl EventStreamHandler for MyEventHandler {
    async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
        // Move your event processing logic here
        // Convert any errors to String
        self.process_event(event).await.map_err(|e| e.to_string())
    }

    // Optional: customize error handling
    async fn on_error(&mut self, error: &str) -> Result<(), String> {
        eprintln!("Stream error: {}", error);
        self.metrics.increment_error_count();
        Ok(())  // Continue processing on errors
    }

    // Optional: cleanup when stream ends
    async fn on_stream_end(&mut self) -> Result<(), String> {
        self.metrics.increment_stream_count();
        Ok(())
    }
}
```

### 2. Replace Stream Acceptance

Replace your custom `accept_uni()` calls with the new API:

```rust
// Before
let recv = connection.accept_uni().await?;
tokio::spawn(async move {
    handle_event_stream(recv).await
});

// After
let handler = MyEventHandler::new();
connection.accept_event_stream(handler).await?;
```

### 3. Remove Protocol Code

Delete all custom framing and deserialization code:

- Remove `recv_raw()` or similar framing functions
- Remove bincode codec initialization
- Remove manual header reading
- Remove message length validation code

All of this is now handled by `review-protocol`.

### 4. Update Error Handling

Convert your error types to `String` returns:

```rust
// Before
async fn process_event(event: EventMessage) -> Result<(), MyError> {
    // ...
}

// After
async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
    self.process_event(event)
        .await
        .map_err(|e| e.to_string())
}
```

### 5. Test Compatibility

Verify that your application processes the same events correctly:

```rust
#[tokio::test]
async fn test_migration_compatibility() {
    // Create test connection
    let (server_conn, client_conn) = setup_test_connection().await;

    // Create handler with expected behavior
    let handler = MyEventHandler::new();

    // Test event processing
    let server_handle = tokio::spawn(async move {
        server_conn.accept_event_stream(handler).await
    });

    // Send test events
    send_test_events(client_conn).await;

    // Verify results
    assert!(server_handle.await.unwrap().is_ok());
}
```

## Handling Multiple Streams

If your application handles multiple concurrent streams, use
`accept_event_streams()`:

```rust
// Before
loop {
    match connection.accept_uni().await {
        Ok(recv) => {
            tokio::spawn(async move {
                handle_event_stream(recv).await
            });
        }
        Err(e) => {
            error!("Failed to accept stream: {}", e);
            break;
        }
    }
}

// After
connection.accept_event_streams(
    || MyEventHandler::new(),
    Some(10)  // Limit concurrent streams
).await?;
```

## Benefits

### Less Code

- **~50 lines of protocol code removed** per application
- No need to maintain custom framing logic
- No need to handle bincode codec setup

### Better Errors

- Clearer error messages and handling
- Automatic distinction between network, protocol, and handler errors
- Optional hooks for custom error handling

### Consistency

- Same pattern as bidirectional channels
- Consistent behavior across all REview applications
- Easier to understand and maintain

### Maintainability

- Protocol changes isolated to review-protocol
- Applications don't need updates when protocol evolves
- Centralized testing ensures reliability

## Advanced Usage

### Custom Error Recovery

Implement custom error handling to continue processing after errors:

```rust
#[async_trait::async_trait]
impl EventStreamHandler for ResilientHandler {
    async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
        // Process event
        Ok(())
    }

    async fn on_error(&mut self, error: &str) -> Result<(), String> {
        self.error_count += 1;

        if self.error_count < MAX_ERRORS {
            eprintln!("Recoverable error: {}", error);
            Ok(())  // Continue processing
        } else {
            Err("Too many errors".to_string())  // Stop processing
        }
    }
}
```

### State Management

Share state across multiple handlers:

```rust
struct StatefulHandler {
    shared_state: Arc<Mutex<SharedState>>,
}

connection.accept_event_streams(
    || StatefulHandler {
        shared_state: shared_state.clone(),
    },
    Some(5)
).await?;
```

### Integration with Existing Code

Integrate with existing connection loops:

```rust
loop {
    tokio::select! {
        // Handle bidirectional requests
        res = connection.accept_bi() => {
            if let Ok((send, recv)) = res {
                handle_request(send, recv).await?;
            }
        }

        // Handle unidirectional event streams
        res = connection.accept_event_stream(MyEventHandler::new()) => {
            if let Err(e) = res {
                eprintln!("Event stream error: {}", e);
            }
        }
    }
}
```

## Troubleshooting

### Events Not Being Processed

**Symptom**: Handler's `handle_event()` method is not being called.

**Solution**: Ensure the protocol header is being sent by the client:

```rust
// Client must send 2-byte header before events
send_stream.write_all(&[0, 0]).await?;
```

### Deserialization Errors

**Symptom**: `on_error()` called with "deserialization error" messages.

**Solution**: Verify that the client is using `bincode::DefaultOptions::new()`
for serialization:

```rust
// Client side
let codec = bincode::DefaultOptions::new();
let serialized = codec.serialize(&event)?;
```

### Connection Closes Prematurely

**Symptom**: Stream ends before all events are processed.

**Solution**: Ensure the handler doesn't return an error for expected
conditions:

```rust
async fn on_error(&mut self, error: &str) -> Result<(), String> {
    // Log but don't propagate recoverable errors
    eprintln!("Non-fatal error: {}", error);
    Ok(())  // Continue processing
}
```

## Migration Checklist

- [ ] Implement `EventStreamHandler` trait
- [ ] Replace `accept_uni()` with `accept_event_stream()`
- [ ] Remove custom protocol framing code
- [ ] Remove custom deserialization logic
- [ ] Update error handling to return `String`
- [ ] Test with existing event sources
- [ ] Verify protocol compatibility
- [ ] Update documentation
- [ ] Remove deprecated code

## Getting Help

If you encounter issues during migration:

1. Check that client and server protocol versions match
2. Verify bincode serialization format is compatible
3. Review handler error messages for clues
4. Test with the integration tests in `tests/unidirectional_streams.rs`
5. File an issue at <https://github.com/petabi/review-protocol/issues>
