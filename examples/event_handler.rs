//! Example: Comprehensive Event Handler Implementation
//!
//! This example demonstrates a complete implementation of the unidirectional
//! event stream API, including:
//! - Custom event handler with state management
//! - Error handling and recovery
//! - Metrics collection
//! - Multiple concurrent stream handling
//! - Integration with a connection loop
//!
//! Run with: `cargo run --example event_handler --features test-support`

#![allow(clippy::unwrap_used)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::redundant_pattern_matching)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use review_protocol::{
    server::EventStreamHandler,
    types::{EventKind, EventMessage},
};

/// Event statistics and metrics
#[derive(Debug, Default, Clone)]
struct EventMetrics {
    total_events: usize,
    events_by_kind: HashMap<String, usize>,
    total_errors: usize,
    streams_completed: usize,
}

impl EventMetrics {
    fn record_event(&mut self, kind: EventKind) {
        self.total_events += 1;
        let kind_str = format!("{kind:?}");
        *self.events_by_kind.entry(kind_str).or_insert(0) += 1;
    }

    fn record_error(&mut self) {
        self.total_errors += 1;
    }

    fn record_stream_end(&mut self) {
        self.streams_completed += 1;
    }

    fn print_summary(&self) {
        println!("\n=== Event Processing Summary ===");
        println!("Total events processed: {}", self.total_events);
        println!("Total errors: {}", self.total_errors);
        println!("Streams completed: {}", self.streams_completed);
        println!("\nEvents by type:");
        for (kind, count) in &self.events_by_kind {
            println!("  {}: {}", kind, count);
        }
        println!("================================\n");
    }
}

/// Custom event handler that collects metrics and handles errors
struct MetricsEventHandler {
    metrics: Arc<Mutex<EventMetrics>>,
    max_errors: usize,
    error_count: usize,
}

impl MetricsEventHandler {
    fn new(metrics: Arc<Mutex<EventMetrics>>, max_errors: usize) -> Self {
        Self {
            metrics,
            max_errors,
            error_count: 0,
        }
    }
}

#[async_trait::async_trait]
impl EventStreamHandler for MetricsEventHandler {
    async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
        // Record metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.record_event(event.kind);
        } // Lock is dropped here before await

        // Process the event
        println!(
            "[Handler] Processing event: {:?} at {}",
            event.kind, event.time
        );

        // Simulate event processing
        // In a real application, this would:
        // - Parse event fields
        // - Store in database
        // - Trigger alerts
        // - Update analytics
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Ok(())
    }

    async fn on_error(&mut self, error: &str) -> Result<(), String> {
        self.error_count += 1;

        // Record error in metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.record_error();
        }

        eprintln!(
            "[Handler] Error #{} (max {}): {}",
            self.error_count, self.max_errors, error
        );

        // Continue processing unless we've hit the error limit
        if self.error_count >= self.max_errors {
            Err(format!(
                "Too many errors: {}/{}",
                self.error_count, self.max_errors
            ))
        } else {
            Ok(())
        }
    }

    async fn on_stream_end(&mut self) -> Result<(), String> {
        println!("[Handler] Stream ended gracefully");

        let mut metrics = self.metrics.lock().unwrap();
        metrics.record_stream_end();

        Ok(())
    }
}

/// Send sample events from client to server
async fn send_events(
    client: review_protocol::client::Connection,
    event_count: usize,
    stream_id: usize,
) {
    println!(
        "[Client] Stream {}: Opening unidirectional stream",
        stream_id
    );

    let mut send_stream = client.open_uni().await.expect("Failed to open stream");

    // Send protocol header
    send_stream
        .write_all(&[0, 0])
        .await
        .expect("Failed to send header");

    println!(
        "[Client] Stream {}: Sending {} events",
        stream_id, event_count
    );

    // Send events
    for i in 0..event_count {
        let kind = match i % 4 {
            0 => EventKind::HttpThreat,
            1 => EventKind::DnsCovertChannel,
            2 => EventKind::PortScan,
            _ => EventKind::BlocklistConn,
        };

        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind,
            fields: format!("stream_{}_event_{}", stream_id, i).into_bytes(),
        };

        let serialized = bincode::serde::encode_to_vec(&event, bincode::config::standard())
            .expect("Failed to serialize");
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (serialized.len() as u32).to_be_bytes();

        send_stream
            .write_all(&len_bytes)
            .await
            .expect("Failed to send length");
        send_stream
            .write_all(&serialized)
            .await
            .expect("Failed to send event");
    }

    // Properly close the stream
    send_stream.finish().expect("Failed to finish stream");

    println!("[Client] Stream {}: Finished sending events", stream_id);
}

/// Example 1: Single event stream
async fn example_single_stream() {
    println!("\n=== Example 1: Single Event Stream ===\n");

    let test_env = review_protocol::test::TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let metrics = Arc::new(Mutex::new(EventMetrics::default()));
    let metrics_clone = metrics.clone();

    // Create handler
    let handler = MetricsEventHandler::new(metrics_clone, 5);

    let server_conn_for_teardown = server_conn.clone();

    // Server accepts a single stream
    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    // Client sends events
    let client_handle = tokio::spawn(async move {
        send_events(client_conn, 10, 1).await;
    });

    // Wait for completion
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    // Print metrics
    metrics.lock().unwrap().print_summary();

    test_env.teardown(&server_conn_for_teardown);
}

/// Example 2: Multiple concurrent streams
async fn example_multiple_streams() {
    println!("\n=== Example 2: Multiple Concurrent Streams ===\n");

    let test_env = review_protocol::test::TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let metrics = Arc::new(Mutex::new(EventMetrics::default()));
    let metrics_for_factory = metrics.clone();

    // Server accepts multiple streams with concurrency limit
    let server_conn_for_teardown = server_conn.clone();
    let server_conn_clone = server_conn.clone();
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_conn_clone.accept_event_streams(
                move || MetricsEventHandler::new(metrics_for_factory.clone(), 10),
                Some(5), // Max 5 concurrent streams
            ),
        )
        .await
    });

    // Client sends multiple streams
    let client_handle = tokio::spawn(async move {
        let mut handles = Vec::new();

        for stream_id in 0..8 {
            let client_conn = client_conn.clone();
            let handle = tokio::spawn(async move {
                send_events(client_conn, 15, stream_id).await;
            });
            handles.push(handle);
        }

        // Wait for all streams to complete
        for handle in handles {
            handle.await.expect("Client task failed");
        }

        println!("[Client] All streams sent, waiting before closing connection");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        client_conn.close(0u32.into(), b"test complete");
    });

    // Wait for completion
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    // Server should timeout (expected)
    assert!(matches!(server_result.unwrap(), Err(_)));
    assert!(client_result.is_ok());

    // Print metrics
    metrics.lock().unwrap().print_summary();

    test_env.teardown(&server_conn_for_teardown);
}

/// Example 3: Error handling and recovery
async fn example_error_handling() {
    println!("\n=== Example 3: Error Handling and Recovery ===\n");

    let test_env = review_protocol::test::TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    /// Handler that simulates errors on certain events
    struct ErrorSimulatingHandler {
        events_processed: usize,
        errors_encountered: usize,
    }

    #[async_trait::async_trait]
    impl EventStreamHandler for ErrorSimulatingHandler {
        async fn handle_event(&mut self, event: EventMessage) -> Result<(), String> {
            self.events_processed += 1;

            // Simulate an error on every 5th event
            if self.events_processed % 5 == 0 {
                return Err(format!(
                    "Simulated error on event {}",
                    self.events_processed
                ));
            }

            println!(
                "[Handler] Successfully processed event {}: {:?}",
                self.events_processed, event.kind
            );
            Ok(())
        }

        async fn on_error(&mut self, error: &str) -> Result<(), String> {
            self.errors_encountered += 1;
            eprintln!("[Handler] Recoverable error: {}", error);
            Ok(()) // Continue processing
        }

        async fn on_stream_end(&mut self) -> Result<(), String> {
            println!(
                "[Handler] Stream ended: {} events processed, {} errors",
                self.events_processed, self.errors_encountered
            );
            Ok(())
        }
    }

    let handler = ErrorSimulatingHandler {
        events_processed: 0,
        errors_encountered: 0,
    };

    let server_conn_for_teardown = server_conn.clone();

    // Server accepts stream with error-prone handler
    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    // Client sends events
    let client_handle = tokio::spawn(async move {
        send_events(client_conn, 12, 1).await;
    });

    // Wait for completion
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    // Should succeed despite errors (errors were handled gracefully)
    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    test_env.teardown(&server_conn_for_teardown);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  review-protocol: Event Handler Examples                ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    // Run examples
    example_single_stream().await;
    example_multiple_streams().await;
    example_error_handling().await;

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  All examples completed successfully!                    ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
}
