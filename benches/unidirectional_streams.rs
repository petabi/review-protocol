//! Performance benchmarks for unidirectional event stream processing
//!
//! These benchmarks measure the throughput and performance characteristics
//! of the event stream API under various conditions.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::cast_sign_loss)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use review_protocol::{
    server::EventStreamHandler,
    test::TEST_ENV,
    types::{EventKind, EventMessage},
};
use tokio::runtime::Runtime;

/// No-op handler for measuring pure processing overhead
struct NoopHandler;

#[async_trait::async_trait]
impl EventStreamHandler for NoopHandler {
    async fn handle_event(&mut self, _event: EventMessage) -> Result<(), String> {
        Ok(())
    }
}

/// Handler that simulates minimal processing work
struct MinimalHandler {
    count: usize,
}

#[async_trait::async_trait]
impl EventStreamHandler for MinimalHandler {
    async fn handle_event(&mut self, _event: EventMessage) -> Result<(), String> {
        self.count += 1;
        Ok(())
    }
}

fn benchmark_event_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("event_throughput");

    for event_count in [100, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*event_count as u64));

        group.bench_with_input(
            BenchmarkId::new("noop_handler", event_count),
            event_count,
            |b, &event_count| {
                b.iter(|| {
                    rt.block_on(async {
                        let test_env = TEST_ENV.lock().await;
                        let (server_conn, client_conn) = test_env.setup().await;

                        let handler = NoopHandler;
                        let server_conn_for_teardown = server_conn.clone();

                        let server_handle =
                            tokio::spawn(
                                async move { server_conn.accept_event_stream(handler).await },
                            );

                        let client_handle = tokio::spawn(async move {
                            let mut send_stream = client_conn.open_uni().await.unwrap();
                            send_stream.write_all(&[0, 0]).await.unwrap();

                            for i in 0..event_count {
                                let event = EventMessage {
                                    time: jiff::Timestamp::now(),
                                    kind: EventKind::HttpThreat,
                                    fields: format!("event_{i}").into_bytes(),
                                };

                                let serialized = bincode::serde::encode_to_vec(
                                    &event,
                                    bincode::config::standard(),
                                )
                                .unwrap();
                                #[allow(clippy::cast_possible_truncation)]
                                let len_bytes = (serialized.len() as u32).to_be_bytes();

                                send_stream.write_all(&len_bytes).await.unwrap();
                                send_stream.write_all(&serialized).await.unwrap();
                            }

                            send_stream.finish().unwrap();
                        });

                        let _ = tokio::join!(server_handle, client_handle);

                        test_env.teardown(&server_conn_for_teardown);

                        black_box(event_count);
                    });
                });
            },
        );
    }

    group.finish();
}

fn benchmark_event_sizes(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("event_sizes");

    for size in [100, 1024, 10_240, 102_400].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("bytes", size), size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    let test_env = TEST_ENV.lock().await;
                    let (server_conn, client_conn) = test_env.setup().await;

                    let handler = NoopHandler;
                    let server_conn_for_teardown = server_conn.clone();

                    let server_handle =
                        tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

                    let client_handle = tokio::spawn(async move {
                        let mut send_stream = client_conn.open_uni().await.unwrap();
                        send_stream.write_all(&[0, 0]).await.unwrap();

                        let event = EventMessage {
                            time: jiff::Timestamp::now(),
                            kind: EventKind::ExtraThreat,
                            fields: vec![0x42; size],
                        };

                        let serialized =
                            bincode::serde::encode_to_vec(&event, bincode::config::standard())
                                .unwrap();
                        #[allow(clippy::cast_possible_truncation)]
                        let len_bytes = (serialized.len() as u32).to_be_bytes();

                        send_stream.write_all(&len_bytes).await.unwrap();
                        send_stream.write_all(&serialized).await.unwrap();
                        send_stream.finish().unwrap();
                    });

                    let _ = tokio::join!(server_handle, client_handle);

                    test_env.teardown(&server_conn_for_teardown);

                    black_box(size);
                });
            });
        });
    }

    group.finish();
}

fn benchmark_concurrent_streams(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_streams");

    for stream_count in [1, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::new("streams", stream_count),
            stream_count,
            |b, &stream_count| {
                b.iter(|| {
                    rt.block_on(async {
                        let test_env = TEST_ENV.lock().await;
                        let (server_conn, client_conn) = test_env.setup().await;

                        let server_conn_clone = server_conn.clone();
                        let server_handle = tokio::spawn(async move {
                            tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                server_conn_clone.accept_event_streams(
                                    || MinimalHandler { count: 0 },
                                    Some(stream_count),
                                ),
                            )
                            .await
                        });

                        let client_handle = tokio::spawn(async move {
                            let mut handles = Vec::new();

                            for stream_id in 0..stream_count {
                                let client_conn = client_conn.clone();
                                let handle = tokio::spawn(async move {
                                    let mut send_stream = client_conn.open_uni().await.unwrap();
                                    send_stream.write_all(&[0, 0]).await.unwrap();

                                    for i in 0..100 {
                                        let event = EventMessage {
                                            time: jiff::Timestamp::now(),
                                            kind: EventKind::DnsCovertChannel,
                                            fields: format!("stream_{stream_id}_event_{i}")
                                                .into_bytes(),
                                        };

                                        let serialized = bincode::serde::encode_to_vec(
                                            &event,
                                            bincode::config::standard(),
                                        )
                                        .unwrap();
                                        #[allow(clippy::cast_possible_truncation)]
                                        let len_bytes = (serialized.len() as u32).to_be_bytes();

                                        send_stream.write_all(&len_bytes).await.unwrap();
                                        send_stream.write_all(&serialized).await.unwrap();
                                    }

                                    send_stream.finish().unwrap();
                                });

                                handles.push(handle);
                            }

                            for handle in handles {
                                handle.await.unwrap();
                            }

                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            client_conn.close(0u32.into(), b"done");
                        });

                        let _ = tokio::join!(server_handle, client_handle);

                        test_env.teardown(&server_conn);

                        black_box(stream_count);
                    });
                });
            },
        );
    }

    group.finish();
}

fn benchmark_deserialization_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("deserialization");

    group.bench_function("bincode_deserialize", |b| {
        b.iter(|| {
            rt.block_on(async {
                let event = EventMessage {
                    time: jiff::Timestamp::now(),
                    kind: EventKind::HttpThreat,
                    fields: b"test event data".to_vec(),
                };

                let serialized =
                    bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
                let (_deserialized, _len): (EventMessage, usize) =
                    bincode::serde::decode_from_slice(&serialized, bincode::config::standard())
                        .unwrap();

                black_box(event);
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_event_throughput,
    benchmark_event_sizes,
    benchmark_concurrent_streams,
    benchmark_deserialization_overhead
);
criterion_main!(benches);
