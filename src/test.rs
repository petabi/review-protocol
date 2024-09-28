//! Shared test code

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::LazyLock,
};

use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex;

pub(crate) struct Channel {
    pub(crate) server: Endpoint,
    pub(crate) client: Endpoint,
}

pub(crate) struct Endpoint {
    pub(crate) conn: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

pub(crate) static TOKEN: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));

/// Creates a bidirectional channel, returning server's send and receive and
/// client's send and receive streams.
pub(crate) async fn channel() -> Channel {
    use std::sync::Arc;

    const TEST_SERVER_NAME: &str = "test-server";
    const TEST_PORT: u16 = 60190;

    let cert =
        rcgen::generate_simple_self_signed([TEST_SERVER_NAME.to_string()]).expect("infallible");
    let cert_der = vec![CertificateDer::from(cert.cert)];
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server_config = quinn::ServerConfig::with_single_cert(cert_der.clone(), key_der.into())
        .expect("infallible");
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT);

    let server_endpoint = {
        loop {
            break match quinn::Endpoint::server(server_config.clone(), server_addr) {
                Ok(e) => e,
                Err(e) => {
                    if e.kind() == tokio::io::ErrorKind::AddrInUse {
                        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                        continue;
                    } else {
                        panic!("{}", e);
                    }
                }
            };
        }
    };

    let handle = tokio::spawn(async move {
        let server_connection = match server_endpoint.accept().await {
            Some(conn) => match conn.await {
                Ok(conn) => conn,
                Err(e) => panic!("{}", e.to_string()),
            },
            None => panic!("connection closed"),
        };
        let (server_send, mut server_recv) = server_connection.accept_bi().await.unwrap();
        let mut server_buf = [0; 5];
        server_recv.read_exact(&mut server_buf).await.unwrap();
        (server_connection, server_send, server_recv)
    });

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(cert_der);
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(root_cert_store))
        .expect("invalid client config");
    let client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    let client_connecting = client_endpoint
        .connect_with(client_config, server_addr, TEST_SERVER_NAME)
        .unwrap();

    let client_connection = client_connecting.await.unwrap();
    let (mut client_send, client_recv) = client_connection.open_bi().await.unwrap();
    client_send.write_all(b"ready").await.unwrap();

    let (server_connection, server_send, server_recv) = handle.await.unwrap();

    Channel {
        server: self::Endpoint {
            conn: server_connection,
            send: server_send,
            recv: server_recv,
        },
        client: self::Endpoint {
            conn: client_connection,
            send: client_send,
            recv: client_recv,
        },
    }
}

#[cfg(all(feature = "client", feature = "server"))]
pub(crate) struct TestEnvironment {
    server_cert_pem: String,
    server_config: quinn::ServerConfig,
}

#[cfg(all(feature = "client", feature = "server"))]
impl TestEnvironment {
    // server configuration
    const SERVER_NAME: &str = "test-server";
    const SERVER_PORT: u16 = 60192;
    const SERVER_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), Self::SERVER_PORT);

    fn new() -> Self {
        let server_certified_key =
            rcgen::generate_simple_self_signed([Self::SERVER_NAME.to_string()])
                .expect("infallible");
        let server_cert_pem = server_certified_key.cert.pem();
        let server_certs_der = vec![CertificateDer::from(server_certified_key.cert)];
        let server_key_der =
            PrivatePkcs8KeyDer::from(server_certified_key.key_pair.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(server_certs_der.clone(), server_key_der.into())
                .expect("valid certificate");

        Self {
            server_cert_pem,
            server_config,
        }
    }

    pub(crate) async fn setup(&self) -> (crate::server::Connection, crate::client::Connection) {
        // client configuration
        const CLIENT_NAME: &str = "test-client";
        const APP_NAME: &str = "review-protocol";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let server_endpoint = loop {
            break match quinn::Endpoint::server(self.server_config.clone(), Self::SERVER_ADDR) {
                Ok(e) => e,
                Err(e) => {
                    if e.kind() == tokio::io::ErrorKind::AddrInUse {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    } else {
                        panic!("cannot create the test server: {}", e);
                    }
                }
            };
        };

        let handler_endpoint = server_endpoint.clone();
        let server_handle = tokio::spawn(async move {
            let server_conn = match handler_endpoint.accept().await {
                Some(conn) => match conn.await {
                    Ok(conn) => conn,
                    Err(e) => panic!("{}", e),
                },
                None => panic!("no connection"),
            };
            let client_addr = server_conn.remote_address();
            let agent_info = crate::server::handshake(
                &server_conn,
                client_addr,
                PROTOCOL_VERSION,
                PROTOCOL_VERSION,
            )
            .await
            .unwrap();
            (server_conn, agent_info)
        });

        let client_certified_key =
            rcgen::generate_simple_self_signed([CLIENT_NAME.to_string()]).expect("infallible");
        let client_cert_pem = client_certified_key.cert.pem();
        let client_key_pem = client_certified_key.key_pair.serialize_pem();
        let mut builder = crate::client::ConnectionBuilder::new(
            Self::SERVER_NAME,
            Self::SERVER_ADDR,
            APP_NAME,
            APP_VERSION,
            PROTOCOL_VERSION,
            client_cert_pem.as_bytes(),
            client_key_pem.as_bytes(),
        )
        .unwrap();
        let mut server_cert_pem_buf = std::io::Cursor::new(self.server_cert_pem.as_bytes());
        builder.add_root_certs(&mut server_cert_pem_buf).unwrap();

        // Connect to the server
        let client_conn = builder.connect().await.unwrap();
        let (server_conn, agent_info) = server_handle.await.unwrap();
        assert_eq!(agent_info.app_name, APP_NAME);
        assert_eq!(agent_info.version, APP_VERSION);

        let server_conn = crate::server::Connection::new(server_endpoint, server_conn.clone());
        (server_conn, client_conn)
    }

    pub(crate) fn teardown(&self, server_conn: crate::server::Connection) {
        server_conn.close();
    }
}

#[cfg(all(feature = "client", feature = "server"))]
pub(crate) static TEST_ENV: LazyLock<Mutex<TestEnvironment>> =
    LazyLock::new(|| Mutex::new(TestEnvironment::new()));
