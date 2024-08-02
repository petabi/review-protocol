# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Implemented `get_trusted_domain_list` method in the client API to fetch the
  list of trusted domains from the server.

## [0.4.2] - 2024-07-31

### Added

- Introduced a new method `open_uni` in the `Connection` struct. This method
  initiates an outgoing unidirectional stream and directly corresponds to the
  `open_uni` method of the underlying `quinn::Connection`. This addition is for
  backward-compatibility and will be removed when this crate provides all the
  necessary features without exposing quinn's types.

## [0.4.1] - 2024-07-30

### Added

- The `ConnectionBuilder` struct has been enhanced to allow for the setting of
  certificates, private keys, and root certificates. This includes new methods
  to set and replace these components:

  - `ConnectionBuilder::cert` sets the client certificate for the connection.
  - `ConnectionBuilder::key` sets the client's private key for the connection.
  - `root_certs` sets the root certificates for the connection.
  
  These additions provide more flexibility in managing secure connections by
  allowing certificates and keys to be updated dynamically.
- The `update_config` is added to the `request::Handler` trait. This function
  allows the server to notify agents to take actions to update their
  configuration.

### Deprecated

- The `handshake` function in the `client` module is deprecated. This function
  will be removed in the next major/minor release. Applications using
  review-protocol should now create a `Connection` instance using
  `ConnectionBuilder` instead of calling `quinn::Endpoint::connect` and
  `client::handshake` separately.
- The `reload_config` function in the `request::Handler` trait is deprecated.
  This function will be removed in the next major/minor release. Applications
  using review-protocol should now use the `update_config` function in the
  client API to make agents update their configuration.

## [0.4.0] - 2024-07-22

### Added

- New `ConnectionBuilder` struct in the `client` module for creating customized
  connections. This allows for more flexible configuration of TLS settings and
  root certificates.
  - `ConnectionBuilder::new` function to create a new builder with given remote
    and local configurations.
  - `ConnectionBuilder::add_root_certs` method to add root certificates to the
    endpoint's certificate store.
  - `ConnectionBuilder::local_addr` method to set a specific local address for
    binding.
  - `ConnectionBuilder::connect` method to construct the final `Connection`
    instance. This combines `quinn::Endpoint::connect` and
    `review-protocol::client::handshake`. This simplifies the connection process
    for applications using review-protocol, reducing code duplication.
    Applications using review-protocol should now create a `Connection` instance
    using `ConnectionBuilder` instead of calling `quinn::Endpoint::connect` and
    `client::handshake` separately.
- `Connection` struct in the `client` module. This provides a protocol-specific
  connection, improving encapsulation and making the API more idiomatic to
  review-protocol.
  - Methods like `local_addr`, `remote_addr`, `close_reason`, `open_bi`, and `accept_bi`
    to interact with the connection.
- Introduced `EventCategory` enum to categorize security events.
- New client API `get_config()` to fetch configuration from the server. This
  method allows clients to request and receive configuration data from the
  server. The format of the configuration is left to the caller to interpret.

### Changed

- The `handshake` function in the `client` module no longer returns the
  `SendStream` and `RecvStream` handles. These values were previously returned
  but not used by the caller, so they have been removed to simplify the
  function's return type.
- Minimized dependencies when only default features are used.
  - Made several dependencies optional and tied them to specific features.
    `anyhow`, `async-trait`, `num_enum`, `semver`, and `thiserror` are now
    optional dependencies.
  - Modified `unary_request` function to return `std::io::Result` instead of
    `anyhow::Result`.

### Removed

- Direct dependency on `quinn::Connection` in the public API. The `Connection`
  struct now encapsulates the `quinn::Connection` and `quinn::Endpoint`.
- Removed unused configurations and fields to streamline the crate and improve
  maintainability. These removals are based on the observation that these items
  were not being utilized by any applications depending on review-database.
  - `ReconvergeConfig` has been eliminated.
  - `review_address` field has been removed from `HogConfig`, `PigletConfig`,
    and `CrusherConfig`.

## [0.3.0] - 2024-05-28

### Added

- Added a public API that provides `frame` functionality to avoid exposing `oinq`'s
  `frame`. This change improves the modularity of the `review-protocol`.
- `server::send_trusted_domain_list` to facilitate sending the trusted domain
  list from the server to the client.

## Changed

- `HandshakeError::ReadError` now provides the underlying error as
  `std::io::Error`, which is more informative than the previous custom error
  type.
- Update `oinq` to version `0.13.0`. Updating to this version results in the
  following changes.
  - Bump dependencies.
    - Update quinn to version 0.11.
    - Update rustls to version 0.23.
    - Update rcgen to version 0.13.
  - Fixed the handling of the error types provided by `oinq`. `oinq` has
    changed from providing the `RecvError`/`SendError` error type to providing
    the `std::io::Error` error type. As a result, `review-protocol` has also
    been modified to `std::io::Error` or convert to the correct internally
    defined error type.

## [0.2.0] - 2024-04-04

### Added

- `AgentInfo` to represent the agent's information during the handshake process.
- `request::Handler`, `request::handle`, and other related types needed to
  implement a request handler.

### Changed

- `SendError::MessageTooLarge` no longer contains the underlying error,
  `std::num::TryFromIntError`, since it does not provide any useful information.
- Merge `SendError`'s `MessageTooLarge` and `SerializationFailure`, and
  `HandshakeError`'s `MessageTooLarge` and `SerializationFailure` into
  `MessageTooLarge`, since serialization into a memory buffer fails only when
  the message is too large.

## [0.1.2] - 2024-03-25

### Added

- Types used in the protocol:
  - `Process`
  - `TrafficFilterRule`
- `client::send_ok` and `client::send_err` methods to facilitate sending
  responses from the client to the server.

## [0.1.1] - 2024-03-21

### Added

- Types used in the protocol:
  - `Config`
  - `CrusherConfig`
  - `HogConfig`
  - `HostNetworkGroup`
  - `PigletConfig`
  - `ReconvergeConfig`
  - `ResourceUsage`
- `HandshakeError` for the handshake process.
- `frame` module for low-level protocol communication. This module provides the
  necessary communication primitives and ensures compatibility with the `oinq`
  crate until the protocol's full implementation.
- `client::send_request` method to facilitate initiating requests from the
  client to the server.

## [0.1.0] - 2024-03-15

### Added

- `unary_request` exchanges RPC-like messages between agents.
- The `request` module provides request handlers that an agent needs to
  implement.
- `client::handshake` implements the application-level handshake process for the
  client after a QUIC connection is established.

[Unreleased]: https://github.com/petabi/review-protocol/compare/0.4.2...main
[0.4.2]: https://github.com/petabi/review-protocol/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/petabi/review-protocol/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/petabi/review-protocol/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-protocol/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-protocol/compare/0.1.2...0.2.0
[0.1.2]: https://github.com/petabi/review-protocol/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/petabi/review-protocol/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/petabi/review-protocol/tree/0.1.0
