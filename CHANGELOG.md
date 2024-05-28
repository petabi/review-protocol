# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.0]: https://github.com/petabi/review-protocol/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-protocol/compare/0.1.2...0.2.0
[0.1.2]: https://github.com/petabi/review-protocol/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/petabi/review-protocol/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/petabi/review-protocol/tree/0.1.0
