# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `AgentInfo` to represent the agent's information during the handshake process.
- `server::handshake` implements the application-level handshake process for the
  server after a QUIC connection is established.

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

[Unreleased]: https://github.com/petabi/review-protocol/compare/0.1.2...main
[0.1.2]: https://github.com/petabi/review-protocol/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/petabi/review-protocol/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/petabi/review-protocol/tree/0.1.0
