# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Types for agent configuration under `types`:
  - `Config`
  - `CrusherConfig`
  - `HogConfig`
  - `PigletConfig`
  - `ReconvergeConfig`
  - `ResourceUsage`

## [0.1.0] - 2024-03-15

### Added

- `unary_request` exchanges RPC-like messages between agents.
- The `request` module provides request handlers that an agent needs to
  implement.
- `client::handshake` implements the application-level handshake process for the
  client after a QUIC connection is established.

[Unreleased]: https://github.com/petabi/review-protocol/compare/0.1.0...main
[0.1.0]: https://github.com/petabi/review-protocol/tree/0.1.0
