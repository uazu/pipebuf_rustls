# Significant feature changes and additions

This project follows Rust semantic versioning.

Note that every minor version change is a breaking change because
Rustls has breaking changes.

<!-- see keepachangelog.com for format ideas -->

## 0.23.1 (2024-09-16)

### Added

- `TlsClient::connection` and `TlsServer::connection` to get immutable
  access to the wrapped Rustls structure, for obtaining `server_name`,
  ALPN info, or whatever.

## 0.23.0 (2024-04-14)

### Added

- Support client TLS handling as well as server
- Support using Rustls unbuffered interface (not yet recommended)
- Thorough testing implemented in-crate

### Fixed

- EOF handling bug in server code

## 0.21.0 (2023-05-18)

Initial release, server handling only

<!-- Local Variables: -->
<!-- mode: markdown -->
<!-- End: -->
