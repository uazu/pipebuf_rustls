//! [`PipeBuf`] wrapper around [**Rustls**]
//!
//! This offers a single "process" call that takes care of all the
//! calls required to move data between the encrypted and plain-text
//! sides of a [**Rustls**] client or server connection structure.
//! This would typically be used along with other
//! [`PipeBuf`]-supporting crates such as `pipebuf_mio` or similar to
//! offer transport, and a [`PipeBuf`]-based implementation of the
//! wrapped protocol to form a complete solution.
//!
//! Internally this uses either the buffered or unbuffered interface
//! provided by [**Rustls**], depending on which cargo feature is
//! selected.  The default is to use the buffered interface because
//! that is mature.  Whilst the unbuffered interface mostly works as
//! of 0.23.4, there are some rough corners (some failing tests in
//! this crate) and it doesn't yet offer any performance advantage due
//! to the planned [**Rustls**] unbuffered optimisations not yet being
//! implemented.
//!
//! # Versioning
//!
//! This crate follows the major/minor version number of the
//! [**Rustls**] crate it wraps.  Rustls is re-exported as
//! `pipebuf_rustls::rustls`.
//!
//! # Selecting [**Rustls**] crate features
//!
//! This crate brings in [**Rustls**] with only `std` enabled by
//! default (for buffered operation).  This means that you need to
//! include the same version of [**Rustls**] in your own dependencies
//! in order to select the features required, especially the crypto
//! provider.  This approach is necessary in order to allow you to use
//! `default-features = false` to disable `tls12` if necessary.  So
//! your dependency section may look like this to use the default
//! crypto provider:
//!
//! ```ignore
//! [dependencies]
//! pipebuf_rustls = "0.23"
//! rustls = "0.23"
//! ```
//!
//! Or maybe like this to use `ring`:
//!
//! ```ignore
//! [dependencies]
//! pipebuf_rustls = "0.23"
//! rustls = { version = "0.23", features = ["ring"] }
//! ```
//!
//! Or maybe like this to disable `tls12`:
//!
//! ```ignore
//! [dependencies]
//! pipebuf_rustls = "0.23"
//! rustls = { version = "0.23", default-features = false,
//!            features = ["aws_lc_rs", "logging"] }
//! ```
//!
//! Check out the [**Rustls**
//! `Cargo.toml`](https://github.com/rustls/rustls/blob/main/rustls/Cargo.toml)
//! to see how to control this.
//!
//! To use the Rustls unbuffered implementation (not recommended yet),
//! you'll need something like this:
//!
//! ```ignore
//! [dependencies]
//! pipebuf_rustls = { version = "0.23", default-features = false, features = ["unbuffered"] }
//! rustls = "0.23"
//! ```
//!
//! [`PipeBuf`]: https://crates.io/crates/pipebuf
//! [**Rustls**]: https://crates.io/crates/rustls

#![forbid(unsafe_code)]

pub use rustls;

#[cfg(all(not(feature = "unbuffered"), not(feature = "buffered")))]
compile_error!("Select a crate feature: either `buffered` or `unbuffered`");

// If they select both `unbuffered` and `buffered`, default to
// `buffered` for 0.23, since that is more mature
#[cfg(feature = "buffered")]
mod client;
#[cfg(feature = "buffered")]
mod server;
#[cfg(feature = "buffered")]
pub use client::TlsClient;
#[cfg(feature = "buffered")]
pub use server::TlsServer;

#[cfg(not(feature = "buffered"))]
mod unbuf;
#[cfg(not(feature = "buffered"))]
pub use unbuf::{TlsClient, TlsServer};

/// Error in TLS processing
#[derive(Debug)]
pub struct TlsError(String);

impl std::error::Error for TlsError {}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
