# `PipeBuf` wrapper for **Rustls**

This offers a single "process" call that takes care of all the calls
required to move data between the encrypted and plain-text sides of a
**Rustls** `ServerConnection`, transferring data via pipe-buffers.
This would typically be used along with other `PipeBuf`-supporting
crates such as `pipebuf_mio` to offer transport, along with a
`PipeBuf`-based implementation of the wrapped protocol to form a
complete processing chain.

### Documentation

See the [crate documentation](http://docs.rs/pipebuf_rustls).

# License

This project is licensed under either the Apache License version 2 or
the MIT license, at your option.  (See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT)).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
