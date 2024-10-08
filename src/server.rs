use crate::TlsError;
use pipebuf::{tripwire, PBufRdWr};
use rustls::{ServerConfig, ServerConnection};
use std::io::ErrorKind;
use std::sync::Arc;

/// [`PipeBuf`] wrapper of [**Rustls**] [`ServerConnection`]
///
/// If TLS is not configured then just passes data through unchanged.
///
/// There is a single "process" call that takes care of all the calls
/// required to move data between the encrypted and plain-text sides
/// of a [**Rustls**] `ServerConnection`.
///
/// [`PipeBuf`]: https://crates.io/crates/pipebuf
/// [**Rustls**]: https://crates.io/crates/rustls
pub struct TlsServer {
    sc: Option<ServerConnection>,
}

impl TlsServer {
    /// Create a new TLS engine using the given Rustls configuration,
    /// or set it up to just pass data straight through if there is no
    /// configuration provided
    pub fn new(config: Option<Arc<ServerConfig>>) -> Result<Self, rustls::Error> {
        let sc = if let Some(conf) = config {
            Some(ServerConnection::new(conf)?)
        } else {
            None
        };

        Ok(Self { sc })
    }

    /// Get immutable access to the wrapped `ServerConnection`, if
    /// available
    pub fn connection(&self) -> Option<&ServerConnection> {
        self.sc.as_ref()
    }

    /// Process as much data as possible, moving data between `ext`
    /// and `int`.  `ext` is the pipe which typically carries TLS
    /// protocol data to/from an external TCP connection.  `int` is
    /// the pipe carrying plain-text data to/from whatever protocol
    /// handlers there are on the internal side.
    ///
    /// If TLS is disabled, this just passes data straight through.
    ///
    /// Normal "Closing" end-of-file indicated from the internal side
    /// is converted into a TLS `close_notify`, i.e. a clean TLS
    /// shutdown.  "Aborting" end-of-file causes the TLS protocol
    /// stream to be abruptly closed, which will result in an
    /// "aborted" end-of-file status at the remote end.
    ///
    /// A clean `close_notify` end-of-file received by TLS from the
    /// external side results in a normal "Closing" end-of-file being
    /// indicated for the internal handlers.  Any other end-of-file
    /// results in an "Aborting" end-of-file.  Note that some TLS
    /// libraries always end their streams with an unclean shutdown.
    ///
    /// Returns `Ok(true)` if there was activity, `Ok(false)` if no
    /// progress could be made, and `Err(_)` if there was an error.
    pub fn process(&mut self, mut ext: PBufRdWr, mut int: PBufRdWr) -> Result<bool, TlsError> {
        let before = tripwire!(ext.rd, ext.wr, int.rd, int.wr);

        if let Some(ref mut sc) = self.sc {
            loop {
                // ServerConnection -> ext.wr
                if sc.wants_write() && !ext.wr.is_eof() {
                    // We're not expecting any error from this as
                    // PipeBuf Write implementation doesn't return Err
                    // and `write_tls` is just copying from an
                    // internal Rustls buffer.
                    sc.write_tls(&mut ext.wr).map_err(|e| {
                        TlsError(format!(
                            "Unexpected error from ServerConnection::write_tls: {e}"
                        ))
                    })?;
                    // If we've done a `send_close_notify` and Rustls
                    // has nothing more to write, it's time to close
                    // the TLS outgoing stream too
                    if int.rd.is_done() && !sc.wants_write() {
                        ext.wr.close();
                    }
                    continue;
                }

                if !sc.is_handshaking() {
                    // int.rd -> ServerConnection; flushes only on "push"
                    if !int.rd.is_empty() {
                        // Not expecting any error
                        int.rd.output_to(&mut sc.writer(), false).map_err(|e| {
                            TlsError(format!(
                                "Unexpected error from ServerConnection::writer.write: {e}"
                            ))
                        })?;
                        continue;
                    }
                    // int.rd is empty
                    if int.rd.consume_eof() {
                        if int.rd.is_aborted() {
                            // For Abort, don't terminate the TLS protocol
                            // nicely.  This will result in an
                            // UnexpectedEof at the other end.  It should
                            // be possible (on the other end of int.rd) to
                            // write data, push, and abort and that data
                            // will be sent before the abort of the
                            // ext.wr.
                            ext.wr.abort();
                        } else {
                            // Close cleanly with a "close_notify"
                            sc.send_close_notify();
                        }
                        continue;
                    }
                }

                // ext.rd -> ServerConnection
                if sc.wants_read() && !ext.rd.is_empty() {
                    // We don't expect any error from this.  The
                    // PipeBuf Read implementation doesn't return an
                    // error if there are bytes.  The call may return
                    // an error if its buffer is full, but we only
                    // call it when it wants more data.
                    sc.read_tls(&mut ext.rd).map_err(|e| {
                        TlsError(format!(
                            "Unexpected failure from ServerConnection::read_tls: {e}"
                        ))
                    })?;

                    let state = sc
                        .process_new_packets()
                        .map_err(|e| TlsError(format!("TLS stream error: {e}")))?;

                    // ServerConnection -> int.wr
                    if !int.wr.is_eof() {
                        let read_len = state.plaintext_bytes_to_read();
                        if read_len > 0 {
                            if let Err(e) = int.wr.input_from(&mut sc.reader(), read_len) {
                                match e.kind() {
                                    ErrorKind::WouldBlock => (),
                                    ErrorKind::UnexpectedEof => int.wr.abort(),
                                    _ => return Err(TlsError(format!("TLS read error: {e}"))),
                                }
                            }
                        }
                    }
                    continue;
                }

                // Pass through EOF from external side.  For the case
                // where a close has be handled from the internal side
                // (`send_close_notify()` and `int.rd.is_done()`), the
                // Rustls engine no longer accepts data from the
                // external side, so in that case just pass the EOF
                // through even thought there is pending data.
                if ext.rd.has_pending_eof()
                    && (ext.rd.is_aborted() || ext.rd.is_empty() || int.rd.is_done())
                {
                    ext.rd.consume_eof();
                    if !int.wr.is_eof() {
                        if ext.rd.is_aborted() {
                            int.wr.abort();
                        } else {
                            int.wr.close();
                        }
                    }
                    continue;
                }

                // Nothing left to do
                break;
            }
        } else {
            // TLS disabled: Pass data through unchanged
            int.rd.forward(ext.wr.reborrow());
            ext.rd.forward(int.wr.reborrow());
        }

        let after = tripwire!(ext.rd, ext.wr, int.rd, int.wr);
        Ok(after != before)
    }
}
