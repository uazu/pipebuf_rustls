use crate::TlsError;
use pipebuf::{tripwire, PBufRdWr};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection};
use std::io::ErrorKind;
use std::sync::Arc;

/// [`PipeBuf`] wrapper of [**Rustls**] [`ClientConnection`]
///
/// If TLS is not configured then just passes data through unchanged.
///
/// There is a single "process" call that takes care of all the calls
/// required to move data between the encrypted and plain-text sides
/// of a [**Rustls**] `ClientConnection`.
///
/// [`PipeBuf`]: https://crates.io/crates/pipebuf
/// [**Rustls**]: https://crates.io/crates/rustls
pub struct TlsClient {
    cc: Option<ClientConnection>,
}

impl TlsClient {
    /// Create a new TLS engine using the given Rustls configuration,
    /// or set it up to just pass data straight through if there is no
    /// configuration provided
    pub fn new(
        config: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    ) -> Result<Self, rustls::Error> {
        let cc = if let Some((conf, name)) = config {
            Some(ClientConnection::new(conf, name)?)
        } else {
            None
        };

        Ok(Self { cc })
    }

    /// Get immutable access to the wrapped `ClientConnection`, if
    /// available
    pub fn connection(&self) -> Option<&ClientConnection> {
        self.cc.as_ref()
    }

    /// Process as much data as possible, moving data between `ext`
    /// and `int`.  `ext` is the pipe which typically carries TLS
    /// protocol data to/from an external TCP connection.  `int` is
    /// the pipe carrying plain-text data to/from whatever handlers
    /// there are on the internal side.
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

        if let Some(ref mut cc) = self.cc {
            loop {
                // ClientConnection -> ext.wr
                if cc.wants_write() && !ext.wr.is_eof() {
                    // We're not expecting any error from this as
                    // PipeBuf Write implementation doesn't return Err
                    // and `write_tls` is just copying from an
                    // internal Rustls buffer.
                    cc.write_tls(&mut ext.wr).map_err(|e| {
                        TlsError(format!(
                            "Unexpected error from ClientConnection::write_tls: {e}"
                        ))
                    })?;
                    // If we've done a `send_close_notify` and Rustls
                    // has nothing more to write, it's time to close
                    // the TLS outgoing stream too
                    if int.rd.is_done() && !cc.wants_write() {
                        ext.wr.close();
                    }
                    continue;
                }

                // int.rd -> ClientConnection; flushes only on "push"
                if !cc.is_handshaking() {
                    if !int.rd.is_empty() {
                        // Not expecting any error
                        int.rd.output_to(&mut cc.writer(), false).map_err(|e| {
                            TlsError(format!(
                                "Unexpected error from ClientConnection::writer.write: {e}"
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
                            cc.send_close_notify();
                        }
                        continue;
                    }
                }

                // ext.rd -> ClientConnection
                if cc.wants_read() && !ext.rd.is_empty() {
                    // We don't expect any error from this.  The
                    // PipeBuf Read implementation doesn't return an
                    // error if there are bytes.  The call may return
                    // an error if its buffer is full, but we only
                    // call it when it wants more data.
                    cc.read_tls(&mut ext.rd).map_err(|e| {
                        TlsError(format!(
                            "Unexpected failure from ClientConnection::read_tls: {e}"
                        ))
                    })?;

                    let state = cc
                        .process_new_packets()
                        .map_err(|e| TlsError(format!("TLS stream error: {e}")))?;

                    // ClientConnection -> int.wr
                    if !int.wr.is_eof() {
                        let read_len = state.plaintext_bytes_to_read();
                        if read_len > 0 {
                            if let Err(e) = int.wr.input_from(&mut cc.reader(), read_len) {
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
