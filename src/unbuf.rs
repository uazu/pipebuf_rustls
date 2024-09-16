use crate::TlsError;
use pipebuf::{tripwire, PBufRdWr, PBufState};
use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::ConnectionState;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

/// Rustls-unbuffered bug/limitation: After `Closed`, no more
/// `WriteTraffic` states come through.  This means that the final
/// bytes on the outgoing side cannot be sent, and the EOF is not
/// handled.  We can't do anything about the unsent outgoing bytes,
/// but we can fake the EOF handling.
const FIXUP_CLOSE: bool = true;

macro_rules! read_early_data {
    (true, $red:ident, $discard:ident, $int:ident) => {{
        // Accept early data, despite security concerns.  The caller
        // can limit early data in the config.
        while let Some(rec) = $red.next_record() {
            let rec =
                rec.map_err(|e| TlsError(format!("Failed fetching TLS incoming data: {e}")))?;
            $discard += rec.discard;
            $int.wr.append(rec.payload);
        }
    }};
    (false, $red:ident, $discard:ident, $int:ident) => {{
        return Err(TlsError("Not expecting early data on client".into()));
    }};
}

// To share processing code requires a macro, due to static typing of
// the unbuffered API (no traits)
macro_rules! process {
    ($ext:ident, $int:ident, $conn:ident, $is_server:tt) => {{
        if $int.rd.is_aborted() || $ext.rd.is_aborted() {
            // Give up totally on abort in either direction
            $int.rd.consume($int.rd.data().len());
            $int.rd.consume_eof();
            $ext.rd.consume($ext.rd.data().len());
            $ext.rd.consume_eof();
            if !$ext.wr.is_eof() {
                $ext.wr.abort();
            }
            if !$int.wr.is_eof() {
                $int.wr.abort();
            }
        } else {
            let mut discard = 0;
            loop {
                $ext.rd.consume(discard);
                discard = 0;

                if $ext.rd.data().len() == 0 && $ext.rd.consume_eof() {
                    // Normal close.  Maybe the TLS engine got a
                    // `close_notify` or maybe not.  So duplicate `Closed`
                    // handling here.
                    if !$int.wr.is_eof() {
                        $int.wr.close();
                    }
                    if FIXUP_CLOSE && $int.rd.consume_eof() {
                        $int.rd.consume($int.rd.data().len());
                        if $int.rd.is_aborted() {
                            $ext.wr.abort();
                        } else {
                            $ext.wr.close();
                        }
                    }
                    break;
                }

                let status = $conn.process_tls_records($ext.rd.data_mut());
                discard += status.discard;
                let state = status.state.map_err(|e| {
                    TlsError(format!(
                        "Failed whilst processing incoming TLS records: {e}"
                    ))
                })?;
                match state {
                    ConnectionState::ReadTraffic(mut rt) => {
                        while let Some(rec) = rt.next_record() {
                            let rec = rec.map_err(|e| {
                                TlsError(format!("Failed fetching TLS incoming data: {e}"))
                            })?;
                            discard += rec.discard;
                            $int.wr.append(rec.payload);
                        }
                    }
                    ConnectionState::ReadEarlyData(mut _red) => {
                        read_early_data!($is_server, _red, discard, $int);
                    }
                    ConnectionState::Closed => {
                        if !$int.wr.is_eof() {
                            $int.wr.close();
                        }
                        if FIXUP_CLOSE && $int.rd.consume_eof() {
                            $int.rd.consume($int.rd.data().len());
                            if $int.rd.is_aborted() {
                                $ext.wr.abort();
                            } else {
                                $ext.wr.close();
                            }
                        }
                        break;
                    }
                    ConnectionState::EncodeTlsData(mut etd) => {
                        // The Rustls 0.23 API doesn't tell us how much
                        // space is required.  Apparently could require up
                        // to 18KB.
                        let len = etd.encode($ext.wr.space(18 * 1024)).map_err(|e| {
                            TlsError(format!("Failed to write TLS handshake record: {e}"))
                        })?;
                        if !$ext.wr.is_eof() {
                            $ext.wr.commit(len);
                        }
                    }
                    ConnectionState::TransmitTlsData(ttd) => {
                        // I guess this state is to make sure that it is
                        // transmitted?  So "push" it?
                        $ext.wr.push();
                        ttd.done();
                    }
                    ConnectionState::BlockedHandshake => break,
                    ConnectionState::WriteTraffic(mut wt) => {
                        let wr_open = !$ext.wr.is_eof();
                        let data = $int.rd.data();
                        let len = data.len();
                        let closing = $int.rd.state() == PBufState::Closing;
                        if len == 0 && !closing {
                            break;
                        }
                        if len > 0 && wr_open {
                            // Rustls doesn't give us a way to tell how
                            // much space is required for TLS overheads.
                            // Allow the larger of 12% or 100 bytes.
                            let space = $ext.wr.space(len + (len >> 3).max(100));
                            let written = wt.encrypt(data, space).map_err(|e| {
                                TlsError(format!("Error encrypting outgoing data: {e}"))
                            })?;
                            $ext.wr.commit(written);
                            $int.rd.consume(len);
                        }
                        if closing {
                            // Rustls seems to need the
                            // `queue_close_notify` even if output is
                            // already closed, otherwise it gets stuck in
                            // an endless loop
                            $int.rd.consume_eof();
                            let space = $ext.wr.space(1024);
                            let written = wt.queue_close_notify(space).map_err(|e| {
                                TlsError(format!("Error encrypting outgoing close_notify: {e}"))
                            })?;
                            if wr_open {
                                $ext.wr.commit(written);
                                $ext.wr.close();
                            }
                        }
                    }
                    _ => return Err(TlsError(format!("Unexpected TLS state: {state:?}"))),
                }
            }
            $ext.rd.consume(discard);
        }
    }};
}

/// [`PipeBuf`] wrapper of [**Rustls**] [`UnbufferedServerConnection`]
///
/// If TLS is not configured then just passes data through unchanged.
///
/// There is a single "process" call that takes care of all the calls
/// required to move data between the encrypted and plain-text sides
/// of a [**Rustls**] `UnbufferedServerConnection`.
///
/// [`PipeBuf`]: https://crates.io/crates/pipebuf
/// [**Rustls**]: https://crates.io/crates/rustls
pub struct TlsServer {
    sc: Option<UnbufferedServerConnection>,
}

impl TlsServer {
    /// Create a new TLS engine using the given **Rustls**
    /// configuration, or set it up to just pass data straight through
    /// if there is no configuration provided.  Use the configuration
    /// to set `max_fragment_size` if required.
    pub fn new(config: Option<Arc<ServerConfig>>) -> Result<Self, rustls::Error> {
        let sc = if let Some(conf) = config {
            Some(UnbufferedServerConnection::new(conf)?)
        } else {
            None
        };

        Ok(Self { sc })
    }

    /// Get immutable access to the wrapped
    /// `UnbufferedServerConnection`, if available
    pub fn connection(&self) -> Option<&UnbufferedServerConnection> {
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
            process!(ext, int, sc, true);
        } else {
            // TLS disabled: Pass data through unchanged
            int.rd.forward(ext.wr.reborrow());
            ext.rd.forward(int.wr.reborrow());
        }

        let after = tripwire!(ext.rd, ext.wr, int.rd, int.wr);
        Ok(after != before)
    }
}

/// [`PipeBuf`] wrapper of [**Rustls**] [`UnbufferedClientConnection`]
///
/// If TLS is not configured then just passes data through unchanged.
///
/// There is a single "process" call that takes care of all the calls
/// required to move data between the encrypted and plain-text sides
/// of a [**Rustls**] `UnbufferedClientConnection`.
///
/// [`PipeBuf`]: https://crates.io/crates/pipebuf
/// [**Rustls**]: https://crates.io/crates/rustls
pub struct TlsClient {
    cc: Option<UnbufferedClientConnection>,
}

impl TlsClient {
    /// Create a new TLS engine using the given Rustls configuration,
    /// or set it up to just pass data straight through if there is no
    /// configuration provided
    pub fn new(
        config: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    ) -> Result<Self, rustls::Error> {
        let cc = if let Some((conf, name)) = config {
            Some(UnbufferedClientConnection::new(conf, name)?)
        } else {
            None
        };

        Ok(Self { cc })
    }

    /// Get immutable access to the wrapped
    /// `UnbufferedClientConnection`, if available
    pub fn connection(&self) -> Option<&UnbufferedClientConnection> {
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
            process!(ext, int, cc, false);
        } else {
            // TLS disabled: Pass data through unchanged
            int.rd.forward(ext.wr.reborrow());
            ext.rd.forward(int.wr.reborrow());
        }

        let after = tripwire!(ext.rd, ext.wr, int.rd, int.wr);
        Ok(after != before)
    }
}
