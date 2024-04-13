//! Benchmark a long stream of data through TlsServer and TlsClient,
//! with or without involving Rustls.  This measures setup, handshake,
//! overheads of passing data in and out and the encryption overheads.
//!
//! To get a flamegraph, run (adding `--features` option if required):
//!
//! ```
//! cargo bench --bench stream -- --profile-time=5
//! ```

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pprof::criterion::{Output, PProfProfiler};

use pipebuf::PipeBufPair;
use pipebuf_rustls::{TlsClient, TlsServer};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("stream with TLS, 1 bytes", |b| {
        b.iter(|| do_test(black_box(1234), 1, true))
    });
    c.bench_function("stream direct, 1 bytes", |b| {
        b.iter(|| do_test(black_box(1234), 1, false))
    });
    c.bench_function("stream with TLS, 1e6 bytes", |b| {
        b.iter(|| do_test(black_box(5678), 1000000, true))
    });
    c.bench_function("stream direct, 1e6 bytes", |b| {
        b.iter(|| do_test(black_box(5678), 1000000, false))
    });
    c.bench_function("stream with TLS, 2e6 bytes", |b| {
        b.iter(|| do_test(black_box(4321), 2000000, true))
    });
    c.bench_function("stream direct, 2e6 bytes", |b| {
        b.iter(|| do_test(black_box(4321), 2000000, false))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = criterion_benchmark
}
criterion_main!(benches);

/// Send `total_len` bytes each way
fn do_test(seed: u64, total_len: usize, use_tls: bool) {
    let mut rand = Rand32::new(seed);
    let (server_config, client_config) = if use_tls {
        let c = rustls_configs();
        (
            Some(Arc::new(c.0)),
            Some((Arc::new(c.1), ServerName::try_from("example.com").unwrap())),
        )
    } else {
        (None, None)
    };

    #[derive(Copy, Clone, Debug)]
    enum Op {
        Req(usize),
        ReqEnd,
        Resp(usize),
        RespEnd,
        Run,
    }

    let mut client_sent = 0;
    let mut server_sent = 0;
    let mut ops = Vec::new();
    while client_sent < total_len || server_sent < total_len {
        let v = rand.get() as usize;
        let mut len1 = (((v >> 4) & 0xFFF) + 1).min(total_len - client_sent);
        let mut len2 = (((v >> 16) & 0xFFF) + 1).min(total_len - server_sent);
        match v % 3 {
            0 => len2 = 0,
            1 => len1 = 0,
            _ => (),
        }
        if len1 > 0 {
            ops.push(Op::Req(len1));
            client_sent += len1;
        }
        if len2 > 0 {
            ops.push(Op::Resp(len2));
            server_sent += len2;
        }
        if len1 > 0 || len2 > 0 {
            ops.push(Op::Run);
        }
    }
    ops.push(Op::ReqEnd);
    ops.push(Op::RespEnd);
    ops.push(Op::Run);

    // Run the following chain, executing the given list of operations:
    //
    // ```
    // client <=> TlsClient <=> transport <=> TlsServer <=> server
    // ```
    //
    let mut client_send_data = RandStream::new(rand.get().into());
    let mut client = PipeBufPair::new();
    let mut tls_client = TlsClient::new(client_config).unwrap();
    let mut transport = PipeBufPair::new();
    let mut tls_server = TlsServer::new(server_config).unwrap();
    let mut server = PipeBufPair::new();
    let mut server_send_data = RandStream::new(rand.get().into());

    let mut client_recv = 0;
    let mut server_recv = 0;

    for op in ops {
        match op {
            Op::Req(len) => {
                let mut client_wr = client.left().wr;
                let space = client_wr.space(len);
                client_send_data.generate(space);
                client_wr.commit(len);
            }
            Op::ReqEnd => client.left().wr.close(),
            Op::Resp(len) => {
                let mut server_wr = server.right().wr;
                let space = server_wr.space(len);
                server_send_data.generate(space);
                server_wr.commit(len);
            }
            Op::RespEnd => server.right().wr.close(),
            Op::Run => {
                // Loop until all activity has ceased
                loop {
                    let client_activity = tls_client
                        .process(transport.left(), client.right())
                        .unwrap();
                    let server_activity = tls_server
                        .process(transport.right(), server.left())
                        .unwrap();
                    if !client_activity && !server_activity {
                        break;
                    }
                }

                // Consume data and EOFs
                let mut client_rd = client.left().rd;
                let len = client_rd.data().len();
                client_recv += len;
                client_rd.consume(len);
                client_rd.consume_eof();
                let mut server_rd = server.right().rd;
                let len = server_rd.data().len();
                server_recv += len;
                server_rd.consume(len);
                server_rd.consume_eof();
            }
        }
    }

    assert_eq!(client_recv, total_len);
    assert_eq!(server_recv, total_len);
}

/// 32-bit pseudo-random number generator using algorithm from
/// `oorandom` crate
#[derive(Clone)]
struct Rand32(u64);

impl Rand32 {
    const INC: u64 = 1442695040888963407;
    const MUL: u64 = 6364136223846793005;

    fn new(seed: u64) -> Self {
        let mut this = Self(0);
        let _ = this.get();
        this.0 = this.0.wrapping_add(seed);
        let _ = this.get();
        this
    }

    fn get(&mut self) -> u32 {
        let state = self.0;
        self.0 = state.wrapping_mul(Self::MUL).wrapping_add(Self::INC);
        let xorshifted = (((state >> 18) ^ state) >> 27) as u32;
        let rot = (state >> 59) as u32;
        xorshifted.rotate_right(rot)
    }
}

/// Pseudo-random stream of bytes from a seed
#[derive(Clone)]
struct RandStream {
    rand: Rand32,
    out: u32,
    len: usize,
}

impl RandStream {
    fn new(seed: u64) -> Self {
        Self {
            rand: Rand32::new(seed),
            out: 1,
            len: 0,
        }
    }

    fn next(&mut self) -> u8 {
        self.len += 1;
        let rv;
        if self.out > 1 {
            rv = self.out as u8;
            self.out >>= 8;
        } else {
            let rand = self.rand.get();
            rv = rand as u8;
            self.out = (rand >> 8) | 0x01000000;
        }
        rv
    }

    fn generate(&mut self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            dest[i] = self.next();
        }
    }
}

fn rustls_configs() -> (ServerConfig, ClientConfig) {
    // See `gen_test_cert/` folder to regenerate certificate and key.
    // Certificate expires in 2099.
    const CERT_PEM: &str = r"
-----BEGIN CERTIFICATE-----
MIIBXzCCAQagAwIBAgIUevHh1V8OzyjyztlIqH7ZNtHv9Q4wCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAw
MDBaGA8yMDk5MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWdu
ZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEV9vqnWeaunsOW1UkCC
vqi/VkkMV0XIBX9q/rVmAHkjehsESBSnxuVW2062Zxve0juIaCGO3XA4iRAyVFWo
CB+jGjAYMBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0cAMEQC
IA35DbL1xe6La3pUXbLUrylyN6gLytjU/C6+q3ctfzXiAiAmivvmmR+rQYWcAK2f
+9FkQCkIcUmO91CpOCC2qz9cUA==
-----END CERTIFICATE-----
";
    const KEY_PEM: &str = r"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7EIkh0WEIvb6pksT
67xl3DX9YlQF3YLMnyqxKlwdG4WhRANCAARFfb6p1nmrp7DltVJAgr6ov1ZJDFdF
yAV/av61ZgB5I3obBEgUp8blVttOtmcb3tI7iGghjt1wOIkQMlRVqAgf
-----END PRIVATE KEY-----
";

    let certificate_chain = rustls_pemfile::certs(&mut CERT_PEM.as_bytes())
        .map(|c| c.unwrap())
        .collect::<Vec<rustls::pki_types::CertificateDer>>();
    assert!(!certificate_chain.is_empty());

    let mut root_certs = RootCertStore::empty();
    assert_eq!(
        (1, 0), // Add one, ignore none
        root_certs.add_parsable_certificates(certificate_chain.clone())
    );

    let private_key = rustls_pemfile::private_key(&mut KEY_PEM.as_bytes())
        .unwrap()
        .unwrap();

    (
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .unwrap(),
        ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth(),
    )
}
