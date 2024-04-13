use pipebuf::PipeBufPair;
use pipebuf_rustls::{TlsClient, TlsServer};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;

// This is testing code so it uses `unwrap()` liberally.  In real life
// you'd need to handle all these errors.

const DEBUG: bool = false;

// Send a byte and close each way
#[test]
fn byte_each_way() {
    do_test(
        vec![Op::Req(1), Op::ReqEnd, Op::Resp(1), Op::RespEnd, Op::Run],
        Configs::gen(),
    );
}

/// Send a byte and close, close comes back
#[test]
fn send_only() {
    let configs = Configs::gen();
    for immediate in [false, true] {
        let mut ops = Vec::new();
        if !immediate {
            ops.push(Op::Run);
        }
        ops.push(Op::Req(1));
        ops.push(Op::ReqEnd);
        ops.push(Op::Run);
        ops.push(Op::RespEnd);
        ops.push(Op::Run);
        do_test(ops, configs.clone());
    }
}

/// Recv a byte and close, send close back
#[test]
fn recv_only() {
    let configs = Configs::gen();
    for immediate in [false, true] {
        let mut ops = Vec::new();
        if !immediate {
            ops.push(Op::Run);
        }
        ops.push(Op::Resp(1));
        ops.push(Op::RespEnd);
        ops.push(Op::Run);
        ops.push(Op::ReqEnd);
        ops.push(Op::Run);
        do_test(ops, configs.clone());
    }
}

/// Exhaustively test all combinations of a small set of operations
/// focussed on startup, small amounts of data, push, close/abort
/// handling and running the network.  This is designed to shake out
/// issues in any dark corners in the code apart from bulk data
/// transfer.  It runs almost 2000 tests.
#[test]
fn combinations() {
    let configs = Configs::gen();

    const C1: u16 = 1; // Client send one byte
    const CP: u16 = 2; // Client push and send another byte
    const CC: u16 = 4; // Client close
    const CA: u16 = 8; // Client abort
    const S1: u16 = 16; // Server send one byte
    const SP: u16 = 32; // Server push and send another byte
    const SC: u16 = 64; // Server close
    const SA: u16 = 128; // Server abort

    fn recurse(v: &mut Vec<Op>, map: u16, configs: &Configs) {
        let vlen = v.len();
        let cca = 0 != (map & (CC | CA)); // Client closed or aborted
        let sca = 0 != (map & (SC | SA)); // Server closed or aborted
        if cca && sca {
            v.push(Op::Run);
            do_test(v.clone(), configs.clone());
            v.drain(vlen..);
            return;
        }
        macro_rules! bit_recurse {
            ($bit:ident, $cond:expr $(, $op:expr)+) => {
                if 0 == (map & $bit) && $cond {
                    $( v.push($op); )+
                        recurse(v, map | $bit, configs);
                    v.drain(vlen..);
                }
            }
        }
        bit_recurse!(C1, !cca, Op::Req(1));
        bit_recurse!(
            CP,
            !cca && matches!(v.last(), Some(Op::Req(_))),
            Op::ReqPush,
            Op::Run,
            Op::Req(1)
        );
        bit_recurse!(CC, !cca, Op::ReqEnd);
        bit_recurse!(CA, !cca, Op::ReqAbort);
        bit_recurse!(S1, !sca, Op::Resp(1));
        bit_recurse!(
            SP,
            !sca && matches!(v.last(), Some(Op::Resp(_))),
            Op::RespPush,
            Op::Run,
            Op::Resp(1)
        );
        bit_recurse!(SC, !sca, Op::RespEnd);
        bit_recurse!(SA, !sca, Op::RespAbort);

        if !matches!(v.last(), Some(Op::Run)) {
            v.push(Op::Run);
            recurse(v, map, configs);
            v.pop();
        }
    }

    recurse(&mut Vec::new(), 0, &configs);
    //recurse(&mut Vec::new(), CP | SP, &configs); // Don't need to test push
}

/// Series of tests of random lengths, of random segment lengths,
/// randomly sending at one end or both simultaneously.
#[test]
fn rand_seq() {
    let configs = Configs::gen();
    let mut rand = Rand32::new(9876);
    for _ in 0..10 {
        let mut ops = Vec::new();
        if 0 == (rand.get() & 1) {
            ops.push(Op::Run);
        }
        for _ in 0..((rand.get() & 255) + 10) {
            let v = rand.get() as usize;
            // From 1 to 64K, biased towards smaller values, kind of
            // exponential/log weighting
            let len = (((v >> 4) & 0xFFFF) >> ((v >> 20) & 15)) + 1;
            match v % 3 {
                0 => ops.push(Op::Req(len)),
                1 => ops.push(Op::Resp(len)),
                _ => {
                    ops.push(Op::Req(len));
                    let v = rand.get() as usize;
                    let len = (((v >> 4) & 0xFFFF) >> ((v >> 20) & 15)) + 1;
                    ops.push(Op::Resp(len));
                }
            }
            ops.push(Op::Run);
        }
        ops.push(Op::ReqEnd);
        ops.push(Op::RespEnd);
        ops.push(Op::Run);
        do_test(ops, configs.clone());
    }
}

#[derive(Copy, Clone, Debug)]
enum Op {
    Req(usize),
    ReqPush,
    ReqEnd,
    ReqAbort,
    Resp(usize),
    RespPush,
    RespEnd,
    RespAbort,
    Run,
}

/// Run the following chain, executing the given list of operations:
///
/// ```
/// client <=> TlsClient <=> transport <=> TlsServer <=> server
/// ```
///
fn do_test(ops: Vec<Op>, configs: Configs) {
    if DEBUG {
        println!("{ops:?}");
    }

    let mut client_send_data = RandStream::new(1234);
    let mut client_recv_data = RandStream::new(4321);
    let mut client = PipeBufPair::new();
    let mut tls_client = TlsClient::new(configs.client).unwrap();
    let mut transport = PipeBufPair::new();
    let mut tls_server = TlsServer::new(configs.server).unwrap();
    let mut server = PipeBufPair::new();
    let mut server_send_data = client_recv_data.clone();
    let mut server_recv_data = client_send_data.clone();

    for op in ops {
        match op {
            Op::Req(len) => {
                let mut client_wr = client.left().wr;
                let space = client_wr.space(len);
                client_send_data.generate(space);
                client_wr.commit(len);
            }
            Op::ReqPush => client.left().wr.push(),
            Op::ReqEnd => client.left().wr.close(),
            Op::ReqAbort => client.left().wr.abort(),
            Op::Resp(len) => {
                let mut server_wr = server.right().wr;
                let space = server_wr.space(len);
                server_send_data.generate(space);
                server_wr.commit(len);
            }
            Op::RespPush => server.right().wr.push(),
            Op::RespEnd => server.right().wr.close(),
            Op::RespAbort => server.right().wr.abort(),
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

                // Check that any bytes that have arrived at server or client
                // match what is expected, and consume data and EOFs
                let mut client_rd = client.left().rd;
                let data = client_rd.data();
                assert!(client_recv_data.check(data), "Client receive data mismatch");
                client_rd.consume(data.len());
                client_rd.consume_eof();
                let mut server_rd = server.right().rd;
                let data = server_rd.data();
                assert!(server_recv_data.check(data), "Server receive data mismatch");
                server_rd.consume(data.len());
                server_rd.consume_eof();

                if DEBUG {
                    println!(
                        "{:?} {:?} {:?} / {:?} {:?} {:?}",
                        client.right().rd.state(),
                        transport.right().rd.state(),
                        server.right().rd.state(),
                        server.left().rd.state(),
                        transport.left().rd.state(),
                        client.left().rd.state(),
                    );
                }

                // Check that EOF status and final data have been
                // faithfully passed through
                if client.left().wr.is_eof() {
                    assert!(client.right().rd.is_done());
                    assert!(server.right().rd.is_done());
                    if client.right().rd.is_aborted() {
                        assert!(server.right().rd.is_aborted());
                    }
                    assert_eq!(client_send_data.len, server_recv_data.len);
                }
                if server.right().wr.is_eof() {
                    assert!(server.left().rd.is_done());
                    assert!(client.left().rd.is_done());
                    if server.left().rd.is_aborted() {
                        assert!(client.left().rd.is_aborted());
                    }
                    assert_eq!(server_send_data.len, client_recv_data.len);
                }
            }
        }
    }
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

    fn check(&mut self, src: &[u8]) -> bool {
        for &b in src {
            if b != self.next() {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
struct Configs {
    server: Option<Arc<ServerConfig>>,
    client: Option<(Arc<ClientConfig>, ServerName<'static>)>,
}

impl Configs {
    fn gen() -> Self {
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

        Self {
            server: Some(Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certificate_chain, private_key)
                    .unwrap(),
            )),
            client: Some((
                Arc::new(
                    ClientConfig::builder()
                        .with_root_certificates(root_certs)
                        .with_no_client_auth(),
                ),
                ServerName::try_from("example.com").unwrap(),
            )),
        }
    }
}
