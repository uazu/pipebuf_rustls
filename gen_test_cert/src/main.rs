use rcgen::{CertificateParams, KeyPair};

/// Generate and dump Rust source for a self-signed certificate and
/// private key in PEM format.  Expires in 2099
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(vec!["example.com".into()])?;
    params.not_after = params.not_after.replace_year(2099).unwrap();

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    println!("const CERT_PEM: &str = r\"\n{cert_pem}\";");
    println!("const KEY_PEM: &str = r\"\n{key_pem}\";");
    Ok(())
}
