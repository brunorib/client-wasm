use openssl::rsa::Rsa;
use openssl::pkey::Public;
use openssl::x509::X509;

pub fn parse_x509(x509pem: String) -> Rsa<Public> {
    let cert: X509 = X509::from_pem(&x509pem.as_bytes()).unwrap();

    cert.public_key().unwrap().rsa().unwrap()
}