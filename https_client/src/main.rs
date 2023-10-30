use crate::ciphers::TLS_RSA_WITH_AES_128_GCM_SHA256;
use byteorder::WriteBytesExt;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::TcpStream;

struct TLSClient {}

mod ciphers {
    pub(crate) const TLS_RSA_WITH_AES_128_GCM_SHA256: [u8; 2] = [0x00, 0x39];
}
mod record_type {
    pub(crate) const HANDSHAKE: u8 = 0x16;
}

fn get_tls_client_hello() -> anyhow::Result<Vec<u8>> {
    let mut ret = vec![];
    ret.write_u8(record_type::HANDSHAKE)?;
    let protocol_version = vec![3, 1];
    ret.write_all(&protocol_version)?;
    let handshake = 0x01;
    ret.write_u8(handshake)?;
    // The client provides 32 bytes of random data
    // The TLS 1.2 spec says that the first 4 bytes should be the current
    // time in seconds-since-1970 but this is now recommended against as
    // it enables fingerprinting of hosts and servers.
    let random: [u8; 32] = rand::random();
    let session_id = vec![0];
    // The client provides an ordered list of which cryptographic methods it will
    // support for key exchange, encryption with that exchanged key, and message authentication.
    // The list is in the order preferred by the client, with highest preference first.
    let cipher_suite = vec![
        0x00,
        0x02,
        TLS_RSA_WITH_AES_128_GCM_SHA256[0],
        TLS_RSA_WITH_AES_128_GCM_SHA256[1],
    ];
    // The client provides an ordered list of which compression methods it will support.
    // This compression would be applied before encryption (as encrypted data is usually incompressible).
    // Compression has characteristics that can weaken the security of the encrypted data
    // (see CRIME). so this feature has been removed from future TLS protocols.
    let compression_method = vec![0x01, 0x00];
    ret
}

fn main() -> anyhow::Result<()> {
    println!("Hello, world!");
    let mut stream = TcpStream::connect("https://www.google.com")?;
    let sock = TcpStream::connect("https://www.google.com")?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_tls_client_hello() {}
}
