use crate::hash::sha1::sha1;

pub fn sha1_mac(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(key);
    buf.extend_from_slice(payload);
    sha1(&buf)
}

#[cfg(test)]
mod test {
    use crate::hash::to_hex;
    use crate::mac::sha1_mac;
    use std::assert_eq;

    #[test]
    fn test_sha1_mac() {
        assert_eq!(
            to_hex(&sha1_mac(b"Secret key", b"Original message")),
            "5480f6e6ca2cf32fb3b5263f2eaf59f4a7fa0af8"
        );
    }
}
