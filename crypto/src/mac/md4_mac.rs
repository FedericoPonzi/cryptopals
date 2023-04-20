use crate::hash::md4::md4;

/// A simple md4 keyed MAC. It creates the hash of [key || payload].
pub fn md4_mac(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(key);
    buf.extend_from_slice(payload);
    md4(&buf)
}

#[cfg(test)]
mod test {
    use crate::hash::to_hex;
    use crate::mac::md4_mac;
    use std::assert_eq;

    #[test]
    fn test_md4_mac() {
        let tests = [("", "", "31d6cfe0d16ae931b73c59d7e0c089c0")];

        for (input, payload, expected) in tests {
            assert_eq!(
                to_hex(&md4_mac(input.as_bytes(), payload.as_bytes())),
                expected,
                "Failed on input: {}",
                expected
            );
        }
    }
}
