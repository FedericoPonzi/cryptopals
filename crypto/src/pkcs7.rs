pub struct Pkcs7;
impl Pkcs7 {
    /// A very simple padding implementation used by Pkcs7
    /// Padding is in whole bytes. The value of each
    /// added byte is the number of bytes that are added, i.e.
    /// N bytes, each of value N are added. The number of bytes added will
    /// depend on the block boundary to which the message needs to be extended.
    /// It's not superefficient because of heap allocation, but for the purpose of
    /// cryptopals allows for easier debugging.
    pub fn pad(input: &[u8], block_size: usize) -> Vec<u8> {
        let msg_size = input.len();
        let padding = block_size - (msg_size % block_size);
        let mut ret = Vec::from(input);

        for _ in msg_size..(msg_size + padding) {
            ret.push(padding as u8);
        }
        ret
    }

    /// Removes PKCS7 padding.
    pub fn remove_padding_unchecked(plaintext: Vec<u8>) -> Vec<u8> {
        Self::remove_padding(plaintext).unwrap()
    }

    // Returns `Some` only if plaintext is padded with Pkcs7.
    pub fn remove_padding(plaintext: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(b) = plaintext.last() {
            if *b < 16u8 {
                let mut ret = plaintext.clone();
                for _ in 0..*b as usize {
                    let is_valid = ret.pop().map(|v| v == *b).unwrap_or(false);
                    if !is_valid {
                        return None;
                    }
                }
                return Some(ret);
            }
        }
        None
    }
}
#[cfg(test)]
mod test {
    use crate::Pkcs7;

    #[test]
    fn test_pkcs7_padding() {
        let padded = Pkcs7::pad(b"123", 16);
        assert_eq!(
            Vec::from([49, 50, 51, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13]),
            padded
        );
        let unpadded = Pkcs7::remove_padding_unchecked(padded);
        assert_eq!(Vec::from(*b"123"), unpadded);

        let invalid = Pkcs7::remove_padding(Vec::from(*b"123"));
        assert!(invalid.is_none(), "{:?}", invalid.unwrap());
    }
}
