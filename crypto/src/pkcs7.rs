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
        input
            .iter()
            .map(|v| *v)
            .chain(
                (msg_size..(msg_size + padding))
                    .into_iter()
                    .map(|_| padding as u8),
            )
            .collect()
    }
    pub fn pad_16(input: &[u8]) -> Vec<u8> {
        Self::pad(input, 16)
    }

    /// Removes PKCS7 padding.
    pub fn remove_padding_unchecked(plaintext: Vec<u8>) -> Vec<u8> {
        Self::remove_padding(plaintext).unwrap()
    }
    pub fn is_padding_valid(plaintext: Vec<u8>) -> bool {
        Self::remove_padding(plaintext).is_some()
    }
    // Returns `Some` only if plaintext is padded with Pkcs7.
    pub fn remove_padding(plaintext: Vec<u8>) -> Option<Vec<u8>> {
        if plaintext.len() == 0 {
            return None;
        }
        // it should have the right length
        if plaintext.len() % 16 != 0 {
            return None;
        }

        let last_b = *plaintext.last().unwrap();
        // A valid  pkcs#7 last byte should be less than 16.
        if last_b > 16u8 || last_b <= 0 {
            return None;
        }
        let mut ret = plaintext.clone();
        for _ in 0..last_b as usize {
            let is_valid = ret.pop().map(|v| v == last_b).unwrap_or(false);
            if !is_valid {
                return None;
            }
        }
        return Some(ret);
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

        let unpadded = Pkcs7::remove_padding_unchecked(std::iter::repeat(16).take(16).collect());
        assert!(unpadded.is_empty());

        let invalid = Pkcs7::remove_padding(Vec::from(*b"123"));
        assert!(invalid.is_none(), "{:?}", invalid.unwrap());

        let unpadded = Pkcs7::remove_padding(vec![]);
        assert!(unpadded.is_none(), "{:?}", unpadded);
    }
}
