pub struct Pkcs7;
impl Pkcs7 {
    /// A very simple padding implementation used by Pkcs7
    /// Padding is in whole bytes. The value of each
    /// added byte is the number of bytes that are added, i.e.
    /// N bytes, each of value N are added. The number of bytes added will
    /// depend on the block boundary to which the message needs to be extended.
    fn pad(input: &mut [u8], msg_size: usize, block_size: usize) -> Result<(), String> {
        let padding = block_size - (msg_size % block_size);
        for i in msg_size..(msg_size + padding) {
            input[i] = padding as u8;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::ex_9_pkcs_padding::Pkcs7;

    #[test]
    fn test_ex_9() {
        let input = "YELLOW SUBMARINE".as_bytes();
        let msg_size = input.len();
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let mut output = [0u8; 20];
        output[..input.len()].copy_from_slice(input);
        Pkcs7::pad(&mut output, msg_size, 20).unwrap();
        assert_eq!(output, *expected);
    }
}
