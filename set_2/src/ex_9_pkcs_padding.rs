use crypto::Pkcs7;

#[cfg(test)]
mod test {
    use crate::ex_9_pkcs_padding::Pkcs7;

    #[test]
    fn test_ex_9() {
        let input = "YELLOW SUBMARINE".as_bytes();
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let padded = Pkcs7::pad(&input, 20);
        assert_eq!(padded.as_slice(), expected);
    }
}
