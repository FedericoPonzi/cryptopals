#[cfg(test)]
mod test {
    use crate::shared::single_byte_xor_dechiper;

    #[test]
    fn test_decipher() {
        let input = hex!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let expected = b"Cooking MC's like a pound of bacon";
        assert_eq!(
            single_byte_xor_dechiper(input.to_vec()).1,
            expected.to_vec()
        );
    }
}
