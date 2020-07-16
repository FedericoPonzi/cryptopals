use std::ops::BitXor;

// Returns the input repeatedly XORed with key.
pub fn repeating_xor_key(input: &[u8], key: Vec<u8>) -> Vec<u8> {
    input
        .into_iter()
        .zip(key.into_iter().cycle())
        .map(|(ch, k)| ch.bitxor(k))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::ex_5_repeating_key_xor::repeating_xor_key;

    #[test]
    fn test_decipher() {
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
            .to_string()
            + "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let input = br#"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"#;
        let key = "ICE".bytes();
        let received = repeating_xor_key(input, key.collect());
        assert_eq!(hex::encode(received), expected);
    }
}
