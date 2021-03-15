extern crate base64;

pub(crate) fn convert_hex_to_b64(input: Vec<u8>) -> String {
    base64::encode(&input)
}

#[cfg(test)]
mod test {
    use crate::ex_1_hex_to_b64::convert_hex_to_b64;

    #[test]
    fn test_conversion() {
        let input = hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(convert_hex_to_b64(input.to_vec()), expected);
    }
}
