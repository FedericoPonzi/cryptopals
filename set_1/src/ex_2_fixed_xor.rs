use std::ops::BitXor;

fn fixed_xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    a.into_iter()
        .enumerate()
        .map(|(i, v)| b.get(i).unwrap().bitxor(v))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::ex_2_fixed_xor::fixed_xor;
    use hex_literal::hex;

    #[test]
    fn test_conversion() {
        let a = hex!("1c0111001f010100061a024b53535009181c");
        let b = hex!("686974207468652062756c6c277320657965");
        let expected = hex!("746865206b696420646f6e277420706c6179");
        assert_eq!(fixed_xor(a.to_vec(), b.to_vec()), expected);
    }
}
