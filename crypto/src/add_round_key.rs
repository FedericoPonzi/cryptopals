/// With this transformation, we implement an XOR operation between the round key and the input bits.
pub fn add_round_key(state: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0u8; 16];
    state
        .iter()
        .cloned()
        .zip(round_key.iter().cloned())
        .map(|(s, k)| s ^ k)
        .enumerate()
        .for_each(|(pos, el)| ret[pos] = el);
    ret
}

#[cfg(test)]
mod test {
    use crate::add_round_key::add_round_key;

    #[test]
    fn test_add_round_keys() {
        let state = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let round_key = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1];
        assert_eq!(
            add_round_key(&state, &round_key),
            [3, 1, 7, 1, 3, 1, 15, 1, 3, 1, 7, 1, 3, 1, 31, 17]
        );
    }
}
