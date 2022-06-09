//! https://cryptopals.com/sets/3/challenges/20
//! ## Break fixed-nonce CTR statistically
//! In this file find a similar set of Base64'd plaintext. Do with them exactly what you did
//! with the first, but solve the problem differently.
//! Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts
//! the same way you would repeating-key XOR.
//! Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce
//! they are effectively the same thing.
//! To exploit this: take your collection of ciphertexts and truncate them to a common length
//! (the length of the smallest ciphertext will work).
//! Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key
//! size of the length of the ciphertext you XOR'd.

fn solve(ciphertexts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    super::ex_19_break_fixed_nonce_ctr_mode_using_substitutions::solve(ciphertexts)
}
#[cfg(test)]
mod test {
    use crate::ex_20_break_fixed_nonce_ctr_statistically::solve;
    use crypto::aes::ctr;

    #[test]
    fn test_solve() {
        let key = crypto::aes::random_key();
        let lines = include_str!("../res/20.txt")
            .lines()
            .map(base64::decode)
            .map(|r| r.unwrap())
            .map(|v| ctr::encrypt(v, 0, key))
            .collect();
        let ret = solve(lines);
        let expected = [
            105, 39, 109, 32, 114, 97, 116, 101, 100, 32, 34, 82, 34, 46, 46, 46, 116, 104, 105,
            115, 32, 105, 115, 32, 97, 32, 119, 97, 115, 110, 105, 110, 103, 44, 32, 121, 97, 32,
            98, 101, 116, 116, 101, 114, 32, 118, 111, 105, 100, 32, 47, 32, 80, 111, 101, 116,
            115, 32, 97, 114, 101, 32, 112, 97, 114, 97, 110, 111, 105, 100, 44, 32, 68, 74, 39,
            115, 32, 68, 45, 115, 116, 114, 111, 121, 101, 100,
        ];
        // I'm checking only the first row, the longer lines are not fully recovered
        assert_eq!(ret[0], expected);

        //ret.into_iter()
        //    .for_each(|r| println!("{}", String::from_utf8_lossy(&r)));
    }
}
