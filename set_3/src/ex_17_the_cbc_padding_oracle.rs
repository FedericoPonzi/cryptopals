//! https://cryptopals.com/sets/3/challenges/17
const BLOCK_SIZE: usize = 16;

/// https://en.wikipedia.org/wiki/Padding_oracle_attack
///
const CRYPTOTEXTS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];
struct Manager {
    key: [u8; BLOCK_SIZE],
    iv: [u8; BLOCK_SIZE],
    index: usize,
}
impl Manager {
    fn select(&self) -> Vec<u8> {
        crypto::aes::cbc::encrypt_with_iv(
            &self.iv,
            &self.key,
            &crypto::Pkcs7::pad_16(&base64::decode(CRYPTOTEXTS[self.index]).unwrap()),
        )
    }
    ///The second function should consume the ciphertext produced by the first function,
    /// decrypt it, check its padding, and return true or false depending on whether the padding is valid.
    fn check_padding(&self, iv: &[u8; BLOCK_SIZE], ciphertext: Vec<u8>) -> bool {
        let pt = crypto::aes::cbc::decrypt_with_iv(iv, &self.key, &ciphertext);
        crypto::Pkcs7::is_padding_valid(pt)
    }
    fn get(&self) -> Vec<u8> {
        base64::decode(CRYPTOTEXTS[self.index]).unwrap()
    }
}
fn gen_mask(x: u8, y: u8) -> u8 {
    let mut mask = 0;
    for i in 0..8 {
        let m = 1 << i;
        if x & m != y & m {
            mask |= m;
        }
    }
    return mask;
}

fn solve_block(manager: &Manager, ciphertext: Vec<u8>) -> Vec<u8> {
    let mut zeroing_iv = vec![0; BLOCK_SIZE];
    for pad_val in 1..BLOCK_SIZE + 1 {
        let mut padding_iv = [0; BLOCK_SIZE];
        zeroing_iv
            .iter()
            .enumerate()
            .for_each(|(index, b)| padding_iv[index] = pad_val as u8 ^ b);
        let mut last_candidate = None;
        let index = BLOCK_SIZE - pad_val;
        for candidate in 0..=255 {
            padding_iv[index] = candidate;
            if manager.check_padding(&padding_iv, ciphertext.clone()) {
                if pad_val == 1 {
                    padding_iv[BLOCK_SIZE - 2] = 0;
                    if !manager.check_padding(&padding_iv, ciphertext.clone()) {
                        continue;
                    }
                }
                last_candidate = Some(candidate);
                break;
            }
        }
        zeroing_iv[index] =
            last_candidate.expect("Could not find a valid candidate :(") ^ pad_val as u8;
    }
    zeroing_iv
}

fn solve(manager: Manager) -> Vec<u8> {
    let ciphertext = manager.select();
    let mut ret = vec![];
    let mut iv = manager.iv.to_vec();
    let blocks: Vec<Vec<u8>> = ciphertext.chunks(BLOCK_SIZE).map(Vec::from).collect();

    for b in blocks {
        let dec = solve_block(&manager, b.clone());
        dec.into_iter()
            .zip(iv.into_iter())
            .map(|(a, b)| a ^ b)
            .for_each(|pt| ret.push(pt));
        iv = b;
    }
    crypto::Pkcs7::remove_padding(ret).unwrap()
}

#[cfg(test)]
mod test {
    use crate::ex_17_the_cbc_padding_oracle::{gen_mask, solve, Manager, CRYPTOTEXTS};
    use crypto::aes::random_key;

    #[test]
    fn test_solve() {
        let key = random_key();
        let iv = random_key();
        let index = rand::random::<usize>() % CRYPTOTEXTS.len();
        let manager = Manager { key, iv, index };
        //let manager = Manager::new();
        assert_eq!(
            String::from_utf8_lossy(&manager.get()).to_string(),
            String::from_utf8_lossy(&solve(manager)).to_string()
        );
    }
    #[test]
    fn test_gen_mask() {
        let x = 10;
        let y = 5;
        assert_eq!(gen_mask(x, y) ^ x, y);
        assert_eq!(gen_mask(x, y) ^ y, x);
    }
}
