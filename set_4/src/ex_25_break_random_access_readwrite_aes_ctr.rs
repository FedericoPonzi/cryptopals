//!
//! ### Break "random access read/write" AES CTR
//!
//! Back to CTR. Encrypt the recovered plaintext from
//! [this file](https://cryptopals.com/static/challenge-data/25.txt) (the ECB exercise) under CTR
//! with a random key (for this exercise the key should be unknown to you, but hold on to it).
//!
//! Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt
//! with different plaintext. Expose this as a function, like, _"edit(ciphertext, key, offset,
//! newtext)"_.
//!
//! Imagine the "edit" function was exposed to attackers by means of an API call that didn't
//! reveal the key or the original plaintext; the attacker has the ciphertext and controls the
//! offset and "new text".
//!
//! Recover the original plaintext.
//!
//! ### Food for thought.
//!
//! A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the
//! ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate
//! byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.

use std::iter;

struct Seeker {
    pt: Vec<u8>,
    key: Vec<u8>,
}
impl Seeker {
    fn new(pt: Vec<u8>, key: Vec<u8>) -> Self {
        Self { pt, key }
    }
    fn encrypt(&self) -> Vec<u8> {
        use crypto::aes::ctr::encrypt;
        let mut key = [0u8; 16];
        key.copy_from_slice(&self.key);
        encrypt(self.pt.clone(), 0, key)
    }

    fn edit(&mut self, offset: usize, new_text: Vec<u8>) -> Vec<u8> {
        let new_text_len = new_text.len();
        let mut new_pt = Vec::from(&self.pt[..offset]);
        new_pt.extend(&new_text);
        new_pt.extend(&self.pt[offset + new_text_len..]);
        self.pt = new_pt;
        self.encrypt()
    }
}

/// returns: recovered plaintext
/// the idea is that input is Msg1^key, we can pick msg2^key with msg2=0.
/// In this way we get the keystream back, which we can then use to decrypt msg1.
fn solve(mut seeker: Seeker) -> Vec<u8> {
    let ct = seeker.encrypt();
    let key_stream = seeker.edit(0, iter::repeat(0).take(ct.len()).collect());
    ct.iter()
        .zip(key_stream)
        .map(|(old, new)| old ^ new)
        .collect()
}

#[cfg(test)]
mod test {
    use crate::ex_25_break_random_access_readwrite_aes_ctr::{solve, Seeker};
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";

    fn get_pt() -> Vec<u8> {
        let b64_cipherlines: String = include_str!("../res/25.txt")
            .lines()
            .collect::<Vec<&str>>()
            .join("");
        let ciphertext = base64::decode(&b64_cipherlines).unwrap();
        crypto::aes::ecb::decrypt(KEY, ciphertext.as_slice())
    }

    #[test]
    fn test_edit() {
        let pt = b"hello_world".to_vec();
        let mut seeker = Seeker::new(pt, KEY.to_vec());
        seeker.edit("hello".len(), b" ".to_vec());
        assert_eq!(&seeker.pt, b"hello world");
    }

    #[test]
    fn test_solve() {
        let pt = get_pt();
        let seeker = Seeker::new(pt, KEY.to_vec());
        assert_eq!(solve(seeker), get_pt());
    }
}
