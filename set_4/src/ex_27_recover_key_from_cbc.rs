//! ### Recover the key from CBC with IV=Key
//!
//! Take your code from [the CBC exercise](https://cryptopals.com/sets/2/challenges/16) and modify it so that it repurposes the key for CBC encryption as the IV.
//!
//! Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.
//!
//! Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.
//!
//! The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).
//!
//! Use your code to encrypt a message that is at least 3 blocks long:
//!
//! ```AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3```
//!
//! Modify the message (you are now the attacker):
//!
//! ```C_1, C_2, C_3 -> C_1, 0, C_1```
//!
//! Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
//!
//! As the attacker, recovering the plaintext from the error, extract the key:
//!
//! ```P'_1 XOR P'_3```
//!

use crypto::utils::xor_vec_on_vec;
use std::iter;

struct UserManager {
    key: [u8; 16],
}

impl UserManager {
    fn create_encrypted(&self) -> Vec<u8> {
        const PT: &[u8] = b"comment1=cookin;comment2=%20like%20a%20pound%20;"; // 16*3 bytes long.
        crypto::aes::cbc::encrypt_with_iv(&self.key, &self.key, PT)
    }

    fn is_ascii(&self, ciphertext: Vec<u8>) -> Result<(), Vec<u8>> {
        println!("len: {}", ciphertext.len());
        let decrypted = crypto::aes::cbc::decrypt_with_iv(&self.key, &self.key, &ciphertext);
        String::from_utf8(ciphertext)
            .map_err(|_| decrypted)
            .map(|_| ())
    }
}

fn solve(manager: UserManager) -> [u8; 16] {
    const BLOCK_SIZE: usize = 16;

    let ciphertext = manager.create_encrypted();

    let c1_0_c1: Vec<u8> = ciphertext
        .clone()
        .into_iter()
        .take(16)
        .chain(iter::repeat(0).take(BLOCK_SIZE))
        .chain(ciphertext.into_iter().take(BLOCK_SIZE))
        .collect();

    let ret = manager.is_ascii(c1_0_c1);
    let decrypted = ret.unwrap_err();
    let c_p_1 = decrypted.clone().into_iter().take(BLOCK_SIZE).collect();
    let c_p_3 = decrypted.into_iter().skip(32).take(BLOCK_SIZE).collect();
    let key = xor_vec_on_vec(c_p_1, c_p_3);
    let mut ret = [0u8; BLOCK_SIZE];
    ret.copy_from_slice(&key);
    ret
}

#[cfg(test)]
mod test {
    use crate::ex_27_recover_key_from_cbc::{solve, UserManager};
    use crypto::aes::random_key;

    #[test]
    fn test_solution() {
        let key = random_key();
        let manager = UserManager { key };
        assert_eq!(solve(manager), key);
    }
}
