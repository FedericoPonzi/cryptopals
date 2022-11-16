//! There are people in the world that believe that CTR resists bit flipping attacks of the kind to
//! which CBC mode is susceptible.
//!
//! Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode.
//! Inject an "admin=true" token.

use crypto::Pkcs7;
const PREFIX: &[u8] = b"comment1=cooking%20MCs;";
const SUFFIX: &[u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

fn build_plaintext(comment: Vec<u8>) -> Vec<u8> {
    let escape = |comment: Vec<u8>| {
        let as_str = String::from_utf8_lossy(&comment);
        let res = as_str.replace(";", "").replace("=", "").into_bytes();
        res
    };
    let comment_escaped = escape(comment);
    PREFIX
        .to_vec()
        .into_iter()
        .chain(comment_escaped.to_vec())
        .chain(SUFFIX.to_vec())
        .collect()
}

struct UserManager {
    key: [u8; 16],
}

impl UserManager {
    fn create_encrypted_user(&self, comment: Vec<u8>) -> Vec<u8> {
        let plaintext = build_plaintext(comment);
        let padded = Pkcs7::pad(&plaintext, 16);
        crypto::aes::ctr::encrypt(padded, 0, self.key)
    }

    fn is_user_admin(&self, ciphertext: Vec<u8>) -> bool {
        let decrypted = crypto::aes::ctr::decrypt(ciphertext, 0, self.key);
        let decrypted = String::from_utf8_lossy(&decrypted);
        println!("{}", decrypted);

        decrypted
            .split(";")
            .into_iter()
            .any(|el| el == "admin=true")
    }
}

fn solve(manager: UserManager) -> bool {
    const BLOCK_SIZE: usize = 16;
    let prefix_pad = BLOCK_SIZE - PREFIX.len() % BLOCK_SIZE;
    let previous_block: usize = 16;
    let crack = ";admin=true;";
    // result: [prefix + AAA | AAAAAAA| AAAAAAA]
    let msg: Vec<u8> = std::iter::repeat(b'A')
        .take(prefix_pad + previous_block * 2)
        .collect();

    let mut ciphertext = manager.create_encrypted_user(msg.clone());
    let flipped: Vec<u8> = std::iter::repeat(b'A')
        .zip(crack.as_bytes())
        .map(|(a, b)| a ^ b)
        .collect();
    let mut start_index = PREFIX.len() + prefix_pad;

    for b in flipped {
        ciphertext[start_index] ^= b;
        start_index += 1;
    }
    manager.is_user_admin(ciphertext)
}

#[cfg(test)]
mod test {
    use crate::ex_26_ctr_bitflipping::{solve, UserManager};
    use crypto::aes::random_key;

    #[test]
    fn test_solution() {
        let key = random_key();
        let manager = UserManager { key };
        assert!(solve(manager));
    }
}
