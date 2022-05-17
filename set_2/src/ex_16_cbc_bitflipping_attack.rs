//! ### CBC bitflipping attacks
//!
//! Generate a random AES key.
//!
//! Combine your padding code and CBC code to write two functions.
//!
//! The first function should take an arbitrary input string, prepend the string:
//!
//! "comment1=cooking%20MCs;userdata="
//!
//! .. and append the string:
//!
//! ";comment2=%20like%20a%20pound%20of%20bacon"
//!
//! The function should quote out the ";" and "=" characters.
//!
//! The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
//!
//! The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
//!
//! Return true or false based on whether the string exists.
//!
//! If you've written the first function properly, it should _not_ be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.
//!
//! Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
//!
//! You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
//!
//! -   Completely scrambles the block the error occurs in
//! -   Produces the identical 1-bit error(/edit) in the next ciphertext block.
//!
//! ### Stop and think for a second.
//!
//! Before you implement this attack, answer this question: why does CBC mode have this property?

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
        crypto::aes::cbc::encrypt(&self.key, &padded)
    }

    fn is_user_admin(&self, ciphertext: Vec<u8>) -> bool {
        let decrypted = crypto::aes::cbc::decrypt(&self.key, &ciphertext);
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
    use crate::ex_16_cbc_bitflipping_attack::{solve, UserManager};
    use crypto::aes::random_key;

    #[test]
    fn test_auxillary() {
        let key = random_key();
        let user_manager = UserManager { key };
        let encrypted = user_manager.create_encrypted_user("hello".into());
        assert!(!user_manager.is_user_admin(encrypted));
        let encrypted = user_manager.create_encrypted_user(";admin=true".into());
        assert!(!user_manager.is_user_admin(encrypted));
    }

    #[test]
    fn test_solution() {
        let key = random_key();
        let manager = UserManager { key };
        assert!(solve(manager));
    }
}
