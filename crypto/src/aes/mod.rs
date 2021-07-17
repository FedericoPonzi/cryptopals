//! AES implementation
//! Currently supports only AES128.
//! You can either use it directly via encrypt / decrypt, or use
//! the exposed modes (e.g. ECB).
//! Do you want to implement AES yourself?!
//! Internet is full of trash implementations and articles. You only need three resources:
//! 1. http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
//! 2. https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
//! 3. https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf

use modules::{add_round_key, key_expansion, sub_bytes, sub_bytes_inverse};
use modules::{mix_columns, mix_columns_inverse};
use modules::{shift_rows, shift_rows_inverse};

mod cbc;
mod ecb;
mod modules;

pub use cbc::cbc;
pub use cbc::cbc_with_iv;
pub use ecb::ecb;

const ROUNDS_128: usize = 9;

pub fn decrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let expaneded_key = key_expansion(key);
    let mut state = add_round_key(block, &expaneded_key[10]);
    state = shift_rows_inverse(&state);
    state = sub_bytes_inverse(&state);
    for round in (1..=ROUNDS_128).rev() {
        state = add_round_key(&state, &expaneded_key[round]);
        state = mix_columns_inverse(&state);
        state = shift_rows_inverse(&state);
        state = sub_bytes_inverse(&state);
    }
    state = add_round_key(&state, &expaneded_key[0]);
    state
}

fn printhex(inp: &[u8]) -> String {
    inp.into_iter().map(|b| format!("{:#01x}, ", b)).collect()
}

pub fn encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let expaneded_key = key_expansion(key);
    let mut state = add_round_key(&block, &expaneded_key[0]);
    for round in 1..=ROUNDS_128 {
        state = sub_bytes(&state);
        state = shift_rows(&state);
        state = mix_columns(&state);
        state = add_round_key(&state, &expaneded_key[round]);
    }
    state = sub_bytes(&state);
    state = shift_rows(&state);
    state = add_round_key(&state, &expaneded_key[10]);
    state
}

#[cfg(test)]
mod tests {
    use crate::aes::{decrypt, encrypt};

    #[test]
    fn test_encrypt() {
        let key = b"Thats my Kung Fu";
        let plaintext = b"Two One Nine Two";
        let received = encrypt(&plaintext, &key);
        let expected = [
            0x29, 0xC3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02,
            0xD7, 0x3A,
        ];
        assert_eq!(expected, received);
    }

    #[test]
    fn test_decrypt() {
        let key = b"Thats my Kung Fu";
        let crypto = [
            0x29, 0xC3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02,
            0xD7, 0x3A,
        ];
        let received = decrypt(&crypto, key);
        let expected = b"Two One Nine Two";
        println!("Received: {}", String::from_utf8_lossy(&received));
        assert_eq!(expected, &received);
    }
}
