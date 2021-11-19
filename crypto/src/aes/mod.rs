//! AES implementation
//! Currently supports only AES128.
//! You can either use it directly via encrypt / decrypt, or use
//! the exposed modes (e.g. ECB).
//! Do you want to implement AES yourself?!
//! Internet is full of trash implementations and articles. You only need three resources:
//! 1. http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
//! 2. https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
//! 3. https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf
//! https://www.cryptool.org/en/cto/aes-step-by-step

use modules::{add_round_key, key_expansion, sub_bytes, sub_bytes_inverse};
use modules::{mix_columns, mix_columns_inverse};
use modules::{shift_rows, shift_rows_inverse};
use rand::Rng;
use std::collections::HashSet;

pub mod cbc;
pub mod ecb;
mod modules;

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

pub fn encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let expaneded_key = key_expansion(key);
    let mut state = add_round_key(&block, &expaneded_key[0]);
    for round in 1..=ROUNDS_128 {
        state = sub_bytes(&state);
        /*println!(
            "sbox: {:?}",
            state
                .into_iter()
                .map(|v| format!("{:02x}", v))
                .collect::<Vec<String>>()
        );*/
        state = shift_rows(&state);
        /*println!(
            "shift rows: {:?}",
            state
                .into_iter()
                .map(|v| format!("{:02x}", v))
                .collect::<Vec<String>>()
        );*/
        state = mix_columns(&state);
        /*println!(
            "mix columns: {:?}",
            state
                .into_iter()
                .map(|v| format!("{:02x}", v))
                .collect::<Vec<String>>()
        );*/
        state = add_round_key(&state, &expaneded_key[round]);
        /*println!(
            "add round key: {:?}",
            state
                .into_iter()
                .map(|v| format!("{:02x}", v))
                .collect::<Vec<String>>()
        );*/
    }
    state = sub_bytes(&state);
    state = shift_rows(&state);
    state = add_round_key(&state, &expaneded_key[10]);
    state
}

/// Checks if there are any repeating blocks to assess if this ciphertext is encrypted with ecb.
pub fn is_ecb_encrypted(buf: &[u8]) -> bool {
    let unique_blocks = buf.chunks(16).into_iter().collect::<HashSet<&[u8]>>().len();
    let total_blocks = buf.len() / 16;
    let duplicated_blocks = total_blocks as i64 - unique_blocks as i64;
    println!("Duplicated blocks: {}", duplicated_blocks);
    duplicated_blocks > 0
}
pub fn random_key() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    rng.gen()
}

#[cfg(test)]
mod tests {
    use crate::aes::{decrypt, encrypt};
    #[test]
    fn test_encrypt() {
        let g_key = [
            0xc4, 0x99, 0x3c, 0x41, 0x31, 0x3c, 0xf, 0x49, 0xc7, 0xdc, 0x3f, 0x50, 0xdc, 0x69,
            0xe5, 0x9e,
        ];
        //0x54, 0x77, 0x6f, 0x20, 0x4f, 0x6e, 0x65, 0x20, 0x4e, 0x69, 0x6e, 0x65, 0x20, 0x54,
        //0x77, 0x6f,
        let plaintext = b"Two One Nine Two";
        let received = encrypt(&plaintext, &g_key);
        let expected = [
            0xc2, 0x2c, 0xd8, 0x85, 0x58, 0x97, 0x9f, 0xc7, 0x65, 0xcf, 0xf7, 0xfe, 0x54, 0x1f,
            0x2a, 0x19,
        ];
        assert_eq!(expected, received);

        let b_key = [
            0x88, 0x65, 0x20, 0xa9, 0xb8, 0x86, 0xc6, 0xfe, 0x41, 0x18, 0x40, 0x50, 0x42, 0x2f,
            0x7c, 0x1a,
        ];
        let received = encrypt(&plaintext, &b_key);
        let expected = [
            0x3e, 0x8e, 0xab, 0xde, 0x11, 0x50, 0xfe, 0x59, 0x63, 0xf7, 0xb9, 0x05, 0x56, 0x06,
            0x7c, 0x37,
        ];
        assert_eq!(expected, received);
    }
    #[test]
    fn test_encrypt_simple() {
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
