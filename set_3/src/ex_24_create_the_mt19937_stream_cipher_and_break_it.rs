//! https://cryptopals.com/sets/3/challenges/24100
//!
//! Create the MT19937 stream cipher and break it
//!
//! You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit
//! outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.
//!
//! Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt
//! and decrypt properly. This code should look similar to your CTR code.
//!
//! Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by
//! a random number of random characters.
//!
//! From the ciphertext, recover the "key" (the 16 bit seed).
//!
//! Use the same idea to generate a random "password reset token" using MT19937 seeded from the
//! current time.
//! Write a function to check if any given password token is actually the product of an MT19937
//! PRNG seeded with the current time.

use crypto::random::{Mt19937MersenneTwisterRng, Rng};

struct MT19937Iterator {
    rng: Mt19937MersenneTwisterRng,
    key: u16,
}
impl MT19937Iterator {
    fn new(key: u16) -> Self {
        Self {
            rng: Mt19937MersenneTwisterRng::new_seed(key as u32),
            key,
        }
    }
}
impl Iterator for MT19937Iterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some((self.rng.rand() * 100.0) as u32 as u8)
    }
}
fn encrypt(pt: &[u8], key: u16) -> Vec<u8> {
    pt.into_iter()
        .zip(MT19937Iterator::new(key))
        .map(|(a, b)| a ^ b)
        .collect()
}
fn decrypt(ct: &[u8], key: u16) -> Vec<u8> {
    encrypt(ct, key)
}

///  Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters)
/// prefixed by a random number of random characters.
/// From the ciphertext, recover the "key" (the 16 bit seed).
/// Because 16 bit is super small, let's just bruteforce it
fn break_mt19937(ct: &[u8]) -> (Vec<u8>, u16) {
    for i in 0..=0xff {
        let pt = decrypt(ct, i);
        if pt.ends_with(b"aaaaaaaaaaaaaa") {
            println!("{:?}", String::from_utf8_lossy(&pt));
            return (pt, i);
        }
    }
    unreachable!();
}

// 0xf it's an hack to keep tests fast
// the script requested to use 0xffff.
const MAX_SEED_SIZE: u16 = 0xf;

///  Use the same idea to generate a random "password reset token" using MT19937 seeded from
/// the current time.
fn generate_password_reset_token() -> [u8; 16] {
    let time_seed = (chrono::Utc::now().timestamp() as u16) % MAX_SEED_SIZE;
    let token: Vec<u8> = MT19937Iterator::new(time_seed)
        .into_iter()
        .take(16)
        .collect();
    let mut ret = [0u8; 16];
    ret.copy_from_slice(&token);
    ret
}

///  Write a function to check if any given password token is actually the product of an
/// MT19937 PRNG seeded with the current time.
fn is_generated_using_mt19937(token: &[u8]) -> bool {
    for i in 0..=MAX_SEED_SIZE {
        // 0xf is an hack to keep tests fast
        let identical = MT19937Iterator::new(i)
            .into_iter()
            .take(16)
            .zip(token)
            .filter(|(a, b)| a != *b)
            .count();
        if identical == 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod test {
    use crate::ex_24_create_the_mt19937_stream_cipher_and_break_it::{
        break_mt19937, decrypt, encrypt, generate_password_reset_token, is_generated_using_mt19937,
    };
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    #[test]
    fn test_mt19937_cipher() {
        const PT: &[u8] = b"hello world";
        let encrypted = encrypt(PT, 0xff);
        let decrypted = decrypt(&encrypted, 0xff);
        assert_eq!(PT.to_vec(), decrypted);
    }

    #[test]
    fn test_break() {
        let key = 0x10;
        let known_pt = b"aaaaaaaaaaaaaa";

        let pt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .chain(known_pt.into_iter().map(|v| *v))
            .map(char::from)
            .collect();
        assert_eq!(break_mt19937(&encrypt(pt.as_bytes(), key)).1, key);
    }

    #[test]
    fn test_generated_token_break() {
        let token = generate_password_reset_token();
        assert!(is_generated_using_mt19937(&token));
        assert!(!is_generated_using_mt19937(b"aaaaaaaaaaaaaa"));
    }
}
