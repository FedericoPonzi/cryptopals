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
        Some(self.rng.rand() as u32 as u8)
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

#[cfg(test)]
mod test {
    use crate::ex_24_create_the_mt19937_stream_cipher_and_break_it::{decrypt, encrypt};

    #[test]
    fn solve() {
        assert_eq!(b"ciao".to_vec(), decrypt(&encrypt(b"ciao", 0xff), 0xff));
    }
}
