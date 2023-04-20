//! ### Break an MD4 keyed MAC using length extension
//!
//! Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once
//! against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend
//! Googling for an implementation of MD4.
//!
//! ### You're thinking, why did we bother with this?
//!
//! Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an
//! H(k, m) MAC with SHA1. Which meant that SHA1 code was floating all over the Internet.
//! MD4 code, not so much.
//!
//! Major difference with previous exercise: message_size_in_bits should be in little endian bytes.

use crypto::hash::md4::{md4_padding_needed, md4_state_len, Md4State};
use std::iter;

fn glue_padding(message: &[u8], guessed_key_len: usize) -> Vec<u8> {
    let mut forged_message = message.to_vec();
    let prefix_len = guessed_key_len + message.len();
    let prefix_padding = md4_padding_needed(prefix_len);
    const ONE: u8 = 0x80;
    forged_message.push(ONE);
    forged_message.extend(iter::repeat(0).take(prefix_padding));
    // message length in bits (always a multiple of the number of bits in a character).
    let message_size_in_bits = (prefix_len * 8).to_le_bytes();
    forged_message.extend(message_size_in_bits);
    return forged_message;
}

fn solve(
    message: &[u8],
    target: &[u8],
    original_message_digest: Vec<u8>,
    validate: impl Fn(&[u8], &[u8]) -> bool,
) -> Vec<u8> {
    let md4state = Md4State::from_message_digest(&original_message_digest);
    for guessed_key_len in 16..=16 {
        // original-message | glue_padding
        let mut forged_message = glue_padding(message, guessed_key_len);
        // original-message || glue-padding || new-message
        forged_message.extend(target);
        let payload_len = guessed_key_len + forged_message.len();
        let forged_message_digest = md4_state_len(md4state.clone(), target, payload_len).0;
        // validate SHA1(key || original-message || glue-padding || new-message)
        if validate(&forged_message, &forged_message_digest) {
            return forged_message_digest;
        }
    }
    panic!("No solution found");
}

#[cfg(test)]
mod test {
    use crate::ex_30_break_md4_keyed_mac_length_extension::*;
    use crypto::aes::random_key;
    use crypto::mac::md4_mac;
    #[test]
    fn test_break_md4_keyed_mac_length_extension() {
        const MESSAGE: &[u8] =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        const TARGET: &[u8] = b";admin=true";
        let key = random_key();
        let original_md = md4_mac(&key, MESSAGE);
        solve(
            MESSAGE,
            TARGET,
            original_md,
            |forged_message, forged_digest: &[u8]| -> bool {
                let expected_digest = md4_mac(&key, forged_message);
                return forged_digest == expected_digest;
            },
        );
    }
}
