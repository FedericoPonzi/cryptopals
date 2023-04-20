//! https://cryptopals.com/sets/4/challenges/29
//! ### Break a SHA-1 keyed MAC using length extension
//!
//! Secret-prefix SHA-1 MACs are trivially breakable.
//!
//! The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".
//!
//! Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.
//!
//! To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:
//!
//! SHA1(key || original-message || glue-padding || new-message)
//!
//! (where the final padding on the whole constructed message is implied)
//!
//! Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.
//!
//! This sounds more complicated than it is in practice.
//!
//! To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.
//!
//! Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).
//!
//! Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.
//!
//! Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:
//!
//! "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
//!
//! Forge a variant of this message that ends with ";admin=true".
//!
//! ### This is a very useful attack.
//!
//! For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
//!

use crypto::hash::sha1::{sha1_padding_needed, sha1_state_len, Sha1State};
use std::iter;

fn glue_padding(message: &[u8], guessed_key_len: usize) -> Vec<u8> {
    let mut forged_message = message.to_vec();
    let prefix_len = guessed_key_len + message.len();
    let prefix_padding = sha1_padding_needed(prefix_len);
    const ONE: u8 = 0x80;
    forged_message.push(ONE);
    forged_message.extend(iter::repeat(0).take(prefix_padding));
    // message length in bits (always a multiple of the number of bits in a character).
    let message_size_in_bits = (prefix_len * 8).to_be_bytes();
    forged_message.extend(message_size_in_bits);
    return forged_message;
}

fn solve(
    message: &[u8],
    target: &[u8],
    original_message_digest: Vec<u8>,
    validate: impl Fn(&[u8], &[u8]) -> bool,
) -> Vec<u8> {
    let sha1state = Sha1State::from_message_digset(&original_message_digest);
    for guessed_key_len in 16..=16 {
        // original-message | glue_padding
        let mut forged_message = glue_padding(message, guessed_key_len);
        // original-message || glue-padding || new-message
        forged_message.extend(target);
        let payload_len = guessed_key_len + forged_message.len();
        let forged_message_digest = sha1_state_len(sha1state.clone(), target, payload_len).0;
        // validate SHA1(key || original-message || glue-padding || new-message)
        if validate(&forged_message, &forged_message_digest) {
            return forged_message_digest;
        }
    }
    panic!("No solution found");
}

#[cfg(test)]
mod test {
    use crate::ex_29_break_sha1_keyed_mac_length_extension::solve;
    use crypto::aes::random_key;
    use crypto::mac::sha1_mac;

    #[test]
    fn test_solve() {
        const MESSAGE: &[u8] =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        const TARGET: &[u8] = b";admin=true";
        let key = random_key();
        let original_md = sha1_mac(&key, MESSAGE);
        solve(
            MESSAGE,
            TARGET,
            original_md,
            |forged_message, forged_digest: &[u8]| -> bool {
                let expected_digest = sha1_mac(&key, forged_message);
                return forged_digest == expected_digest;
            },
        );
    }
}
