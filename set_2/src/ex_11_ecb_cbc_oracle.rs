// https://cryptopals.com/sets/2/challenges/11
use crypto::Pkcs7;
///
/*
An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is,
a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly)
before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under
CBC the other half (just use random IVs each time for CBC).
Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time.
You should end up with a piece of code that, pointed at a block box
that might be encrypting ECB or CBC, tells you which one is happening.
*/
use rand::{random, Rng};
use std::collections::HashSet;
use std::ops::Range;

pub fn random_key() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    rng.gen()
}

/// Gen a random prefix and random suffix, Between 5 and 10 bytes:
fn get_rnd_padding() -> Vec<u8> {
    const RND_RANGE: Range<u8> = 5..10;
    let rnd_len = rand::thread_rng().gen_range(RND_RANGE);
    (0..rnd_len)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
}
#[derive(Debug, Clone)]
pub enum EncryptionMode {
    ECB,
    CBC,
}
pub fn encrypt_with_random_key(plaintext: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let key = random_key();
    let prefix = get_rnd_padding();
    let suffix = get_rnd_padding();
    println!("Prefix len:{}, suffix len: {}", prefix.len(), suffix.len());
    let plaintext_w_gibberish: Vec<u8> = prefix
        .into_iter()
        .chain(Vec::from(plaintext))
        .chain(suffix)
        .collect();
    if rand::random::<bool>() {
        println!("Encrypting using CBC...");
        let padded = Pkcs7::pad(&plaintext_w_gibberish, 16);
        let iv = random_key();
        (
            crypto::aes::cbc::encrypt_with_iv(&iv, &key, padded.as_slice()),
            EncryptionMode::CBC,
        )
    } else {
        println!("Encrypting using ECB...");
        let padded = Pkcs7::pad(&plaintext_w_gibberish, 16);
        (
            crypto::aes::ecb::encrypt(&key, padded.as_slice()),
            EncryptionMode::ECB,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::ex_11_ecb_cbc_oracle::{encrypt_with_random_key, EncryptionMode};
    use base64;

    #[test]
    fn test_oracle() {
        let input = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (ciphertext, mode) = encrypt_with_random_key(input);
        let encoded = base64::encode(ciphertext.clone());
        println!("Random encrypted: {} - {:?}", encoded, ciphertext.clone());
        match (mode, crypto::aes::is_ecb_encrypted(&ciphertext)) {
            a @ (EncryptionMode::ECB, false) | a @ (EncryptionMode::CBC, true) => {
                panic!("The mode was: {:?}, is ecb encrypted: {}", a.0, a.1);
            }
            _ => (),
        }
    }
}
