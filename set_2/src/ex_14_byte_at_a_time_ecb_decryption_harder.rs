/*
https://cryptopals.com/sets/2/challenges/14

### Byte-at-a-time ECB decryption (Harder)
Take your oracle function [from #12.](https://cryptopals.com/sets/2/challenges/12) Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

### Stop and think for a second.

What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
 */

use crypto::aes::ecb::cryptanalysis::find_block_size_random_prefix;
use crypto::utils::longest_substring;

const APPENDED_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

#[derive(Debug, Clone)]
pub struct RandomPrefix {
    /// Total random prefix len
    total_prefix_len: usize,
    /// Amount of bytes necessary to finish the block.
    padding_len: usize,
}
fn round(num: usize) -> usize {
    let factor = 16f64;
    if num == 0 {
        return 0;
    }
    let num = num as f64;
    let res = factor * (num / factor).round();
    res as usize
}
/// Returns.
/// Random prefix size.
/// amount of bytes to finish the block
///
pub fn find_random_prefix_size(oracle: impl Fn(Vec<u8>) -> Vec<u8>) -> RandomPrefix {
    let plaintext = std::iter::repeat(b'A')
        .take(48)
        .chain(std::iter::repeat(b'D').take(10))
        .collect();
    let mut last_ciphertext = oracle(plaintext);
    let pb: Vec<u8> = std::iter::repeat(b'A')
        .take(48)
        .chain(std::iter::repeat(b'B').take(1))
        .collect();
    let mut last_longest = round(longest_substring(&last_ciphertext, &oracle(pb)));
    for i in (0..49).rev() {
        let ciphertext = oracle(std::iter::repeat(b'A').take(i).collect());
        let longest = round(longest_substring(&last_ciphertext, &ciphertext));
        if longest < last_longest {
            let previous_index = i + 1;
            return RandomPrefix {
                total_prefix_len: last_longest - (previous_index + last_longest % 16),
                padding_len: (previous_index) % 16,
            };
        }
        last_longest = longest;
        last_ciphertext = ciphertext;
    }
    panic!("Random prefix not found! :( ");
}

fn solve(oracle: impl Fn(Vec<u8>) -> Vec<u8> + Clone) -> String {
    let plaintext = std::iter::repeat(b'A').take(2048).collect();
    let ciphertext = oracle(plaintext);
    if !crypto::aes::is_ecb_encrypted(&ciphertext) {
        println!("Not AES?!");
        return "".to_string();
    }
    println!("It is ECB :)");
    let random_prefix = find_random_prefix_size(oracle.clone());
    let rounded_prefix_block_size = random_prefix.total_prefix_len + random_prefix.padding_len;

    let block_len =
        find_block_size_random_prefix(oracle.clone(), rounded_prefix_block_size).unwrap();
    assert_eq!(block_len, 16);
    String::from_utf8_lossy(
        &crypto::aes::ecb::cryptanalysis::crack_ecb_one_byte_at_time_random_prefix(
            block_len,
            oracle,
            random_prefix.total_prefix_len,
        ),
    )
    .to_string()
}

fn build_oracle(key: [u8; 16], prefix: Vec<u8>) -> impl Fn(Vec<u8>) -> Vec<u8> + Clone {
    //Takes a random key as input and returns
    //`AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    move |plaintext: Vec<u8>| -> Vec<u8> {
        let decoded = base64::decode(APPENDED_B64).unwrap();
        let plaintext: Vec<u8> = prefix
            .clone()
            .into_iter()
            .chain(plaintext.into_iter().chain(decoded.into_iter()))
            .collect();
        const KEY_SIZE: usize = 16;
        crypto::aes::ecb::pad_and_encrypt(&key, plaintext)
    }
}

#[cfg(test)]
mod test {
    use crate::ex_14_byte_at_a_time_ecb_decryption_harder::{
        build_oracle, find_random_prefix_size, solve, APPENDED_B64,
    };
    use crypto::aes::random_key;

    fn random_bytes_n(take: u32) -> Vec<u8> {
        use rand::Rng;
        let range = rand::distributions::Uniform::from(0..u8::MAX);
        rand::thread_rng()
            .sample_iter(range)
            .take(take as usize)
            .collect()
    }

    #[test]
    fn test_find_block_size() {
        for _ in 0..10 {
            let n: u32 = rand::random::<u32>() % 1000;
            let key = random_key();
            let random_bytes = random_bytes_n(n);
            let oracle = build_oracle(key, random_bytes.clone());
            let padd = 16 - n as usize % 16;
            assert_eq!(
                crypto::aes::ecb::cryptanalysis::find_block_size_random_prefix(
                    oracle,
                    n as usize + padd
                )
                .unwrap(),
                16,
                "Key: {:?}\nRandom bytes:{:?}\nn:{:?}",
                key,
                random_bytes,
                n,
            );
        }
    }

    #[test]
    fn test_random_prefix_size() {
        for _ in 0..100 {
            let n: u32 = rand::random::<u32>() % 10;
            let key: [u8; 16] = random_key();
            let random_prefix = random_bytes_n(n);
            let oracle = build_oracle(key, random_prefix.clone());

            let received = find_random_prefix_size(oracle);
            assert_eq!(
                random_prefix.len(),
                received.total_prefix_len,
                " Padding len: {}",
                received.padding_len
            );
        }
    }

    fn test_single(n: u32) {
        let key: [u8; 16] = random_key();
        let random_prefix = random_bytes_n(n);
        let oracle = build_oracle(key, random_prefix);
        let expected = String::from_utf8(base64::decode(APPENDED_B64).unwrap()).unwrap();
        assert_eq!(expected, solve(oracle));
    }
    #[test]
    fn test_byte_a_time() {
        test_single(0);
        test_single(1);
        test_single(16);
        let n: u32 = rand::random::<u32>() % 1000;
        test_single(n);
    }
}
