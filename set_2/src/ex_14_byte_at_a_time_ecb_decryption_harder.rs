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

/// Returns.
/// Random prefix size.
/// amount of bytes to finish the block
///
pub fn find_random_prefix_size(oracle: impl Fn(Vec<u8>) -> Vec<u8>) -> RandomPrefix {
    // 1. we find the size of the random prefix + padding to fill up the whole block.
    let mut last_vec: Vec<u8> = oracle(vec![]);
    let mut random_prefix_size = 0;
    // found prefix size:
    for i in 1..=128 {
        let plaintext = std::iter::repeat(b'A').take(i).collect();
        let ciphertext = oracle(plaintext);
        let temp_block_size = longest_substring(&ciphertext, &last_vec);
        if temp_block_size == 0 {
            random_prefix_size = 1;
        }
        if random_prefix_size == 0 {
            random_prefix_size = temp_block_size;
        } else if temp_block_size > random_prefix_size {
            let plaintext = std::iter::repeat(b'A')
                .take(i - 1)
                .chain(std::iter::repeat(b'B').take(1))
                .collect();
            let ciphertext_replaced = oracle(plaintext);
            let new_block_size = longest_substring(&ciphertext, &ciphertext_replaced);
            if new_block_size == temp_block_size {
                //println!("temp_block size: {}, i:{}, i", temp_block_size, i);
                return RandomPrefix {
                    total_prefix_len: temp_block_size + 1 - i,
                    padding_len: i - 1,
                };
            }
            random_prefix_size = temp_block_size;
        }
        last_vec = ciphertext;
    }
    panic!("Random prefix len not found :(");
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

fn build_oracle(key: Vec<u8>, prefix: Vec<u8>) -> impl Fn(Vec<u8>) -> Vec<u8> + Clone {
    /**
    Takes a random key as input and returns
    `AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)`
    Looking good!
     **/
    let oracle = move |plaintext: Vec<u8>| -> Vec<u8> {
        let decoded = base64::decode(APPENDED_B64).unwrap();
        let plaintext: Vec<u8> = prefix
            .clone()
            .into_iter()
            .chain(plaintext.into_iter().chain(decoded.into_iter()))
            .collect();
        const KEY_SIZE: usize = 16;
        let mut k = [0; KEY_SIZE];
        k.copy_from_slice(&key.as_slice()[..KEY_SIZE]);
        crypto::aes::ecb::pad_and_encrypt(&k, plaintext)
    };
    return oracle;
}

#[cfg(test)]
mod test {
    use crate::ex_14_byte_at_a_time_ecb_decryption_harder::{
        build_oracle, find_random_prefix_size, solve, APPENDED_B64,
    };
    use crypto::aes::random_key;

    fn random_bytes() -> Vec<u8> {
        let n: u32 = rand::random::<u32>() % 1000 + 16;
        let n = 1;
        println!("random n : {}", n);
        random_bytes_n(n)
    }
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
            let oracle = build_oracle(random_key().to_vec(), random_bytes_n(n));
            let padd = 16 - n as usize % 16;
            assert_eq!(
                crypto::aes::ecb::cryptanalysis::find_block_size_random_prefix(
                    oracle,
                    n as usize + padd
                )
                .unwrap(),
                16
            );
        }
    }

    #[test]
    fn test_random_prefix_size() {
        for _ in 0..10 {
            let n: u32 = rand::random::<u32>() % 1000;
            let key: &[u8; 16] = &random_key();
            let random_prefix = random_bytes_n(n);
            let oracle = build_oracle(key.to_vec(), random_prefix);
            assert_eq!(n as usize, find_random_prefix_size(oracle).total_prefix_len);
        }
    }

    fn test_single(n: usize) {
        let key: &[u8; 16] = &random_key();
        let random_prefix = random_bytes_n(1);
        let oracle = build_oracle(key.to_vec(), random_prefix);
        let expected = String::from_utf8(base64::decode(APPENDED_B64).unwrap()).unwrap();
        assert_eq!(expected, solve(oracle));
    }
    #[test]
    fn test_byte_a_time() {
        test_single(0);
        test_single(1);
        test_single(16);
        let n: u32 = rand::random::<u32>() % 1000;
        test_single(n as usize);
    }
}
