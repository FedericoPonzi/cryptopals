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

use rand::random;
use std::io::Write;

const APPENDED_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
fn longest_substring(first: &[u8], second: &[u8]) -> usize {
    first
        .iter()
        .zip(second)
        .take_while(|(cur, prev)| *cur == *prev)
        .count()
}

/// random_prefix_padding is the padding till the end of the block for the random prefix string.
fn decrypt_ecb(
    block_size: usize,
    oracle: impl Fn(Vec<u8>) -> Vec<u8>,
    random_prefix_len: usize,
) -> Vec<u8> {
    let random_prefix_padding = if random_prefix_len % block_size > 0 {
        let last_block_len = random_prefix_len % block_size;
        block_size - last_block_len
    } else {
        0
    };
    let random_prefix_total_size = random_prefix_padding + random_prefix_len;

    let take = |i| {
        std::iter::repeat(b'A')
            .take(random_prefix_padding + i)
            .collect()
    };
    let windows: Vec<Vec<u8>> = (0..block_size).into_iter().map(take).rev().collect();
    println!("Random prefix padding: {}", random_prefix_padding);
    let mut current_plaintext = vec![];
    for w in windows.into_iter().cycle() {
        let target_ciphertext = &oracle(w.clone())[random_prefix_total_size..];

        let mut extended_w = w.clone();
        extended_w.extend_from_slice(&current_plaintext);
        for i in 0..=u8::MAX {
            let mut temp_w = extended_w.clone();
            temp_w.push(i);
            let w_len = temp_w.len() - (random_prefix_padding);
            let received = &oracle(temp_w)[random_prefix_total_size..];
            let longest = longest_substring(target_ciphertext, received);
            if longest >= w_len {
                print!("{}", String::from_utf8_lossy(&[i]));
                std::io::stdout().flush().unwrap();
                current_plaintext.push(i);
                break;
            }
            if i == u8::MAX - 1 {
                panic!(
                    "NOT FOUND: w_len:{}, longest: {}, w: {:?}, \ncurrent_pt: {:?}, \nreceievd ={:?}, \ntarget: {:?}",
                    w_len,
                    longest,
                    extended_w,
                    String::from_utf8_lossy(&current_plaintext),
                    received,
                    target_ciphertext
                );
            }
        }
        //TODO.
        if current_plaintext.len() == 138 {
            break;
        }
    }
    return current_plaintext;
}

/// Returns.
/// Random prefix size.
/// amount of bytes to finish the block
pub fn find_random_prefix_size(oracle: impl Fn(Vec<u8>) -> Vec<u8>) -> (usize, usize) {
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
                return (temp_block_size + 1 - i, i - 1);
            }
            random_prefix_size = temp_block_size;
        }
        last_vec = ciphertext;
    }
    panic!("Random prefix len not found :(");
}

/// random_prefix_rounded_to_block_len: random prefix size + padding to complete the block.
pub fn find_block_size(
    oracle: impl Fn(Vec<u8>) -> Vec<u8> + Clone,
    random_prefix_rounded_to_block_len: usize,
) -> usize {
    let mut last_vec: Vec<u8> = vec![];

    for i in 1..=128 {
        let plaintext = std::iter::repeat(b'A').take(i).collect();

        let ciphertext = oracle(plaintext);
        let block_size = longest_substring(&ciphertext, &last_vec);
        if block_size > random_prefix_rounded_to_block_len {
            return block_size - random_prefix_rounded_to_block_len;
        }
        last_vec = ciphertext;
    }
    panic!("Block size not found :(");
}

fn solve(oracle: impl Fn(Vec<u8>) -> Vec<u8> + Clone) -> String {
    let plaintext = std::iter::repeat(b'A').take(2048).collect();
    let ciphertext = oracle(plaintext);
    if !crypto::aes::is_ecb_encrypted(&ciphertext) {
        println!("Not AES?!");
        return "".to_string();
    }
    println!("It is ECB :)");
    let (random_prefix_size, start) = find_random_prefix_size(oracle.clone());
    let rounded_prefix_block_size = random_prefix_size + start;

    let block_len = find_block_size(oracle.clone(), rounded_prefix_block_size);
    assert_eq!(block_len, 16);
    println!(
        "Block Size: {}, random_prefix_len: {}, prefix pad: {}",
        block_len,
        random_prefix_size,
        random_prefix_size % block_len
    );
    String::from_utf8_lossy(&decrypt_ecb(block_len, oracle, random_prefix_size)).to_string()
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
        build_oracle, find_block_size, find_random_prefix_size, solve, APPENDED_B64,
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
    fn test_random_prefix_size() {
        for _ in 0..10 {
            let n: u32 = rand::random::<u32>() % 1000;
            let key: &[u8; 16] = &random_key();
            let random_prefix = random_bytes_n(n);
            let oracle = build_oracle(key.to_vec(), random_prefix);
            assert_eq!(n as usize, find_random_prefix_size(oracle).0);
        }
    }

    #[test]
    fn test_find_block_size() {
        let key: &[u8; 16] = &random_key();
        let random_prefix = random_bytes();
        let oracle = build_oracle(key.to_vec(), random_prefix);
        assert_eq!(find_block_size(oracle, 0), 16);
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
        //test_single(0);
        //test_single(1);
        //test_single(16);
        let n: u32 = rand::random::<u32>() % 1000;
        test_single(n as usize);
    }
}
