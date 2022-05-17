//! Functions to help cracks ciphertexts based on ecb

use crate::utils::longest_substring;

/// Find the block size by searching for repeating blocks
pub fn find_block_size(oracle: impl Fn(Vec<u8>) -> Vec<u8>) -> Option<usize> {
    find_block_size_random_prefix(oracle, 0)
}

/// Find block size for oracles that have a random prefix.  
/// random_prefix_rounded_to_block_len: random prefix size + amount of padding necessary to complete the block.
pub fn find_block_size_random_prefix(
    oracle: impl Fn(Vec<u8>) -> Vec<u8>,
    random_prefix_rounded_to_block_len: usize,
) -> Option<usize> {
    let mut last_vec: Vec<u8> = vec![];
    for i in 1..=128 {
        let plaintext = std::iter::repeat(b'A').take(i).collect();

        let ciphertext = oracle(plaintext);
        let block_size = longest_substring(&ciphertext, &last_vec);
        if block_size > random_prefix_rounded_to_block_len
            && block_size - random_prefix_rounded_to_block_len > 8
        {
            let ret = block_size - random_prefix_rounded_to_block_len;
            assert_eq!(
                    ret, 16,
                    "Something went wrong when finding the block size. Block size: {}, Random prefix: {}",
                    block_size,random_prefix_rounded_to_block_len

                );
            return Some(ret);
        }
        last_vec = ciphertext;
    }
    None
}
/// By knowing the block size and having the oracle function we can break the ciphertext
/// one byte a time. Assume a block of len n.
/// We first create a window of length n-1 and we run it through the oracle.
/// This block now contains: N-1 b`A` and a target character we want to recover.
/// * Block size = 3
/// * target string = BE
/// * first window w1 = [AA]
/// * passing through oracle, the resulting block will contain: [AA] + B = [AAB].
/// Now we iterate through all the possible bytes. We encrypt through the oracle and compare the blocks.
/// [AA] + A = [AAA], [AA] + B = [AAB],
/// When there is a match - boom, we have our byte.
pub fn crack_ecb_one_byte_at_time(
    block_size: usize,
    oracle: impl Fn(Vec<u8>) -> Vec<u8>,
) -> Vec<u8> {
    crack_ecb_one_byte_at_time_random_prefix(block_size, oracle, 0)
}

pub fn crack_ecb_one_byte_at_time_random_prefix(
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
                //print!("{}", String::from_utf8_lossy(&[i]));
                //std::io::stdout().flush().unwrap();
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
