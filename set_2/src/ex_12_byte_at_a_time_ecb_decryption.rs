use crypto::utils::longest_substring;
use crypto::Pkcs7;

/**
https://cryptopals.com/sets/2/challenges/12
### Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a _consistent_ but _unknown_ key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

### Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. _Do not base64 decode the string by hand; make your code do it_. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1.  Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
2.  Detect that the function is using ECB. You already know, but do this step anyways.
3.  Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
4.  Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
5.  Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
6.  Repeat for the next byte.

### Congratulations.

This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can _decrypt the contents of those ciphertexts_, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
**/

const APPENDED_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn decrypt_ecb(block_size: usize, oracle: impl Fn(Vec<u8>) -> Vec<u8> + Clone) -> Vec<u8> {
    let windows: Vec<Vec<u8>> = (0..block_size)
        .into_iter()
        .map(|i| std::iter::repeat(b'A').take(i).collect())
        .rev()
        .collect();
    let mut current_plaintext = vec![];
    for w in windows.into_iter().cycle() {
        let mut extended_w = w.clone();
        extended_w.extend_from_slice(&current_plaintext);
        let target_ciphertext = oracle(w.clone());
        for i in 0..=u8::MAX {
            let mut w = extended_w.clone();
            w.push(i);
            let w_len = w.len();
            let received = oracle(w);
            let longest = longest_substring(&target_ciphertext, &received);
            if longest >= w_len {
                current_plaintext.push(i);
                break;
            }
            if i == u8::MAX - 1 {
                println!(
                    "w_len:{}, longest: {}, w: {:?}, \ncurrent_pt: {:?}, \nreceievd ={:?}, \ntarget: {:?}",
                    w_len,
                    longest_substring(&target_ciphertext, &received)
                   , extended_w,
                    String::from_utf8_lossy(&current_plaintext),
                    received,
                    target_ciphertext,
                );
                // not found!?
                return current_plaintext;
            }
        }
        //TODO.
        if current_plaintext.len() == 138 {
            break;
        }
    }
    return current_plaintext;
}

fn solve(oracle: impl Fn(Vec<u8>) -> Vec<u8> + Clone) -> String {
    let plaintext = std::iter::repeat(b'A').take(2048).collect();
    let ciphertext = oracle(plaintext);
    if !crypto::aes::is_ecb_encrypted(&ciphertext) {
        panic!("Not AES?!");
    }
    println!("It is ECB :)");
    let block_len = crypto::aes::ecb::cryptanalysis::find_block_size(oracle.clone())
        .expect("Block size not found!?");
    println!("Block len: {}", block_len);
    String::from_utf8_lossy(
        &crypto::aes::ecb::cryptanalysis::crack_ecb_one_byte_at_time(block_len, oracle),
    )
    .to_string()
}

/**
Takes a random key as input and returns `AES-128-ECB(your-string || unknown-string, random-key)`
**/
fn build_oracle(key: Vec<u8>) -> impl Fn(Vec<u8>) -> Vec<u8> + Clone {
    return move |plaintext: Vec<u8>| -> Vec<u8> {
        let decoded = base64::decode(APPENDED_B64).unwrap();
        let plaintext: Vec<u8> = plaintext.into_iter().chain(decoded.into_iter()).collect();
        let padded = Pkcs7::pad(&plaintext, 16);
        const KEY_SIZE: usize = 16;
        let mut k = [0; KEY_SIZE];
        k.copy_from_slice(&key.as_slice()[..KEY_SIZE]);
        crypto::aes::ecb::encrypt(&k, padded.as_slice())
    };
}

#[cfg(test)]
mod test {
    use crate::ex_12_byte_at_a_time_ecb_decryption::{build_oracle, solve, APPENDED_B64};
    use crypto::aes::random_key;

    #[test]
    // This test is quite slow.
    fn test_byte_a_time() {
        let expected = String::from_utf8(base64::decode(APPENDED_B64).unwrap()).unwrap();
        let key = random_key();
        let oracle = build_oracle(key.to_vec());
        assert_eq!(
            expected,
            solve(oracle),
            "Something went wrong, key: {:?}",
            key
        );
    }
}
