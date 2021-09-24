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
fn longest_substring(first: &[u8], second: &[u8]) -> usize {
    first
        .clone()
        .into_iter()
        .zip(second)
        .take_while(|(cur, prev)| *cur == *prev)
        .count()
}
fn find_block_size(key: &[u8; 16]) -> Option<usize> {
    let mut last_vec: Vec<u8> = vec![];
    for i in 1..=128 {
        let plaintext = std::iter::repeat(b'A').take(i).collect();
        let ciphertext = oracle(plaintext, key);
        let block_size = ciphertext
            .clone()
            .into_iter()
            .zip(last_vec)
            .take_while(|(cur, prev)| *cur == *prev)
            .count();
        if block_size > 8 {
            return Some(block_size);
        }
        last_vec = ciphertext;
    }
    None
}
fn decrypt_ecb(block_size: usize, key: &[u8; 16]) -> Vec<u8> {
    let windows: Vec<Vec<u8>> = (0..block_size)
        .into_iter()
        .map(|i| std::iter::repeat(b'A').take(i).collect())
        .rev()
        .collect();
    let mut current_plaintext = vec![];
    for w in windows.into_iter().cycle() {
        let mut extended_w = w.clone();
        extended_w.extend_from_slice(&current_plaintext);
        let target_ciphertext = oracle(w.clone(), key);
        for i in 0..u8::MAX {
            let mut w = extended_w.clone();
            w.push(i);
            let w_len = w.len();
            let received = oracle(w.clone(), key);
            let longest = longest_substring(&target_ciphertext, &received);
            if longest >= w_len {
                current_plaintext.push(i);
                break;
            }
            if i == u8::MAX - 1 {
                println!(
                    "w_len:{}, longest: {}, w: {:?}, \ncurrent_pt: {:?}, \nreceievd ={:?}, \ntarget: {:?}, \ntarget: {:?}, \nrecevd: {:?}, lens = {}, {}",
                    w_len,
                    longest_substring(&target_ciphertext, &received)
                   , extended_w,
                    String::from_utf8_lossy(&current_plaintext),
                    received,
                    target_ciphertext,
                    String::from_utf8_lossy(&crypto::aes::ecb::decrypt(key, &target_ciphertext)),
                    String::from_utf8_lossy(&crypto::aes::ecb::decrypt(key, &received)),
                    String::from_utf8_lossy(&crypto::aes::ecb::decrypt(key, &target_ciphertext)).len(),
                    String::from_utf8_lossy(&crypto::aes::ecb::decrypt(key, &received)).len(),
                );
                panic!("Not found!?");
            }
        }
        //TODO.
        if current_plaintext.len() == 138 {
            break;
        }
    }
    return current_plaintext;
}

fn solve(key: &[u8; 16]) -> String {
    let plaintext = std::iter::repeat(b'A').take(2048).collect();
    let ciphertext = oracle(plaintext, key);
    if !crypto::aes::is_ecb_encrypted(&ciphertext) {
        println!("Not AES?!");
        return "".to_string();
    }
    println!("It is ECB :)");
    let block_len = find_block_size(key).unwrap();
    println!("Block len: {}", block_len);
    String::from_utf8_lossy(&decrypt_ecb(block_len, key)).to_string()
}

/**
Received: "AAAAAAAARollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nRollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{6}\u{6}\u{6}\u{6}\u{6}\u{6}"
Target: "AAAAAAAARollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}"

Received: "AAAAAAAARollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nRollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{6}\u{6}\u{6}\u{6}\u{6}\u{6}"
Target: "AAAAAAAARollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}\u{e}"
current: "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nD"

Takes a random key as input and returns `AES-128-ECB(your-string || unknown-string, random-key)`
**/
fn oracle(plaintext: Vec<u8>, key: &[u8; 16]) -> Vec<u8> {
    let decoded = base64::decode(APPENDED_B64).unwrap();
    let plaintext: Vec<u8> = plaintext.into_iter().chain(decoded.into_iter()).collect();
    //println!("Encrypting using ECB...");
    let padded = Pkcs7::pad(&plaintext, 16);
    crypto::aes::ecb::encrypt(&key, padded.as_slice())
}

#[cfg(test)]
mod test {
    use crate::ex_12_byte_at_a_time_ecb_decryption::{oracle, solve, APPENDED_B64};
    use crypto::aes::random_key;

    #[test]
    fn test_byte_a_time() {
        let key: &[u8; 16] = &random_key();
        let expected = String::from_utf8(base64::decode(APPENDED_B64).unwrap()).unwrap();
        assert_eq!(expected, solve(key));
    }
}
