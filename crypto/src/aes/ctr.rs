use crate::aes;
use crate::aes::ctr::Endian::{Big, Little};

/// This could be made faster as nonce is always the same. I could store the buffer and reuse it
/// and just overwrite the counter part.
fn produce_keystream_input(nonce: u64, counter: u64, counter_endian: Endian) -> [u8; 16] {
    let mut ret = [0; 16];
    (&mut ret[..8]).copy_from_slice(&nonce.to_le_bytes());
    match counter_endian {
        Big => (&mut ret[8..]).copy_from_slice(&counter.to_be_bytes()),
        Little => (&mut ret[8..]).copy_from_slice(&counter.to_le_bytes()),
    };

    ret
}

#[derive(Debug, Copy, Clone)]
enum Endian {
    Big,
    Little,
}

#[derive(Debug)]
struct CtrIterator {
    buffer: Vec<u8>,
    counter: u64,
    nonce: u64,
    key: [u8; 16],
    // Cryptopals requires a little endian counter.
    // While cyrptography 1 course requires big endian counter.
    counter_bytes_mode: Endian,
}
impl CtrIterator {
    /// Default counter endian mode: Little. Used by Cryptopals
    fn new(nonce: u64, key: [u8; 16]) -> Self {
        Self {
            buffer: vec![],
            counter: 0,
            key,
            nonce,
            counter_bytes_mode: Little,
        }
    }

    /// Default counter endian mode: Big. Used by Cryptography 1 coursera course.
    fn new_with_counter(nonce: u64, counter: u64, key: [u8; 16]) -> Self {
        Self {
            buffer: vec![],
            counter,
            key,
            nonce,
            counter_bytes_mode: Big,
        }
    }
}
impl Iterator for CtrIterator {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            let keystream =
                produce_keystream_input(self.nonce, self.counter, self.counter_bytes_mode);
            let ciphertext = aes::encrypt(&keystream, &self.key);
            self.buffer = ciphertext.to_vec();
            self.counter += 1;
        }
        Some(self.buffer.remove(0))
    }
}

fn run_ctr(ctr_iterator: CtrIterator, plaintext: Vec<u8>) -> Vec<u8> {
    plaintext
        .into_iter()
        .zip(ctr_iterator)
        .map(|(a, b)| a ^ b)
        .collect()
}

pub fn encrypt(plaintext: Vec<u8>, nonce: u64, key: [u8; 16]) -> Vec<u8> {
    run_ctr(CtrIterator::new(nonce, key), plaintext)
}

///  Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.
/// Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers,
/// because most of what we want to encrypt is better described as a stream than as a sequence
/// of blocks. Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the
/// "decrypt" transforms. Constructions like CTR are what he was talking about.
pub fn decrypt(plaintext: Vec<u8>, nonce: u64, key: [u8; 16]) -> Vec<u8> {
    encrypt(plaintext, nonce, key)
}
#[cfg(test)]
mod test {
    use std::u128;

    use crate::aes::ctr::{
        decrypt, encrypt, produce_keystream_input, run_ctr, CtrIterator, Endian,
    };

    #[test]
    fn test_produce_keystream_input() {
        let counter_little_mode = Endian::Little;
        let received = produce_keystream_input(0, 0, counter_little_mode);
        assert_eq!(u128::from_le_bytes(received), 0);
        let received = produce_keystream_input(0, 1, counter_little_mode);
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(received, expected);
        let received = produce_keystream_input(0, 2, counter_little_mode);
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(received, expected);

        let received = produce_keystream_input(0, 0, Endian::Big);
        assert_eq!(u128::from_le_bytes(received), 0);

        let received = produce_keystream_input(0, 1, Endian::Big);
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(received, expected);
    }
    #[test]
    fn test_ctr() {
        let input = base64::decode(
            b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        let key = b"YELLOW SUBMARINE";
        let received = decrypt(input.clone(), 0, *key);
        let expected = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();
        assert_eq!(expected, received);

        let received = encrypt(expected, 0, *key);
        assert_eq!(input, received);
    }
    fn test_ctr_decrypt_hex(key: &str, ciphertext: &str, expected: &str) {
        let key = hex::decode(key).unwrap();
        let mut encrytped = hex::decode(ciphertext).unwrap();

        let mut key_buff = [0u8; 16];
        key_buff.copy_from_slice(&key);

        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&encrytped[0..8]);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&encrytped[8..16]);

        encrytped.drain(0..16);

        let ctr_iter = CtrIterator::new_with_counter(
            u64::from_le_bytes(nonce),
            u64::from_be_bytes(counter),
            key_buff,
        );

        let res = run_ctr(ctr_iter, encrytped);
        assert_eq!(expected, String::from_utf8_lossy(&res));
    }

    #[test]
    fn test_ctr_decrypt() {
        test_ctr_decrypt_hex("36f18357be4dbd77f050515c73fcf9f2", "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", "CTR mode lets you build a stream cipher from a block cipher.");
        test_ctr_decrypt_hex("36f18357be4dbd77f050515c73fcf9f2", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451", "Always avoid the two time pad!")
    }
}
