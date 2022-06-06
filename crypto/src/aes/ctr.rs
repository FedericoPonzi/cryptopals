use crate::aes;

fn produce_keystream_input(nonce: u64, counter: u64) -> [u8; 16] {
    let mut ret = [0; 16];
    (&mut ret[..8]).copy_from_slice(&nonce.to_le_bytes());
    (&mut ret[8..]).copy_from_slice(&counter.to_le_bytes());
    ret
}
struct CtrIterator {
    buffer: Vec<u8>,
    counter: u64,
    nonce: u64,
    key: [u8; 16],
}
impl CtrIterator {
    fn new(nonce: u64, key: [u8; 16]) -> Self {
        Self {
            buffer: vec![],
            counter: 0,
            key,
            nonce,
        }
    }
}
impl Iterator for CtrIterator {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            let keystream = produce_keystream_input(self.nonce, self.counter);
            let mut ciphertext = aes::encrypt(&keystream, &self.key);
            self.buffer.extend_from_slice(&mut ciphertext);
            self.counter += 1;
        }
        Some(self.buffer.remove(0))
    }
}
pub fn encrypt(plaintext: Vec<u8>, nonce: u64, key: [u8; 16]) -> Vec<u8> {
    plaintext
        .into_iter()
        .zip(CtrIterator::new(nonce, key).into_iter())
        .map(|(a, b)| a ^ b)
        .collect()
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

    use crate::aes::ctr::{decrypt, encrypt, produce_keystream_input};

    #[test]
    fn test_produce_keystream_input() {
        let received = produce_keystream_input(0, 0);
        assert_eq!(u128::from_le_bytes(received), 0);
        let received = produce_keystream_input(0, 1);
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(received, expected);
        let received = produce_keystream_input(0, 2);
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
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
}
