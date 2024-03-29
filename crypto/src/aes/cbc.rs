use super::add_round_key;
use crate::aes::decrypt as aes_decrypt;
use crate::aes::encrypt as aes_encrypt;

pub fn decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let iv = [0u8; 16];
    decrypt_with_iv(&iv, key, ciphertext)
}
pub fn decrypt_with_iv(iv: &[u8; 16], key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut ret = vec![];
    let mut previous = [0u8; 16];
    previous.copy_from_slice(iv);
    for block in ciphertext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        let decrypted_block = aes_decrypt(&buf, key);
        let xored = add_round_key(&decrypted_block, &previous);
        previous.copy_from_slice(block);
        ret.append(&mut xored.to_vec());
    }
    ret
}

pub fn encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    encrypt_with_iv(&[0u8; 16], key, plaintext)
}

pub fn encrypt_with_iv(iv: &[u8; 16], key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut ret = vec![];
    let mut previous = [0u8; 16];
    previous.copy_from_slice(iv);
    for block in plaintext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        let xored = add_round_key(&buf, &previous);
        let encrypted_block = aes_encrypt(&xored, key);
        previous.copy_from_slice(&encrypted_block);
        ret.append(&mut encrypted_block.to_vec());
    }
    ret
}

#[cfg(test)]
mod test {
    use crate::aes::cbc;
    use crate::aes::cbc::{encrypt, encrypt_with_iv};
    use crate::Pkcs7;

    const PLAINTEXT: &[u8] = br#"The Advanced Encryption Standard (AES) 
also known by its original name Rijndael
is a specification for the encryption of electronic data established 
by the U.S. National Institute of Standards and Technology (NIST) in 2001"#;

    const KEY: [u8; 16] = [
        0xc4, 0x99, 0x3c, 0x41, 0x31, 0x3c, 0x0f, 0x49, 0xc7, 0xdc, 0x3f, 0x50, 0xdc, 0x69, 0xe5,
        0x9e,
    ];

    #[test]
    fn test_cbc_iv() {
        // Non null IV:
        let encrypted_b64 = "GTpPWua12OgeZQDvs381xDR1Hkm/bEegmAj5Q03YXVc3K3n5oAM+W3l0c7lzJlmTKZl6bmXJH/wcZmlSV45guFjjGO/gHwVblCWwLQUaXMWrfRJhgQmNmvSiQV2ZCCLgFpKeFuJ7QlSS0B7HuGPLTAFUwJJynug0jBYRPPWp7T9awq0wvCeN7/zThTc/WO6DzcR9lBxzQvfuv87lSzl4glmnFOwkgiwxGZ/K7GMP2GBFGVFJf1EEUXiwpzEtTSF7hs7nBq4szaYFKwELqSUL8YjIj5bZJiJNQ/ZF7ezwXlo=";

        let received = encrypt_with_iv(&KEY, &KEY, PLAINTEXT);
        let encoded = base64::encode(&received);
        println!("{}", encoded);
        assert_eq!(encrypted_b64, encoded);

        let received = cbc::decrypt_with_iv(&KEY, &KEY, &received);
        assert_eq!(
            String::from_utf8_lossy(&received),
            String::from_utf8_lossy(PLAINTEXT)
        );
    }

    #[test]
    fn test_aes_cbc() {
        let encrypted_b64 = "UUipw+CDhOAzlX1Wcw3aX5yj+eA4+q221IRH8loJ+9yZghMbsUz+8AixTsQOH6oMIYkp/z1oDQfxNvsbw+bv8EHTXDvgF9NIWLspOdXFp/1a2jYwb5TExOttlz6bfK8IJsZh9g+QjOZOWLm8ZA89226TQCPyRSEU3q8jQuWWxFugJueVd0V78ZVqZqE6c+JNiMHqI8uvCyZwRMmQOcQvlth0d96pWiwIGHCA0gpEhYZiHCFwpH2nZBTNKW6pMvWSp0yB2q/84nEyKHNQA6chMi0+9zsEuCOAgn/eKEpanQ8=";
        let received = encrypt(&KEY, PLAINTEXT);
        let encoded = base64::encode(&received);
        assert_eq!(encrypted_b64, encoded);
        let res = cbc::decrypt(&KEY, &base64::decode(encrypted_b64).unwrap());
        assert_eq!(
            String::from_utf8_lossy(&res),
            String::from_utf8_lossy(PLAINTEXT)
        );
    }

    // IV is prefixed to the ciphertext
    fn test_aes_cbc_decrypt_hex(key: &str, ciphertext: &str, expected: &str) {
        let key = hex::decode(key).unwrap();
        let encrytped = hex::decode(ciphertext).unwrap();
        let mut key_buff = [0u8; 16];
        key_buff.copy_from_slice(&key);
        let mut iv_buff = [0u8; 16];
        iv_buff.copy_from_slice(&encrytped[0..16]);
        let mut res =
            Pkcs7::remove_padding(cbc::decrypt_with_iv(&iv_buff, &key_buff, &encrytped)).unwrap();
        res.drain(0..16);
        assert_eq!(expected, String::from_utf8_lossy(&res));
    }
    #[test]
    fn test_aes_cbc_decrypt() {
        // From Cryptograph 1 on Coursera
        let tests = [
            ("140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", "Basic CBC mode encryption needs padding."),
            ("140b41b22a29beb4061bda66b6747e14", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253", "Our implementation uses rand. IV"),
        ];
        for (key, ciphertext, expected) in tests {
            test_aes_cbc_decrypt_hex(key, ciphertext, expected);
        }
    }
}
