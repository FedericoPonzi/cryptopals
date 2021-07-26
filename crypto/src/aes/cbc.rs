use super::add_round_key;
use crate::aes::decrypt as aes_decrypt;
use crate::aes::encrypt as aes_encrypt;
use crate::Pkcs7;

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
    Pkcs7::remove_padding(ret)
}

pub fn decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&ciphertext[0..16]);
    decrypt_with_iv(&iv, key, ciphertext)
}

pub fn encrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    todo!();
    vec![]
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
