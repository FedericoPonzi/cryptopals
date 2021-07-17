use super::add_round_key;
use crate::aes::decrypt;

// todo: move to pkcs struct
fn remove_padding(mut plaintext: Vec<u8>) -> Vec<u8> {
    if let Some(b) = plaintext.last() {
        if *b < 16u8 {
            for i in 0..*b as usize {
                plaintext.pop();
            }
        }
    }
    plaintext
}

pub fn cbc_with_iv(iv: &[u8; 16], key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut ret = vec![];
    let mut previous = [0u8; 16];
    previous.copy_from_slice(iv);

    for block in ciphertext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        let decrypted_block = decrypt(&buf, key);
        let xored = add_round_key(&decrypted_block, &previous);
        previous.copy_from_slice(block);
        ret.append(&mut xored.to_vec());
    }
    remove_padding(ret)
}

pub fn cbc(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&ciphertext[0..16]);
    cbc_with_iv(&iv, key, ciphertext)
}
