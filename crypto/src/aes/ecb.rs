pub fn decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    use crate::aes::decrypt as aes_decrypt;
    let mut ret = vec![];
    for block in ciphertext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        ret.append(&mut aes_decrypt(&buf, key).to_vec());
    }
    ret
}

/// Encrypt using ecb mode.
pub fn encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use crate::aes::encrypt as aes_encrypt;
    let mut ret = vec![];
    for block in plaintext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        ret.append(&mut aes_encrypt(&buf, key).to_vec());
    }
    ret
}
