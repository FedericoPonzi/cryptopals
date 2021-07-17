use crate::aes::decrypt;

pub fn ecb(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut ret = vec![];
    for block in ciphertext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        ret.append(&mut decrypt(&buf, key).to_vec());
    }
    ret
}
