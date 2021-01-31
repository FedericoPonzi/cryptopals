use aes::cipher::generic_array::GenericArray;
use aes::{Aes128, BlockCipher, NewBlockCipher};
use block_modes::block_padding::Pkcs7;
use block_modes::cipher::BlockCipherMut;
use block_modes::{BlockMode, Ecb};
use std::path::PathBuf;

type Aes128Ecb = Ecb<Aes128, Pkcs7>;
fn decrypt_aes_in_ecb_mode(_base64: PathBuf, key: &str) -> Vec<u8> {
    let b64_cipherlines: String = include_str!("../res/ex_7.txt")
        .lines()
        .collect::<Vec<&str>>()
        .join("");
    let cipherlines = base64::decode(&b64_cipherlines).unwrap();
    let mut buffer = [0u8; 2880];
    let mut keybuff = [0u8; 16];
    keybuff.copy_from_slice(key.as_bytes());
    buffer[..cipherlines.len()].copy_from_slice(cipherlines.as_slice());
    let mut cipher = Aes128Ecb::new_var(&keybuff, Default::default()).unwrap();
    cipher.decrypt(&mut buffer);
    buffer.to_vec()
}

#[cfg(test)]
mod test {

    use crate::ex_7_aes_in_ecb_mode::decrypt_aes_in_ecb_mode;
    use std::path::PathBuf;

    #[test]
    fn test_decipher() {
        let _expected = b"Now that the party is jumping\n";
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("res/ex_4.txt");
        let key = "YELLOW SUBMARINE";
        let received = decrypt_aes_in_ecb_mode(file, key);
        assert!(String::from_utf8_lossy(received.as_slice())
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
