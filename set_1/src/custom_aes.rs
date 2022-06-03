// For the key-expansion routine, this was super helpful: https://www.samiam.org/key-schedule.html
use hex_literal::hex;

/// An 8-bit circular rotate on a 32-bit word
fn circular_rotate(mut word: [u8; 4]) -> [u8; 4] {
    let first = word[0];
    for index in 0..word.len() - 1 {
        word[index] = word[index + 1];
    }
    word[3] = first;

    return word;
}
#[test]
fn test_circular_rotate() {
    assert_eq!(circular_rotate(hex!("1d2c3a4f")), hex!("2c3a4f1d"));
}

/// Calculate the rcon used in key expansion
fn rcon(mut word: u32) -> u32 {
    let m1: u32 = 0x80808080;
    let _m2: u32 = 0x7f7f7f7f;
    let m3: u32 = 0x0000001b;
    let mut c = 1;
    if word == 0 {
        return 0;
    }
    while word != 0 {
        let b = c & m1;
        c <<= 1;
        if b == m1 {
            c ^= m3
        }
        word -= 1;
    }
    return c;
}

fn expand_key(_initial_key: [u8; 128]) -> Vec<[u8; 128]> {
    unimplemented!()
}

enum AesMode {
    ECB,
}
struct AES;
impl AES {
    fn add_round_key<'a>(mut state: [u8; 128], round_key: &[u8; 128]) -> [u8; 128] {
        for index in 0..state.len() {
            state[index] ^= round_key[index];
        }
        state
    }
    pub fn decrypt(_data: &[u8], _key: &[u8], _mode: AesMode) -> Vec<u8> {
        unimplemented!()
    }
}
