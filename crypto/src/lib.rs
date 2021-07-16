use crate::mix_columns::mix_columns_inverse;
use crate::sbox::{sub_bytes, sub_bytes_inverse};
use crate::shift_rows::shift_rows_inverse;

mod add_round_key;
mod aes_ecb;
mod key_expansion;
mod mix_columns;
mod sbox;
mod shift_rows;

const ROUNDS_128: usize = 9;
// YELLOW SUBMARINE

// TODO: divide in block.
fn ecb(input: &[u8; 128]) {
    let blocks = input
        .chunks(16)
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
}

// expandkey128(key);
//
// addroundkey(data,key,10);
// rev_shiftrows(data);
// rev_subbytes(data);
//
// for(int i = 9; i>= 1; i--) {
//     addroundkey(data,key,i);
//     rev_mixColumn(data);
//     rev_shiftrows(data);
//     rev_subbytes(data);
// }
//
// addroundkey(data,key,0);
pub fn decrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let expaneded_key = key_expansion::key_expansion(key);
    let mut state = add_round_key::add_round_key(block, &expaneded_key[10]);
    state = shift_rows_inverse(&state);
    state = sub_bytes_inverse(&state);
    for round in (1..=ROUNDS_128).rev() {
        state = add_round_key::add_round_key(&state, &expaneded_key[round]);
        state = mix_columns_inverse(&state);
        state = shift_rows_inverse(&state);
        state = sub_bytes_inverse(&state);
    }
    state = add_round_key::add_round_key(&state, &expaneded_key[0]);
    state
}

fn printhex(inp: &[u8]) -> String {
    inp.into_iter().map(|b| format!("{:#01x}, ", b)).collect()
}

pub fn encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let expaneded_key = key_expansion::key_expansion(key);
    let mut state = add_round_key::add_round_key(&block, &expaneded_key[0]);
    for round in (1..=ROUNDS_128) {
        println!("Round: {}", round);
        state = sub_bytes(&state);
        state = shift_rows::shift_rows(&state);
        state = mix_columns::mix_columns(&state);
        state = add_round_key::add_round_key(&state, &expaneded_key[round]);
    }
    state = sub_bytes(&state);
    state = shift_rows::shift_rows(&state);
    state = add_round_key::add_round_key(&state, &expaneded_key[10]);
    state
}

#[cfg(test)]
mod tests {
    use crate::{decrypt, encrypt, printhex};

    #[test]
    fn test_encrypt() {
        let key = b"Thats my Kung Fu";
        let plaintext = b"Two One Nine Two";
        let received = encrypt(&plaintext, &key);
        let expected = [
            0x29, 0xC3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02,
            0xD7, 0x3A,
        ];
        assert_eq!(expected, received);
    }

    #[test]
    fn test_decrypt() {
        let key = b"Thats my Kung Fu";
        let crypto = [
            0x29, 0xC3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02,
            0xD7, 0x3A,
        ];
        let received = decrypt(&crypto, key);
        let expected = b"Two One Nine Two";
        println!("Received: {}", String::from_utf8_lossy(&received));
        assert_eq!(expected, &received);
    }
}
