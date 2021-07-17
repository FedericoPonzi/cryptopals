use crate::aes::modules::sbox;

const RC_VALUES: &[u8; 11] = &[
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

/// The AES key expansion algorithm takes as input a four-word (16-byte) key and produces a linear
/// array of 44 words (176 bytes)
/// For AES-128, there is 1 AddRoundKey at the beginning, 9 rounds (with 9 AddRounKey) and 1 final
/// AddRoundKey in the final round.
pub fn key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut ret = [[0u8; 16]; 11];

    // number of round keys needed:
    // 11 round keys for AES-128, 13 keys for AES-192, and 15 keys for AES-256
    const ROUNDS: usize = 10;

    ret[0] = key.clone();

    for i in 1..=ROUNDS {
        let mut last_column: [u8; 4] = [0u8; 4];
        last_column.copy_from_slice(&ret[i - 1][12..16]);
        let rotated = rot_word(&last_column);
        let sboxed = sub_word(&rotated);
        let rcon = [RC_VALUES[i], 0x0, 0x0, 0x0];
        let rcon_xored = xor(&sboxed, &rcon);
        let mut first_column_previous_round = [0u8; 4];
        first_column_previous_round.copy_from_slice(&ret[i - 1][0..4]);
        let first_column = xor(&rcon_xored, &first_column_previous_round);
        ret[i] = [0u8; 16];
        ret[i][0..4].copy_from_slice(&first_column);
        let mut previous_round_column = first_column;
        for word in 1..=3 {
            let word_start = 4 * word;
            let word_end = word_start + 4;
            let mut current_column: [u8; 4] = [0u8; 4];
            current_column.copy_from_slice(&ret[i - 1][word_start..word_end]);
            let new_column = xor(&current_column, &previous_round_column);
            ret[i][word_start..word_end].copy_from_slice(&new_column);
            previous_round_column = new_column;
        }
    }
    ret
}

fn xor(sboxed: &[u8; 4], rcon: &[u8; 4]) -> [u8; 4] {
    let mut ret = [0u8; 4];
    for i in 0..ret.len() {
        ret[i] = sboxed[i] ^ rcon[i];
    }
    ret
}

// Rotate left
fn rot_word(w: &[u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

// Apply s-box to each byte
fn sub_word(w: &[u8]) -> [u8; 4] {
    let mut ret = [0u8; 4];
    for (pos, x) in w.iter().cloned().enumerate().take(4) {
        ret[pos] = sbox::single_sub(x);
    }
    ret
}

#[cfg(test)]
mod test {
    use super::key_expansion;

    #[test]
    fn test_key_expansion() {
        let input: &[u8; 16] = b"SOME 128 BIT KEY";
        let expanded = key_expansion(input);
        let expected = [
            0xe1, 0x21, 0x86, 0xf2, 0xc1, 0x10, 0xb4, 0xca, 0xe1, 0x52, 0xfd, 0x9e, 0xc1, 0x19,
            0xb8, 0xc7,
        ];
        assert_eq!(expanded[1], expected);

        let input: &[u8; 16] = b"Thats my Kung Fu";
        let expanded = key_expansion(input);
        let expected = [
            0xe2, 0x32, 0xfc, 0xf1, 0x91, 0x12, 0x91, 0x88, 0xb1, 0x59, 0xe4, 0xe6, 0xd6, 0x79,
            0xa2, 0x93,
        ];
        assert_eq!(expanded[1], expected);
    }
}
