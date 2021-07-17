/// Within this transformation, each column is taken one at a time and each byte within the column
/// is transformed to a new value based on all four bytes in the column.
/// https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
pub fn mix_columns(state: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0u8; 16];
    for i in [0usize, 4usize, 8usize, 12usize] {
        let mut column = [0u8; 4];
        for j in 0..4 {
            column[j] = state[i + j];
        }
        let mixed = mix_column(&column);
        ret[i..i + 4].copy_from_slice(&mixed);
    }
    ret
}

fn mix_column(col: &[u8]) -> [u8; 4] {
    [
        multiply_by_two(col[0]) ^ multiply_by_three(col[1]) ^ col[2] ^ col[3],
        multiply_by_two(col[1]) ^ multiply_by_three(col[2]) ^ col[3] ^ col[0],
        multiply_by_two(col[2]) ^ multiply_by_three(col[3]) ^ col[0] ^ col[1],
        multiply_by_two(col[3]) ^ multiply_by_three(col[0]) ^ col[1] ^ col[2],
    ]
}

/// it is equivalent to shifting the number left by one,
/// and then exclusiving-or'ing the value 0x1B if the high bit had been one
/// (where, in case you're wondering, the value 0x1B came from the field representation).
/// And so, that is the answer to the question you asked; if the high bit was a zero,
/// then you don't need to exclusive or anything (or equivalently, you exclusive-or in a 0x00 constant).
fn multiply_by_two(input: u8) -> u8 {
    let ret = input << 1;
    let high_bit_is_one = input >> 7 == 1;
    if high_bit_is_one {
        ret ^ 0x1B
    } else {
        ret
    }
}

fn multiply_by_three(input: u8) -> u8 {
    multiply_by_two(input) ^ input
}

/// M X M X M = M^-1
pub fn mix_columns_inverse(state: &[u8; 16]) -> [u8; 16] {
    let ret = mix_columns(state);
    let ret = mix_columns(&ret);
    mix_columns(&ret)
}

#[cfg(test)]
mod test {
    use super::{mix_columns, mix_columns_inverse, multiply_by_two};
    #[test]
    fn test_multiply_by_two() {
        assert_eq!(multiply_by_two(0), 0);
        assert_eq!(multiply_by_two(2), 4);
        assert_eq!(multiply_by_two(129), 25);
        assert_eq!(multiply_by_two(255), 229);
    }
    #[test]
    pub fn test_shift_columns() {
        let state: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(mix_columns_inverse(&mix_columns(&state)), state);
        let state: [u8; 16] = [0x1; 16];
        let expected: [u8; 16] = state.clone();
        assert_eq!(mix_columns(&state), expected);

        let state: [u8; 16] = [0xc6; 16];
        let expected: [u8; 16] = state.clone();
        assert_eq!(mix_columns(&state), expected);
    }
}
