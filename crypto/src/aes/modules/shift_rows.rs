/// With this process, the following transformation is applied:
/// * First row remains unchanged.
/// * Second row has a one-byte circular left shift.
/// * Third row has a two-byte circular left shift.
/// * Fourth row has a three-byte circular left shift.
pub fn shift_rows(state: &[u8; 16]) -> [u8; 16] {
    [
        state[0],
        state[4 * 1 + 1],
        state[4 * 2 + 2],
        state[4 * 3 + 3],
        state[4],
        state[4 * 2 + 1],
        state[4 * 3 + 2],
        state[4 * 0 + 3],
        state[8],
        state[4 * 3 + 1],
        state[4 * 0 + 2],
        state[4 * 1 + 3],
        state[12],
        state[4 * 0 + 1],
        state[4 * 1 + 2],
        state[4 * 2 + 3],
    ]
}

pub fn shift_rows_inverse(state: &[u8; 16]) -> [u8; 16] {
    [
        state[0],
        state[4 * 3 + 1],
        state[4 * 2 + 2],
        state[4 * 1 + 3],
        state[4],
        state[4 * 0 + 1],
        state[4 * 3 + 2],
        state[4 * 2 + 3],
        state[8],
        state[4 * 1 + 1],
        state[4 * 0 + 2],
        state[4 * 3 + 3],
        state[12],
        state[4 * 2 + 1],
        state[4 * 1 + 2],
        state[4 * 0 + 3],
    ]
}

#[cfg(test)]
mod test {
    use super::{shift_rows, shift_rows_inverse};

    #[test]
    fn test_shift_rows() {
        let state = [
            0xc9, 0xaf, 0xd4, 0xf2, 0xfb, 0xda, 0xc9, 0xb6, 0x92, 0xaa, 0xd7, 0x59, 0xf5, 0x6b,
            0x43, 0x6a,
        ];

        let expected = [
            0xc9, 0xda, 0xd7, 0x6a, 0xfb, 0xaa, 0x43, 0xf2, 0x92, 0x6b, 0xd4, 0xb6, 0xf5, 0xaf,
            0xc9, 0x59,
        ];

        assert_eq!(expected, shift_rows(&state));
        assert_eq!(shift_rows_inverse(&shift_rows(&state)), state);
    }
}
