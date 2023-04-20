use std::convert::TryInto;
use std::mem;

/// The MD4 Message-Digest Algorithm implementation
/// https://www.rfc-editor.org/rfc/rfc1320
///

const BLOCK_SIZE: usize = 64; // 512 bits.

/// number of bits to rotate left in each operation during the three rounds of the algorithm
const S: [[u32; 4]; 3] = [[3, 7, 11, 19], [3, 5, 9, 13], [3, 9, 11, 15]];

pub fn md4(payload: &[u8]) -> Vec<u8> {
    md4_state_len(Md4State::new(), payload, payload.len()).0
}

pub fn md4_state_len(
    state: Md4State,
    payload: &[u8],
    payload_length: usize,
) -> (Vec<u8>, Md4State) {
    let payload = add_padding(payload.to_vec(), payload_length);

    let mut state = state;

    // Process each 16-word block.
    for block in payload.chunks(BLOCK_SIZE) {
        state = process_block(state, block);
    }

    let mut result = [0u8; 16];
    result.copy_from_slice(
        &state
            .iter()
            .flat_map(|x| x.to_le_bytes().to_vec())
            .collect::<Vec<u8>>(),
    );
    (result.to_vec(), state)
}

#[derive(Debug, Clone)]
pub struct Md4State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl Md4State {
    pub fn from_message_digest(md: &Vec<u8>) -> Self {
        Self {
            a: u32::from_le_bytes(md[0..4].try_into().unwrap()),
            b: u32::from_le_bytes(md[4..8].try_into().unwrap()),
            c: u32::from_le_bytes(md[8..12].try_into().unwrap()),
            d: u32::from_le_bytes(md[12..16].try_into().unwrap()),
        }
    }
}

impl Md4State {
    fn new() -> Self {
        Self {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
        }
    }
    fn iter(&self) -> std::vec::IntoIter<u32> {
        [self.a, self.b, self.c, self.d].to_vec().into_iter()
    }
}
// We define three auxiliary functions that each take as input three 32-bit words
// and produce as output one 32-bit word.
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
pub fn md4_padding_needed(message_size: usize) -> usize {
    const SIZE_OF_ONE: usize = mem::size_of::<u8>();
    BLOCK_SIZE - (message_size + SIZE_OF_ONE + mem::size_of::<u64>()) % BLOCK_SIZE
}
/// The message M is padded so that its length (in bits) is equal to 448 modulo 512, that is,
/// the padded message is 64 bits less than a multiple of 512.
/// The padding consists of a single 1 bit, followed by enough zeros to pad the message to the
/// required length. Padding is always used, even if the length of M happens to equal 448 mod 512.
/// As a result, there is at least one bit of padding, and at most 512 bits of padding.
/// Then the length (in bits) of the message (before padding) is appended as a 64-bit block.
fn add_padding(mut data: Vec<u8>, data_len: usize) -> Vec<u8> {
    let required_padding = md4_padding_needed(data_len);
    data.push(0x80);
    data.extend(vec![0; required_padding]);
    let data_len_bits = (data_len as u64) * 8;
    data.extend_from_slice(&data_len_bits.to_le_bytes());
    data
}

fn process_block(state: Md4State, chunk: &[u8]) -> Md4State {
    let mut x: [u32; 16] = [0; 16];
    for (i, chunk1) in chunk.chunks_exact(4).enumerate() {
        x[i] = u32::from_le_bytes(chunk1.try_into().unwrap());
    }

    let mut a = state.a;
    let mut b = state.b;
    let mut c = state.c;
    let mut d = state.d;
    for round in 0..3 {
        for i in 0..16 {
            let (f_i, k_i, magic_constant) = match round {
                0 => (f(b, c, d), i, 0),
                1 => (
                    g(b, c, d),
                    // produces indexes: 0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15
                    4 * (i % 4) + 1 * (i / 4),
                    0x5a827999,
                ),
                2 => (
                    h(b, c, d),
                    [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i],
                    0x6ed9eba1,
                ),
                _ => unreachable!(),
            };
            let temp = a
                .wrapping_add(f_i)
                .wrapping_add(x[k_i])
                .wrapping_add(magic_constant)
                .rotate_left(S[round][i % 4]);
            a = d;
            d = c;
            c = b;
            b = temp;
        }
    }

    Md4State {
        a: state.a.wrapping_add(a),
        b: state.b.wrapping_add(b),
        c: state.c.wrapping_add(c),
        d: state.d.wrapping_add(d),
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::md4::md4;
    use crate::hash::to_hex;
    use std::assert_eq;

    #[test]
    fn test_md4() {
        let tests = [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
            (
                "The quick brown fox jumps over the lazy dog",
                "1bee69a46ba811185c194762abaeae90",
            ),
        ];
        for (input, expected) in tests {
            assert_eq!(
                to_hex(md4(input.as_bytes())),
                expected,
                "Failed on input: '{}'",
                input
            );
        }
    }
}
