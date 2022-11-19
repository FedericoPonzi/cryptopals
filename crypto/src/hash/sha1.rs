use std::mem;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;
const BLOCK_SIZE: usize = 64; // 512 bits.
const ROUNDS: usize = 80;

struct Sha1State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}
impl Sha1State {
    fn new() -> Self {
        Self {
            h0: H0,
            h1: H1,
            h2: H2,
            h3: H3,
            h4: H4,
        }
    }
    fn iter(&self) -> std::vec::IntoIter<u32> {
        [self.h0, self.h1, self.h2, self.h3, self.h4]
            .to_vec()
            .into_iter()
    }
}

fn process_block(mut state: Sha1State, block: &[u8]) -> Sha1State {
    assert_eq!(block.len(), BLOCK_SIZE);

    let mut w = [0u32; 80];

    for i in 0..16 {
        let mut buf: [u8; 4] = [0u8; 4];
        buf.copy_from_slice(&block[i * 4..i * 4 + 4]);
        w[i] = u32::from_be_bytes(buf);
    }

    for i in 16..80 {
        w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = w[i].rotate_left(1);
    }

    let mut a = H0;
    let mut b = H1;
    let mut c = H2;
    let mut d = H3;
    let mut e = H4;

    for i in 0..ROUNDS {
        let (k, f) = match i {
            0..=19 => (0x5A827999, d ^ (b & (c ^ d))),
            20..=39 => (0x6ED9EBA1, b ^ c ^ d),
            40..=59 => (0x8F1BBCDC, (b & c) | (d & (b | c))),
            _ => (0xCA62C1D6, b ^ c ^ d),
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state.h0 = state.h0.wrapping_add(a);
    state.h1 = state.h1.wrapping_add(b);
    state.h2 = state.h2.wrapping_add(c);
    state.h3 = state.h3.wrapping_add(d);
    state.h4 = state.h4.wrapping_add(e);
    state
}

/// Produce a sha1 hash of payload.
pub fn sha1(payload: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(payload);
    let message_size = payload.len() as u64;
    const ONE: u8 = 0x80;
    const SIZE_OF_ONE: u64 = mem::size_of::<u8>() as u64;

    payload.push(ONE);
    let padding_needed = BLOCK_SIZE as u64
        - (message_size + SIZE_OF_ONE) % BLOCK_SIZE as u64
        - mem::size_of::<u64>() as u64;
    for _ in 0..padding_needed {
        payload.push(0);
    }

    // message length in bits (always a multiple of the number of bits in a character).
    let message_size_in_bits = message_size * 8;
    payload.extend((message_size_in_bits).to_be_bytes());

    assert_eq!(payload.len() % BLOCK_SIZE as usize, 0);

    let mut state = Sha1State::new();

    for block in payload.windows(BLOCK_SIZE as usize) {
        state = process_block(state, block);
    }

    let mut ret = [0u8; 20];
    for (i, h) in state.iter().enumerate() {
        ret[4 * i..4 * i + 4].copy_from_slice(&h.to_be_bytes());
    }
    ret.to_vec()
}

#[cfg(test)]
mod test {
    use crate::hash::sha1::sha1;
    use crate::hash::to_hex;
    use std::assert_eq;

    #[test]
    fn test_sha1() {
        let tests = [
            (
                "The quick brown fox jumps over the lazy dog",
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            ),
            ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("Hello, world!", "943a702d06f34599aee1f8da8ef9f7296031d699"),
        ];
        for (input, expected) in tests {
            let received = to_hex(&sha1(input.as_bytes()));
            let expected = expected.to_string();
            assert_eq!(received, expected);
        }
    }
}
