use std::convert::TryInto;
use std::{iter, mem};

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;
const BLOCK_SIZE: usize = 64; // 512 bits.
const ROUNDS: usize = 80;

// Sometimes these registers are called a,b..e
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Sha1State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}
impl Default for Sha1State {
    fn default() -> Self {
        Self::new()
    }
}
impl Sha1State {
    /// Function to generate a sha1state from a message digest
    pub fn from_message_digset(message_digest: &[u8]) -> Self {
        let h0 = u32::from_be_bytes(message_digest[0..4].try_into().unwrap());
        let h1 = u32::from_be_bytes(message_digest[4..8].try_into().unwrap());
        let h2 = u32::from_be_bytes(message_digest[8..12].try_into().unwrap());
        let h3 = u32::from_be_bytes(message_digest[12..16].try_into().unwrap());
        let h4 = u32::from_be_bytes(message_digest[16..20].try_into().unwrap());
        Self { h0, h1, h2, h3, h4 }
    }
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
pub fn sha1_padding_needed(message_size: usize) -> usize {
    const SIZE_OF_ONE: usize = mem::size_of::<u8>();
    BLOCK_SIZE - (message_size + SIZE_OF_ONE + mem::size_of::<u64>()) % BLOCK_SIZE
}

/// Produce a sha1 hash of payload.
pub fn sha1(payload: &[u8]) -> Vec<u8> {
    sha1_state_len(Sha1State::new(), payload, payload.len()).0
}

/// Produce a sha1 hash of payload.
/// Used for sha1 length extension attack
pub fn sha1_state_len(
    state: Sha1State,
    payload: &[u8],
    payload_length: usize,
) -> (Vec<u8>, Sha1State) {
    let mut payload = payload.to_vec();
    let message_size = payload_length;
    const ONE: u8 = 0x80;
    payload.push(ONE);

    let padding_needed = sha1_padding_needed(message_size);

    payload.extend(iter::repeat(0).take(padding_needed));

    // message length in bits (always a multiple of the number of bits in a character).
    let message_size_in_bits = (message_size * 8).to_be_bytes();
    payload.extend(message_size_in_bits);

    assert_eq!(
        (message_size + padding_needed + 1 + 8) % BLOCK_SIZE as usize,
        0
    );

    let mut state = state;

    for block in payload.chunks(BLOCK_SIZE as usize) {
        state = process_block(state, block);
    }

    let mut ret = [0u8; 20];
    for (i, h) in state.iter().enumerate() {
        ret[4 * i..4 * i + 4].copy_from_slice(&h.to_be_bytes());
    }
    (ret.to_vec(), state)
}

#[cfg(test)]
mod test {
    use crate::aes::random_key;
    use crate::hash::sha1::{sha1, sha1_state_len, Sha1State};
    use crate::hash::to_hex;
    use std::assert_eq;

    #[test]
    fn test_from_md() {
        const MESSAGE: &[u8] =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mut buf = random_key().to_vec();
        buf.extend_from_slice(MESSAGE);
        let (message_digest, state) = sha1_state_len(Default::default(), &buf, buf.len());
        let generated_state = Sha1State::from_message_digset(&message_digest);
        assert_eq!(generated_state, state);
    }

    #[test]
    fn test_sha1() {
        // ref: echo -n 'data' | sha1sum
        let tests = [
            (
                "The quick brown fox jumps over the lazy dog",
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            ),
            ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("Hello, world!", "943a702d06f34599aee1f8da8ef9f7296031d699"),
            /* TODO: this fails
            (

                r#"The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data"."#,
                "83bd0a05c761efdf84eac56ad4afd91fdef620e8",
            ),
             */
        ];
        for (input, expected) in tests {
            let received = to_hex(&sha1(input.as_bytes()));
            let expected = expected.to_string();
            assert_eq!(received, expected);
        }
    }
}
