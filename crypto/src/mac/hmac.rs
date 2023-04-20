use crate::hash::sha1::sha1;

const BLOCK_SIZE: usize = 64;
const OUTPUT_SIZE: usize = 20; // 20 for sha1
const IN_PAD: u8 = 0x5c;
const OUT_PAD: u8 = 0x36;

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    //Compute the block sized key
    let key = if key.len() > BLOCK_SIZE {
        sha1(key)
    } else {
        key.to_vec()
    };

    // Pad key with zeros to block size
    let mut key_block = [0x00; BLOCK_SIZE];
    key_block[..key.len()].copy_from_slice(&key[..]);

    let mut inner_key_block = key_block.clone();
    let mut outer_key_block = key_block.clone();

    // XOR key with 0x3636363636363636
    for i in 0..BLOCK_SIZE {
        inner_key_block[i] ^= OUT_PAD;
    }

    // Inner digest
    let mut inner_input = inner_key_block.to_vec();
    inner_input.extend_from_slice(data);
    let inner_digest = sha1(&inner_input);

    // XOR key with 0x5c5c5c5c5c5c5c5c
    for i in 0..BLOCK_SIZE {
        outer_key_block[i] ^= IN_PAD;
    }

    // Outer digest: hash(o_key_pad ∥ hash(i_key_pad ∥ message))
    let mut outer_input = outer_key_block.to_vec();
    outer_input.extend_from_slice(&inner_digest);
    sha1(&outer_input)
}

#[cfg(test)]
mod tests {
    use crate::hash::to_hex;
    use crate::mac::hmac::hmac_sha1;

    #[test]
    fn test_hmac_sha1() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";
        let result = hmac_sha1(key, message);
        assert_eq!(expected, to_hex(result));
    }
}
