use std::collections::HashSet;
use std::path::PathBuf;

fn find_aes_block(b64input: String) -> (i64, String) {
    b64input
        .lines()
        .into_iter()
        .map(|line| {
            let repeated_blocks = base64::decode(line.clone())
                .map(|f| count_repeated_blocks(&f))
                .unwrap();
            (repeated_blocks, line)
        })
        .max()
        .map(|(v, str)| (v, str.to_string()))
        .unwrap()
}

/// It's a single line in the input text
/// it will be cut in chunks of 16 bytes
fn count_repeated_blocks(buf: &[u8]) -> i64 {
    (buf.len() / 16) as i64 - buf.chunks(16).into_iter().collect::<HashSet<&[u8]>>().len() as i64
}

#[cfg(test)]
mod test {

    use crate::ex_8_find_aes_ecb_cyphertext::find_aes_block;
    use std::path::PathBuf;

    #[test]
    fn test_decipher() {
        let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        let b64_cipherlines: String = include_str!("../res/ex_8.txt")
            .lines()
            .collect::<Vec<&str>>()
            .join("\n");

        assert_eq!(find_aes_block(b64_cipherlines), (3, expected.to_string()));
    }
}
