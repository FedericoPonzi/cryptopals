use std::path::PathBuf;
fn hamming_distance(a: Vec<u8>, b: Vec<u8>) -> u32 {
    let mask = 0b1;
    a.into_iter()
        .zip(b.into_iter())
        .map(|(first, second)| {
            (0..8).map(move |m| {
                if ((first >> m) & mask) != ((second >> m) & mask) {
                    1
                } else {
                    0
                }
            })
        })
        .flatten()
        .sum()
}
fn break_repeating_key_xor(file: PathBuf) -> (Vec<u8>, Vec<u8>) {
    (vec![], vec![])
}

#[cfg(test)]
mod test {
    use crate::ex_6_break_repeating_key_xor::{break_repeating_key_xor, hamming_distance};
    use std::path::PathBuf;

    #[test]
    fn test_hamming_distance() {
        let received = hamming_distance(
            "this is a test".bytes().collect(),
            "wokka wokka!!!".bytes().collect(),
        );
        let expected = 37;
        assert_eq!(received, expected);
    }
    #[test]
    fn test_decipher() {
        let expected = b"Now that the party is jumping\n";
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("res/ex_4.txt");
        let received = break_repeating_key_xor(file);
        println!("Received: {:?}", String::from_utf8_lossy(&received.1));
        assert_eq!(received.1, expected.to_vec());
    }
}
