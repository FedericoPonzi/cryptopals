use crate::ex_5_repeating_key_xor::repeating_xor_key;
use std::path::PathBuf;

fn transpose_blocks(keysize: usize, cyphertext: &[u8]) -> Vec<Vec<u8>> {
    (0..keysize)
        .map(|i| {
            cyphertext
                .chunks(keysize)
                .filter(|ch| i < ch.len())
                .map(|ch| ch[i])
                .collect()
        })
        .collect()
}

fn hamming_distance(a: Vec<u8>, b: Vec<u8>) -> u32 {
    a.into_iter()
        .zip(b.into_iter())
        .map(|(first, second)| (first ^ second).count_ones())
        .sum()
}

fn mean(list: &[i32]) -> f64 {
    let sum: i32 = Iterator::sum(list.iter());
    f64::from(sum) / (list.len() as f64)
}

/// Divides in blocks keysize long, finds the hamming distance, and sort the result with
/// lower HD first.
fn find_key_size(crypted: &[u8]) -> Vec<(usize, f32)> {
    let mut toRet = vec![];
    for keysize in 2..=40 {
        let chunks: Vec<&[u8]> = crypted.chunks(keysize).collect();
        let blocks_amount = 4;
        let blocks: Vec<&[u8]> = (0..blocks_amount)
            .into_iter()
            .map(|index| *chunks.get(index).unwrap())
            .collect();
        let mut distance = 0f32;
        // all combinations of distances
        for x in 0..blocks_amount {
            for y in 0..blocks_amount {
                distance += hamming_distance(blocks[x].into(), blocks[y].into()) as f32;
            }
        }
        let ed = distance / keysize as f32;
        toRet.push((keysize, ed));
    }
    toRet.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    toRet
}

fn find_original_key(transposed: Vec<Vec<u8>>) -> Vec<u8> {
    transposed
        .into_iter()
        .map(|t| crate::shared::single_byte_xor_dechiper(t).2)
        .collect()
}

fn break_repeating_key_xor(file: PathBuf) -> (Vec<u8>, Vec<u8>) {
    let cipherlines: Vec<&str> = include_str!("../res/ex_6.txt").lines().collect();
    let ciphertext: String = cipherlines.join("");
    let crypted = base64::decode(ciphertext).unwrap();

    println!("Crypted: {:?}", crypted);
    let keysize = find_key_size(crypted.as_slice());
    println!("Found keysize: {:?}", keysize);
    for (keysize, _) in keysize.into_iter().take(3) {
        let transposed = transpose_blocks(keysize, crypted.as_slice());
        println!("Transposed: {:?}", transposed);
        let key = find_original_key(transposed);
        println!("Original Key: {:?}", key);
        let decrypted = repeating_xor_key(crypted.as_slice(), key.clone());
        println!(
            "Decrypted: {}",
            String::from_utf8(decrypted.clone())
                .unwrap()
                .chars()
                .collect::<String>()
        );
        return (key, decrypted);
    }
    return (vec![], vec![]);
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
        assert!(String::from_utf8_lossy(received.1.as_slice())
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
