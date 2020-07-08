use crate::shared::single_byte_xor_dechiper;
use std::path::PathBuf;

fn detect_single_character_xor(file: PathBuf) -> Vec<u8> {
    let file = std::fs::read_to_string(&file).unwrap();

    file.split('\n')
        .into_iter()
        .map(hex::decode)
        .filter_map(Result::ok)
        .map(single_byte_xor_dechiper)
        .fold((f64::MAX, Vec::new()), |curr, new| {
            if curr.0 > new.0 {
                new
            } else {
                curr
            }
        })
        .1
}
#[cfg(test)]
mod test {
    use crate::ex_4_detect_single_character_xor::detect_single_character_xor;
    use std::path::PathBuf;
    #[test]
    fn test_decipher() {
        let expected = b"Now that the party is jumping\n";
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("res/ex_4.txt");
        let received = detect_single_character_xor(file);
        println!("Received: {:?}", String::from_utf8_lossy(&received));
        assert_eq!(received, expected.to_vec());
    }
}
