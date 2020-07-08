use std::collections::HashMap;
use std::ops::BitXor;

pub fn xor(a: Vec<u8>, b: u8) -> Vec<u8> {
    a.into_iter()
        .enumerate()
        .map(|(i, v)| b.bitxor(v))
        .collect()
}

pub(crate) fn calculate_frequency(input: Vec<u8>) -> HashMap<u8, f64> {
    let mut LETTERS_FREQUENCY: HashMap<u8, u64> = (b'a'..=b'z').map(|c| (c, 0)).collect();
    input.iter().for_each(|ch| {
        if LETTERS_FREQUENCY.contains_key(ch) {
            *LETTERS_FREQUENCY.get_mut(ch).unwrap() += 1
        }
    });
    LETTERS_FREQUENCY
        .into_iter()
        .map(|(k, v)| (k, (v as f64 / input.len() as f64) * 100f64))
        .collect()
}

pub(crate) fn calculate_difference(
    input: HashMap<u8, f64>,
    LETTERS_FREQUENCY: HashMap<u8, f64>,
) -> f64 {
    input
        .into_iter()
        .flat_map(|(letter, freq)| {
            LETTERS_FREQUENCY
                .get(&letter)
                .map(|def_freq| (def_freq - freq).abs())
        })
        .sum()
}

pub(crate) fn single_byte_xor_dechiper(input: Vec<u8>) -> (f64, Vec<u8>) {
    let LETTERS_FREQUENCY = hashmap! {
        b'a' => 8.497,
        b'b' => 1.492,
        b'c' => 2.202,
        b'd' => 4.253,
        b'e' => 11.162,
        b'f' => 2.228,
        b'g' => 2.015,
        b'h' => 6.094,
        b'i' => 7.546,
        b'j' => 0.153,
        b'k' => 1.292,
        b'l' => 4.025,
        b'm' => 2.406,
        b'n' => 6.749,
        b'o' => 7.507,
        b'p' => 1.929,
        b'q' => 0.095,
        b'r' => 7.587,
        b's' => 6.327,
        b't' => 9.356,
        b'u' => 2.758,
        b'v' => 0.978,
        b'w' => 2.560,
        b'x' => 0.150,
        b'y' => 1.994,
        b'z' => 0.077
    };
    (b'0'..=b'f')
        .map(|c| {
            let decrypted: Vec<u8> = xor(input.clone(), c);
            let frequency = calculate_frequency(decrypted.clone());
            let diff = calculate_difference(frequency, LETTERS_FREQUENCY.clone());
            (diff, decrypted)
        })
        .fold((f64::MAX, Vec::new()), |curr, new| {
            if curr.0 > new.0 {
                new
            } else {
                curr
            }
        })
}
