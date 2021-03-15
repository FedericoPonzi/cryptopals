use std::collections::{BTreeMap, HashMap};
use std::ops::BitXor;

pub fn xor<'a, T: AsRef<[u8]>>(a: T, b: u8) -> Vec<u8> {
    a.as_ref()
        .iter()
        .enumerate()
        .map(|(_i, v)| b.bitxor(*v))
        .collect()
}

/// Caculate frequency of letters in the input
pub(crate) fn calculate_frequency(input: Vec<u8>) -> HashMap<u8, f64> {
    let mut letters_frequency: HashMap<u8, u64> = (b'a'..=b'z').map(|c| (c, 0)).collect();
    input.iter().for_each(|ch| {
        if letters_frequency.contains_key(ch) {
            *letters_frequency.get_mut(ch).unwrap() += 1
        }
    });
    letters_frequency
        .into_iter()
        .map(|(lett, freq)| (lett, (freq as f64 / input.len() as f64) * 100f64))
        .collect()
}

/// Calculates the difference between the input map and the reference letter's frequency.
pub(crate) fn calculate_difference(
    input: HashMap<u8, f64>,
    letters_frequency: HashMap<u8, f64>,
) -> f64 {
    input
        .into_iter()
        .flat_map(|(letter, freq)| {
            letters_frequency
                .get(&letter)
                .map(|def_freq| (def_freq - freq).abs())
        })
        .filter(|freq| *freq > 0f64)
        .sum()
}

/// Returns the confidence score, the decrypted text and the key.
pub(crate) fn single_byte_xor_dechiper(input: Vec<u8>) -> (f64, Vec<u8>, u8) {
    let letters_frequency = hashmap! {
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
    (0x00..0xff)
        .map(|c| {
            let decrypted: Vec<u8> = xor(input.clone(), c);
            let frequency = calculate_frequency(decrypted.clone());
            // Smaller the distance, the better
            let distance = calculate_difference(frequency.clone(), letters_frequency.clone());
            (distance, decrypted, c)
        })
        .fold((f64::MAX, Vec::new(), 0), |curr, new| {
            if curr.0 > new.0 {
                new
            } else {
                curr
            }
        })
}

/// Returns the hamming distance between a and b
pub(crate) fn hamming_distance(a: Vec<u8>, b: Vec<u8>) -> u32 {
    a.into_iter()
        .zip(b.into_iter())
        .map(|(first, second)| (first ^ second).count_ones())
        .sum()
}
