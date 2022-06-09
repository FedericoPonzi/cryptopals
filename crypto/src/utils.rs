use maplit::hashmap;
use std::collections::HashMap;
use std::ops::BitXor;

// returns the length of the longest substring starting from the beginning of first and second.
pub fn longest_substring(first: &[u8], second: &[u8]) -> usize {
    first
        .clone()
        .into_iter()
        .zip(second)
        .take_while(|(cur, prev)| *cur == *prev)
        .count()
}

/// Xor an array of bytes with a byte
pub fn xor<'a, T: AsRef<[u8]>>(a: T, b: u8) -> Vec<u8> {
    a.as_ref()
        .iter()
        .enumerate()
        .map(|(_i, v)| b.bitxor(*v))
        .collect()
}

/// Caculate frequency of letters in the input
pub fn calculate_frequency(input: Vec<u8>) -> HashMap<u8, f64> {
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

/// Calculates fitting Quotient between the input map and the reference letter's frequency.
pub fn calculate_difference(input: HashMap<u8, f64>, letters_frequency: HashMap<u8, f64>) -> f64 {
    let input_len: f64 = input.values().into_iter().sum();
    input
        .into_iter()
        .map(|(letter, freq)| (letter, (freq * 100f64) / input_len))
        .flat_map(|(letter, freq)| {
            letters_frequency
                .get(&letter)
                .map(|def_freq| (def_freq - freq).abs())
        })
        .sum::<f64>()
        / input_len
}

/// Returns the confidence score, the decrypted text and the key.
pub fn single_byte_xor_dechiper(input: Vec<u8>) -> (f64, Vec<u8>, u8) {
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
            if curr.0 >= new.0 {
                new
            } else {
                curr
            }
        })
}

/// Returns the hamming distance between a and b
pub fn hamming_distance(a: Vec<u8>, b: Vec<u8>) -> u32 {
    a.into_iter()
        .zip(b.into_iter())
        .map(|(first, second)| (first ^ second).count_ones())
        .sum()
}

/// Returns the confidence score and the original key
pub fn find_original_key(transposed: Vec<Vec<u8>>) -> (f64, Vec<u8>) {
    let r: Vec<(f64, u8)> = transposed
        .into_iter()
        .map(|t| {
            let i = single_byte_xor_dechiper(t);
            (i.0, i.2)
        })
        .collect();
    let mut score = 0f64;
    let mut res = vec![];
    for i in r {
        score += i.0;
        res.push(i.1);
    }
    return (score, res);
}

// Returns the input repeatedly XORed with key.
pub fn repeating_xor_key<T: Clone + IntoIterator<Item = u8>>(input: &[u8], key: T) -> Vec<u8>
where
    <T as IntoIterator>::IntoIter: Clone,
{
    input
        .into_iter()
        .zip(key.into_iter().cycle())
        .map(|(ch, k)| ch.bitxor(k))
        .collect()
}

/// Gets a vec of vec of ciphertexts, and returns another vec of vec in which n-th vec contains the
/// n-th chart from each vec.
/// E.g.: [[a, b], [c,d]] = [a,c][b,d]
pub fn transpose(ciphertexts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let max_length = ciphertexts.iter().map(|el| el.len()).max().unwrap();
    let mut ret = vec![];
    for _ in 0..max_length {
        ret.push(Vec::new());
    }
    for el in ciphertexts {
        for (index, byte) in el.into_iter().enumerate() {
            ret[index].push(byte);
        }
    }
    ret
}

#[cfg(test)]
mod test {
    use crate::utils::single_byte_xor_dechiper;
    #[test]
    fn test_single_byte_xor_decipher() {
        let buf = [
            154, 144, 145, 138, 128, 158, 155, 151, 149, 135, 135, 149, 132, 149, 135, 128, 158,
            135, 158, 154, 155, 128, 154, 144, 159, 158, 138, 135, 146, 131, 158, 156, 145, 138,
            154, 157, 138, 132, 152, 156, 144, 154, 135, 128, 128, 154, 154, 145, 128, 128, 146,
            149, 244, 128, 129, 244, 138, 146, 135, 146,
        ];
        let received = single_byte_xor_dechiper(buf.to_vec());
        let expected = [
            105, 99, 98, 121, 115, 109, 104, 100, 102, 116, 116, 102, 119, 102, 116, 115, 109, 116,
            109, 105, 104, 115, 105, 99, 108, 109, 121, 116, 97, 112, 109, 111, 98, 121, 105, 110,
            121, 119, 107, 111, 99, 105, 116, 115, 115, 105, 105, 98, 115, 115, 97, 102, 7, 115,
            114, 7, 121, 97, 116, 97,
        ];
        assert_eq!(received.1, expected);
    }
}
