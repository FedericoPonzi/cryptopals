pub mod md4;
pub mod sha1;

pub fn to_hex<T: AsRef<[u8]>>(input: T) -> String {
    let mut s = String::new();
    for b in input.as_ref().iter() {
        s.push_str(&format!("{:02x}", *b));
    }
    return s;
}

pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    // Check that the input string has an even number of characters
    if hex.len() % 2 != 0 {
        return None;
    }

    // Convert each pair of hex digits to a byte
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let byte = match u8::from_str_radix(&hex[i * 2..(i + 1) * 2], 16) {
            Ok(byte) => byte,
            Err(_) => return None,
        };
        bytes.push(byte);
    }

    Some(bytes)
}
