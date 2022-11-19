pub mod sha1;

pub fn to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for b in input.iter() {
        s.push_str(&format!("{:02x}", *b));
    }
    return s;
}
