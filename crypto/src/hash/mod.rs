mod md4;
pub mod sha1;

pub fn to_hex<T: AsRef<[u8]>>(input: T) -> String {
    let mut s = String::new();
    for b in input.as_ref().iter() {
        s.push_str(&format!("{:02x}", *b));
    }
    return s;
}
