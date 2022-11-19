use crate::hash::sha1::sha1;

pub fn sha1_mac(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(key);
    buf.extend_from_slice(payload);
    sha1(&buf)
}
