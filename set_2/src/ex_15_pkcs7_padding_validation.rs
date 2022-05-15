//! ### PKCS#7 padding validation
//!
//! Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
//!
//! The string:
//!
//! "ICE ICE BABY\x04\x04\x04\x04"
//!
//! ... has valid padding, and produces the result "ICE ICE BABY".
//!
//! The string:
//!
//! "ICE ICE BABY\x05\x05\x05\x05"
//!
//! ... does not have valid padding, nor does:
//!
//! "ICE ICE BABY\x01\x02\x03\x04"
//!
//! If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.
//!
//! Crypto nerds know where we're going with this. Bear with us.

fn solve(plaintext: Vec<u8>) -> Option<Vec<u8>> {
    crypto::Pkcs7::remove_padding(plaintext)
}

#[cfg(test)]
mod test {
    use crate::ex_15_pkcs7_padding_validation::solve;

    #[test]
    fn test_solution() {
        solve(b"ICE ICE BABY\x04\x04\x04\x04".to_vec()).unwrap();
        assert!(solve(b"ICE ICE BABY\x05\x05\x05\x05".to_vec()).is_none());
        assert!(solve(b"ICE ICE BABY\x01\x02\x03\x04".to_vec()).is_none());
    }
}
