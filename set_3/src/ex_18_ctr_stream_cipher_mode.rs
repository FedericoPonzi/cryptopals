//! https://cryptopals.com/sets/3/challenges/18

#[cfg(test)]
mod test {
    use crypto::aes::ctr;
    use crypto::aes::ctr::{decrypt, encrypt};

    #[test]
    fn test_solve() {
        // same as: crypto::aes::ctr::test::test_ctr
        let input = base64::decode(
            b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        let key = b"YELLOW SUBMARINE";
        let received = decrypt(input.clone(), 0, *key);
        let expected = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();
        assert_eq!(expected, received);

        let received = encrypt(expected, 0, *key);
        assert_eq!(input, received);
    }
}
