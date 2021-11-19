use crate::aes::random_key;

// TODO: Remove padding.
pub fn decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    use crate::aes::decrypt as aes_decrypt;
    let mut ret = vec![];
    for block in ciphertext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        ret.append(&mut aes_decrypt(&buf, key).to_vec());
    }
    ret
}

/// Encrypt using ecb mode.
pub fn encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use crate::aes::encrypt as aes_encrypt;
    let mut ret = vec![];
    for block in plaintext.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block);
        ret.append(&mut aes_encrypt(&buf, key).to_vec());
    }
    ret
}

pub fn find_block_size<O>(oracle: O) -> Option<usize>
where
    O: Fn(Vec<u8>, &[u8; 16]) -> Vec<u8>,
{
    let key = random_key();
    let mut last_vec: Vec<u8> = vec![];
    for i in 1..=128 {
        let plaintext = std::iter::repeat(b'A').take(i).collect();

        let ciphertext = oracle(plaintext, &key);
        let block_size = ciphertext
            .clone()
            .into_iter()
            .zip(last_vec)
            .take_while(|(cur, prev)| *cur == *prev)
            .count();
        if block_size > 8 {
            return Some(block_size);
        }
        last_vec = ciphertext;
    }
    None
}

#[cfg(test)]
mod test {
    use crate::aes::ecb::decrypt;
    use crate::aes::ecb::encrypt;
    use crate::Pkcs7;

    fn test_encrypt(plaintext: &[u8], expected_b64: String, key: &[u8; 16]) {
        let padded = Pkcs7::pad(&plaintext.to_vec(), 16);
        let received = encrypt(key, &padded);
        let encoded = base64::encode(&received);
        assert_eq!(expected_b64, encoded);
    }

    #[test]
    // Tested against:https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'c4%2099%203c%2041%2031%203c%20f%2049%20c7%20dc%203f%2050%20dc%2069%20e5%209e'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D)To_Base64('A-Za-z0-9%2B/%3D')From_Base64('A-Za-z0-9%2B/%3D',true/disabled)AES_Decrypt(%7B'option':'Hex','string':'88%2065%2020%20a9%20b8%2086%20c6%20fe%2041%2018%2040%2050%2042%202f%207c%201a'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D/disabled)&input=VGhlIEFkdmFuY2VkIEVuY3J5cHRpb24gU3RhbmRhcmQgKEFFUyksIAphbHNvIGtub3duIGJ5IGl0cyBvcmlnaW5hbCBuYW1lIFJpam5kYWVsCmlzIGEgc3BlY2lmaWNhdGlvbiBmb3IgdGhlIGVuY3J5cHRpb24gb2YgZWxlY3Ryb25pYyBkYXRhIGVzdGFibGlzaGVkIApieSB0aGUgVS5TLiBOYXRpb25hbCBJbnN0aXR1dGUgb2YgU3RhbmRhcmRzIGFuZCBUZWNobm9sb2d5IChOSVNUKSBpbiAyMDAx
    fn test_ecb_encrypt() {
        let plaintext = br#"The Advanced Encryption Standard (AES), 
also known by its original name Rijndael
is a specification for the encryption of electronic data established 
by the U.S. National Institute of Standards and Technology (NIST) in 2001"#;

        // 88 65 20 a9 b8 86 c6 fe 41 18 40 50 42 2f 7c 1a
        let bad_key = &[
            136, 101, 32, 169, 184, 134, 198, 254, 65, 24, 64, 80, 66, 47, 124, 26,
        ];
        let b_encr = "yL81OcwP6uL7ygcfNsKvK4PQH4F8tobUKGCSAmJ8psZCBLskIziEujjlLY46z3+PtoWWZoE9Zp2CtFbCUaUdWPgXtiZu5QoGcHLnZXnl1MT6VKgshgT1sVmUpXl2znTBJ2hkkGlB6Sa8reA7iGlomNkmcSvq1p8tW/lpk0ox5oK51zcEgNpPKxcqAUW9DEQQjKDnRaeunzPL4PfvT/KBAUGWWDhI/QxS5tuEO+AhOig8g578AEdbglLBOxaK5CZ8Mm3TWCa2IqMkrwfeZpMGnKxZn32z3liFhA9PgFlGSYs3u8ryDZQQk1u/A1oj8adu".to_string();
        test_encrypt(plaintext, b_encr, bad_key);

        // c4 99 3c 41 31 3c f 49 c7 dc 3f 50 dc 69 e5 9e
        let good_key = &[
            196, 153, 60, 65, 49, 60, 15, 73, 199, 220, 63, 80, 220, 105, 229, 158,
        ];
        let g_encr = "FglqVxpV4iYtdMkQgivE2adWYQVBJ5GScqDhvHR8jeWJLKCJRymUi/h2BjlKMOQQ/armPl2oIeZF17Yag5TF9jseZND8U88uOLnJTPLZAXVHcjIurgeFWokztrpNiA5XXuAVr1fKFrPLX5y6v836QdT9UMuKtrHmSHNWpqqACdrsVe5QPWdVTapRjaEnFZtArFeZkYkvxtzI9iH6143rc/fuCZlD9rZXMif9wW2iqORJ5RDKcmA8QU3oL0HXFP/xMlF2D3d6GvlMLloSedA0kYWOUhM+HCq9PLz5rumHiVEBvu+GA60CePW6sVWZhTmL".to_string();
        test_encrypt(plaintext, g_encr, good_key);
    }
}
