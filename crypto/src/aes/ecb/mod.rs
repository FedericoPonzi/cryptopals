pub mod cryptanalysis;

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

pub fn pad_and_encrypt(key: &[u8; 16], plaintext: Vec<u8>) -> Vec<u8> {
    let plaintext = crate::Pkcs7::pad(&plaintext, 16);
    encrypt(key, &plaintext)
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

#[cfg(test)]
mod test {
    use crate::aes::ecb::encrypt;
    use crate::Pkcs7;

    fn test_encrypt(plaintext: &[u8], expected_b64: &str, key: &[u8; 16]) {
        let padded = Pkcs7::pad(&plaintext.to_vec(), 16);
        let received = encrypt(key, &padded);
        let encoded = base64::encode(&received);
        assert_eq!(expected_b64, encoded);
    }

    #[test]
    // Tested with:https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'c4%2099%203c%2041%2031%203c%20f%2049%20c7%20dc%203f%2050%20dc%2069%20e5%209e'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D)To_Base64('A-Za-z0-9%2B/%3D')From_Base64('A-Za-z0-9%2B/%3D',true/disabled)AES_Decrypt(%7B'option':'Hex','string':'88%2065%2020%20a9%20b8%2086%20c6%20fe%2041%2018%2040%2050%2042%202f%207c%201a'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D/disabled)&input=VGhlIEFkdmFuY2VkIEVuY3J5cHRpb24gU3RhbmRhcmQgKEFFUyksIAphbHNvIGtub3duIGJ5IGl0cyBvcmlnaW5hbCBuYW1lIFJpam5kYWVsCmlzIGEgc3BlY2lmaWNhdGlvbiBmb3IgdGhlIGVuY3J5cHRpb24gb2YgZWxlY3Ryb25pYyBkYXRhIGVzdGFibGlzaGVkIApieSB0aGUgVS5TLiBOYXRpb25hbCBJbnN0aXR1dGUgb2YgU3RhbmRhcmRzIGFuZCBUZWNobm9sb2d5IChOSVNUKSBpbiAyMDAx
    // beware of padding on cyberchef.
    fn test_ecb_encrypt() {
        let plaintext = br#"The Advanced Encryption Standard (AES) 
also known by its original name Rijndael
is a specification for the encryption of electronic data established 
by the U.S. National Institute of Standards and Technology (NIST) in 2001"#;

        let bad_key = &[
            0x88, 0x65, 0x20, 0xa9, 0xb8, 0x86, 0xc6, 0xfe, 0x41, 0x18, 0x40, 0x50, 0x42, 0x2f,
            0x7c, 0x1a,
        ];
        let b_encr = "yL81OcwP6uL7ygcfNsKvK4PQH4F8tobUKGCSAmJ8psZrzb7+9ZEztwrReNmUomWnGCfjDG4TVn5t7shxydEgOXDr2eGl8gD24nimLQj8Q42wesWJy73fll3nx6NhnTggTXMXB15UsWD3x8DNkjSc0HRTeK1sGbXUVBsZW3DlrtGlmNMYsiKqKvpWfKDMDR8angphgBdMamrS+EUTlOCo0eNnRx8AMGZqDWOwoiiu4dn3eQomR2cQqpT6XpB3cZgfY9POerfQpg3e2WMy+tICE1dFpBR0yLEz+W6N8D48EgvOHwjZtSitDuLECh5ATtCo";
        test_encrypt(plaintext, b_encr, bad_key);

        let good_key = &[
            0xc4, 0x99, 0x3c, 0x41, 0x31, 0x3c, 0x0f, 0x49, 0xc7, 0xdc, 0x3f, 0x50, 0xdc, 0x69,
            0xe5, 0x9e,
        ];
        let g_encr = "UUipw+CDhOAzlX1Wcw3aX2AkR069Vcw6x3BRsTleVtkNgvCgOO5mHayXjahZ8yx9q4qNXHFhIpk0+EMaKm/fdhwkyB5Y9BYC8FRk/oVgiQ/ISyHJA8e4WUqJvGl4kCGr8OHsui7WU6gg57a8rbc8jyIh3D5Yp+O8CY+wFPQ+LDAV1Im3TDxIb05U8WT23pQ70nGqS/BRfR58oeAwAqiDtqNQ1AnD9e/Y7qwEjRwIv/Eq/Sm/Nz3xZDDW7QU+ld/RsN7ktfTMMqa92LGGitDViP++X7sypzS7s0vP0HHxq3S3To54gGmRTR4cWcYz609a";
        test_encrypt(plaintext, g_encr, good_key);
    }
}
