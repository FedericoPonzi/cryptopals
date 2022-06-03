//!Crypto Challenge Set 2
//!
//! This is the first of several sets on block cipher cryptography. This is bread-and-butter crypto,
//! the kind you'll see implemented in most web software that does crypto.
//!
//! This set is relatively easy. People that clear set 1 tend to clear set 2 somewhat quickly.
//!
//! Three of the challenges in this set are extremely valuable in breaking real-world crypto;
//! one allows you to decrypt messages encrypted in the default mode of AES, and the other two
//! allow you to rewrite messages encrypted in the most popular modes of AES.
//!
#![allow(dead_code)]
#![allow(unused_imports)]

mod ex_09_pkcs_padding;
mod ex_10_cbc_mode;
mod ex_11_ecb_cbc_oracle;
mod ex_12_byte_at_a_time_ecb_decryption;
mod ex_13_ecb_cut_and_paste;
mod ex_14_byte_at_a_time_ecb_decryption_harder;
mod ex_15_pkcs7_padding_validation;
mod ex_16_cbc_bitflipping_attack;
