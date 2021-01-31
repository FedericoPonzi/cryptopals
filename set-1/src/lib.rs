#![allow(dead_code)]
#![allow(unused_imports)]
#[macro_use]
extern crate hex_literal;
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate aes;

mod custom_aes;
mod ex_1_hex_to_b64;
mod ex_2_fixed_xor;
mod ex_3_single_byte_xor_cipher;
mod ex_4_detect_single_character_xor;
mod ex_5_repeating_key_xor;
mod ex_6_break_repeating_key_xor;
mod ex_7_aes_in_ecb_mode;
mod shared;
