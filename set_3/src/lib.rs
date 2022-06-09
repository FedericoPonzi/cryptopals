//!Crypto Challenge Set 3
//!
//! This is the next set of block cipher cryptography challenges (even the randomness stuff here
//! plays into block cipher crypto).
//!
//! This set is moderately difficult. It includes a famous attack against CBC mode, and a "cloning"
//! attack on a popular RNG that can be annoying to get right.
//!
//! We've also reached a point in the crypto challenges where all the challenges, with one possible
//! exception, are valuable in breaking real-world crypto.
//!
#![allow(dead_code)]
#![allow(unused_imports)]

mod ex_17_the_cbc_padding_oracle;
mod ex_18_ctr_stream_cipher_mode;
mod ex_19_break_fixed_nonce_ctr_mode_using_substitutions;
mod ex_20_break_fixed_nonce_ctr_statistically;
mod ex_21_implement_the_mt19937_mersenne_twister_rng;
mod ex_22_crack_an_mt19937_seed;
mod ex_23_clone_an_mt19937_rng_from_its_output;
mod ex_24_create_the_mt19937_stream_cipher_and_break_it;
