use crate::{get_g, get_p};
/// ### Implement Diffie-Hellman
///
/// For one of the most important algorithms in cryptography this exercise
///   couldn't be a whole lot easier.
///
/// Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even
///   going to explain it. Just do what I do.
///
/// Generate "a", a random number mod 37. Now generate "A", which is "g"
///   raised to the "a" power mode 37 --- A = (g**a) % p.
///
/// Do the same for "b" and "B".
///
/// "A" and "B" are public keys. Generate a session key with them; set
///   "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
///
/// Do the same with A**b, check that you come up with the same "s".
///
/// To turn "s" into a key, you can just hash it to create 128 bits of
///   key material (or SHA256 it to create a key for encrypting and a key
///   for a MAC).
///
/// Ok,  that was fun, now repeat the exercise with bignums like in the real
///   world. Here are parameters NIST likes:
///
/// ```markdown
/// p:
/// ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
/// e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
/// 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
/// 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
/// 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
/// c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
/// bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
/// fffffffffffff
///
/// g: 2
/// ```
///
/// This is very easy to do in Python or Ruby or other high-level
///   languages that auto-promote fixnums to bignums, but it isn't "hard"
///   anywhere.
///
/// Note that you'll need to write your own modexp (this is blackboard
///   math, don't freak out), because you'll blow out your bignum library
///   raising "a" to the 1024-bit-numberth power. You can find modexp
///   routines on Rosetta Code for most languages.
///
/// In reality BigUint implements modexp (modpow) already.
use hex;
use num_bigint::BigUint;
use rand::random;

pub fn generate_pk(p: &BigUint, g: &BigUint) -> (BigUint, u32) {
    let a: u32 = random::<u32>();
    let A: BigUint = g.modpow(&BigUint::from(a), p);
    (A, a)
}
pub fn generate_session_key(prvkey_a: u32, pk_b: &BigUint, p: &BigUint) -> BigUint {
    // s = (B**a) % p.
    let s = pk_b.modpow(&BigUint::from(prvkey_a), &p);
    s
}

fn diffie_hellman() {
    let p = get_p();
    let g = get_g();
    println!("Starting");
    let (pk_a, prv_a) = generate_pk(&p, &g);
    println!("Generated pk_a = {}, prv_a = {}", pk_a, prv_a);
    let (pk_b, prv_b) = generate_pk(&p, &g);
    println!("Generated pk_b = {}, prv_b = {}", pk_b, prv_b);
    let session_a = generate_session_key(prv_a, &pk_b, &p);
    println!("Generated session_a = {}", session_a);
    let session_b = generate_session_key(prv_b, &pk_a, &p);
    println!("Generated session_b = {}", session_b);
    assert_eq!(session_a, session_b);
}

#[cfg(test)]
mod tests {
    use crate::ex_33_implement_diffie_hellman::diffie_hellman;

    #[test]
    fn test_diffie_hellman() {
        diffie_hellman();
    }
}
