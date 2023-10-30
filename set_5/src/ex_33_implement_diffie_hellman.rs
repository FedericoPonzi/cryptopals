use hex;
use num_bigint::BigUint;
use rand::random;

fn get_diffie_hellman_key() -> u64 {
    let p = BigUint::from_bytes_be(
        &hex::decode(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
                + "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
                + "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
                + "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
                + "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
                + "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
                + "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
                + "fffffffffffff",
        )
        .unwrap(),
    );
    let g = BigUint::from(2u32);
}

fn diffie_hellman() -> u64 {
    let p: u64 = 10;
    let g: u64 = 5;
    let a: u32 = random::<u32>() % p as u32;
    let b: u32 = random::<u32>() % p as u32;
    let pk_a: u64 = g.pow(a) % p;
    let pk_b: u64 = g.pow(b) % p;
    println!("a = {}, pk_a = {}", a, pk_a);
    println!("b = {}, pk_b = {}", b, pk_b);
    let key_a = pk_b.pow(a) % p;
    let key_b = pk_a.pow(b) % p;
    assert_eq!(key_a, key_b);
    key_a
}

#[cfg(test)]
mod tests {
    use crate::ex_33_implement_diffie_hellman::diffie_hellman;

    #[test]
    fn test_diffie_hellman() {
        diffie_hellman();
    }
}
