//! https://cryptopals.com/sets/3/challenges/21
//!  You can get the psuedocode for this from Wikipedia.
//! If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you
//! MT19937 as "rand()"; don't use rand(). Write the RNG yourself.

#[cfg(test)]
mod test {
    use crypto::random::Mt19937MersenneTwisterRng;

    #[test]
    fn test_rng() {
        let mut rng = Mt19937MersenneTwisterRng::new();
        let received: Vec<u32> = (0..10).map(|_| rng.extract_number()).collect();
        let expected = [
            3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391, 3922919429,
            949333985, 2715962298, 1323567403,
        ]
        .to_vec();
        assert_eq!(expected, received);
    }
}
