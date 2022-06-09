//! https://cryptopals.com/sets/3/challenges/22
//! ### Crack an MT19937 seed
//!
//! Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the
//! same sequence of outputs given a seed).
//!
//! Write a routine that performs the following operation:
//!
//! -   Wait a random number of seconds between, I don't know, 40 and 1000.
//! -   Seeds the RNG with the current Unix timestamp
//! -   Waits a random number of seconds again.
//! -   Returns the first 32 bit output of the RNG.
//!
//! You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although
//! you're missing some of the fun of this exercise if you do that.
//!
//! From the 32 bit RNG output, discover the seed.
//!

use crypto::random::Mt19937MersenneTwisterRng;
use std::time::{SystemTime, UNIX_EPOCH};

fn solve(random: u32) -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    for seed in now - 1 * 60..now {
        let mut rng = Mt19937MersenneTwisterRng::new_seed(seed);
        if rng.extract_number() == random {
            return seed;
        }
    }
    panic!("Seed not found!");
}
#[cfg(test)]
mod test {
    use crate::ex_22_crack_an_mt19937_seed::solve;
    use crypto::random::Mt19937MersenneTwisterRng;
    use rand::{random, Rng};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn generate_seed() -> (u32, u32) {
        let mut rng = rand::thread_rng();
        std::thread::sleep(Duration::from_secs(rng.gen_range(4..10)));
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut rnd = Mt19937MersenneTwisterRng::new_seed(seed);
        std::thread::sleep(Duration::from_secs(rng.gen_range(10..30)));
        (rnd.extract_number(), seed)
    }

    #[test]
    fn test_solve() {
        let (random, expected) = generate_seed();
        let received = solve(random);
        assert_eq!(expected, received);
    }
}
