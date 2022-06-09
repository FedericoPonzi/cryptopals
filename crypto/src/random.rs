pub trait Rng {
    /// return uniform ditribution in [0,1)
    fn rand(&mut self) -> f32;
}

/// From wikipedia:
/// Is not cryptographically secure, unless the CryptMT variant (discussed below) is used. The reason is
/// that observing a sufficient number of iterations (624 in the case of MT19937, since this is the size
/// of the state vector from which future iterations are produced) allows one to predict all future
/// iterations.
pub struct Mt19937MersenneTwisterRng {
    mt: [u32; N],
    index: usize,
    seed: u32,
}
mod consts_32 {
    pub const N: usize = 624;
    pub const W: u32 = 32;
    pub const M: usize = 397;
    pub const R: u32 = 31;
    pub const A: u32 = 0x9908B0DF;
    pub const U: u32 = 11;
    pub const D: u64 = 0xFFFFFFFF;
    pub const S: u32 = 7;
    pub const B: u64 = 0x9D2C5680;
    pub const T: u32 = 15;
    pub const C: u64 = 0xEFC60000;
    pub const L: u32 = 18;
    pub const F: u64 = 1812433253;
    pub const LOWER_MASK: u64 = (1 << R) - 1;
    pub const UPPER_MASK: u64 = (!LOWER_MASK) & 0xFFFFFFFF;
    pub const DEFAULT_SEED: u32 = 5489;
}
use consts_32::*;
impl Mt19937MersenneTwisterRng {
    pub fn new() -> Self {
        Self::new_seed(DEFAULT_SEED)
    }
    #[inline]
    fn _u32(x: u64) -> u32 {
        let mut ret = [0u8; 4];
        ret.copy_from_slice(&x.to_le_bytes()[..4]);
        u32::from_le_bytes(ret)
    }
    pub fn new_seed(seed: u32) -> Self {
        let mt = [0; N];
        let index = N;
        let mut ret = Self { mt, index, seed };
        ret.initialize_with_seed();
        ret
    }
    fn initialize_with_seed(&mut self) {
        self.mt[0] = self.seed;
        for i in 1..N {
            let a = (self.mt[i - 1] ^ (self.mt[i - 1] >> (W - 2))) as u64;
            self.mt[i] = Self::_u32(F * a + i as u64);
        }
    }
    pub fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            self.twist()
        }
        let mut y = self.mt[self.index] as u64;
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);
        self.index += 1;
        Self::_u32(y)
    }

    fn twist(&mut self) {
        for i in 0..N {
            let x = Self::_u32(
                (self.mt[i] as u64 & UPPER_MASK) + (self.mt[(i + 1) % N] as u64 & LOWER_MASK),
            );
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa = xa ^ A;
            }
            self.mt[i] = self.mt[(i + M) % N] ^ xa;
            self.index = 0
        }
    }
}

impl Rng for Mt19937MersenneTwisterRng {
    fn rand(&mut self) -> f32 {
        (self.extract_number() as f64 / 4294967296f64) as f32
    }
}

#[cfg(test)]
mod test {
    use crate::random::Mt19937MersenneTwisterRng;

    #[test]
    fn test_to_u32() {
        assert_eq!(
            Mt19937MersenneTwisterRng::_u32(9948446125718u64),
            1301868182
        );
    }
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
