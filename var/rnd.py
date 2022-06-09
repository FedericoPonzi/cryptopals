def _int32(x):
    return int(0xFFFFFFFF & x)

class MT19937MersenneTwisterRNG:
    def __init__(self, seed: int = None):
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = 0x9908B0DF
        self.u = 11
        self.d = 0xFFFFFFFF
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.f = 1812433253
        self.mt = [0]*self.n
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = _int32(~self.lower_mask)
        if seed is None:
            self.seed = 5489
        else:
            self.seed = seed
        self.index = self.n
        self.initialize_with_seed()

    def initialize_with_seed(self):
        self.mt[0] = self.seed
        for i in range(1, self.n):
            a = (self.mt[i-1] ^ (self.mt[i-1] >> (self.w - 2)))
            b = self.f * a + i
            self.mt[i] = _int32(b)

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        print(self.index)
        y = self.mt[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        print("y:", y)
        self.index += 1
        return _int32(y)

    def twist(self):
        print("Twisteeed")
        for i in range(self.n):
            x = _int32((self.mt[i] & self.upper_mask) + (self.mt[(i+1) % self.n] & self.lower_mask))
            xa = x >> 1
            if x % 2 != 0:
                xa = xa ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xa
            self.index = 0

i = MT19937MersenneTwisterRNG()
r = []
for _ in range(10):
    r.append(i.extract_number())
print(r)