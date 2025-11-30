class MT19937:
    def __init__(self, seed: int):
        self.w, self.n, self.m, self.r = 32, 624, 397, 31
        self.a = 0x9908B0DF
        self.u, self.d = 11, 0xFFFFFFFF
        self.s, self.b = 7, 0x9D2C5680
        self.t, self.c = 15, 0xEFC60000
        self.l = 18
        self.f = 1812433253

        self.MT = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & 0xFFFFFFFF

        self.seed_mt(seed)

    def seed_mt(self, seed: int):
        self.index = self.n
        self.MT[0] = seed & 0xFFFFFFFF
        for i in range(1, self.n):
            self.MT[i] = (self.f * (self.MT[i-1] ^ (self.MT[i-1]
                          >> (self.w - 2))) + i) & 0xFFFFFFFF

    def extract_number(self) -> int:
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")
            self.twist()

        y = self.MT[self.index]

        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)

        self.index += 1
        return y & 0xFFFFFFFF

    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x & 1) != 0:
                xA ^= self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0

    def set_state(self, state: list[int], index: int = 0):
        if len(state) != self.n:
            raise ValueError("state must have length 624")
        self.MT = [s & 0xFFFFFFFF for s in state]
        self.index = index


def temper(x: int) -> int:
    y = x & 0xFFFFFFFF
    y ^= (y >> 11) & 0xFFFFFFFF
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF


def invert_right_xor(y: int, shift: int) -> int:
    x = y
    iterations = (32 + shift - 1) // shift
    for _ in range(iterations):
        x = y ^ (x >> shift)
    return x & 0xFFFFFFFF


def invert_left_xor_and(y: int, shift: int, mask: int) -> int:
    x = y
    iterations = (32 + shift - 1) // shift
    for _ in range(iterations):
        x = y ^ ((x << shift) & mask)
    return x & 0xFFFFFFFF


def untemper(y: int) -> int:
    y = invert_right_xor(y, 18)
    y = invert_left_xor_and(y, 15, 0xEFC60000)
    y = invert_left_xor_and(y, 7, 0x9D2C5680)
    y = invert_right_xor(y, 11)
    return y & 0xFFFFFFFF


if __name__ == "__main__":
    orig_seed = 676767
    orig = MT19937(seed=orig_seed)

    outputs = [orig.extract_number() for _ in range(624)]

    recovered_state = [untemper(y) for y in outputs]

    clone = MT19937(seed=0)
    clone.set_state(recovered_state, index=624)

    for i in range(1000):
        o = orig.extract_number()
        c = clone.extract_number()
        if o != c:
            print("Wrong")
    print("Success!")
