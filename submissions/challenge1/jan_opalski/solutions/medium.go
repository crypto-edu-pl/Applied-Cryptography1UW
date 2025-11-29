package solutions

import (
	"fmt"
)

// https://cryptopals.com/sets/3/challenges/21
func Medium(seed uint32) {
	fmt.Println("=============================\n\t MEDIUM (21)\n=============================")
	rng := newMt(seed)
	fmt.Println("First 5 integers generated for seed", seed)
	for range 5 {
		fmt.Println(rng.extractNumber())
	}
}

type my_mtrng struct {
	mt    [624]uint32
	index int
}

// used pseudocode from https://pl.wikipedia.org/wiki/Mersenne_Twister
func newMt(seed uint32) my_mtrng {
	ans := my_mtrng{}
	ans.mt[0] = seed
	for i := uint32(1); i < 624; i++ {
		ans.mt[i] = 0x6c078965*(ans.mt[i-1]^(ans.mt[i-1]>>30)) + i
	}
	return ans
}

func (rng *my_mtrng) extractNumber() uint32 {
	if rng.index == 0 {
		rng.generateNumbers()
	}
	y := rng.mt[rng.index]
	y ^= (y >> 11)
	y ^= ((y << 7) & 0x9d2c5680)
	y ^= ((y << 15) & 0xefc60000)
	y ^= (y >> 18)
	rng.index = (rng.index + 1) % 624
	return y
}

func (rng *my_mtrng) generateNumbers() {
	for i := range 624 {
		y := rng.mt[i]&(1<<31) | rng.mt[(i+1)%624]&(^uint32(1<<31))
		rng.mt[i] = rng.mt[(i+397)%624] ^ (y >> 1)
		if y%2 == 1 {
			rng.mt[i] ^= 0x9908b0df
		}
	}
}
