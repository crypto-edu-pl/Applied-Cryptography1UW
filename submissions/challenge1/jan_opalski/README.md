# Language
The code was written in Go. These instructions are based on assumption that user trying to run this solution has Go on their machine.
# Running the solution
- enter the directory
- `go run .` (alternatively: `go build` and then `./challenge1`)
## Flags
By default all three solutions will be launched. If you want to see results of execution of only chosen tasks, you can achieve that by passing a subset of flags `-easy`, `-medium`, `-hard` respectively (passing all 3 is effectively the same as passing none of these).

Solution of medium task (implementation of Mersenne Twister RNG) uses a default seed of 19650218 (taken from [English Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister)). It can be changed to arbitrary value (assuming it can be converted to unsigned 32-bit integer) using flag `-seed <value>`.

Example command with flags: `./challenge1 -medium -seed 42`. This will launch only the Mersenne Twister implementation with a starting seed of 42.

# Done tasks
- Easy: [PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15)
- Medium: [Implement the MT19937 Mersenne Twister RNG](https://cryptopals.com/sets/3/challenges/21)
- Hard: [Recover the key from CBC with IV=Key](https://cryptopals.com/sets/4/challenges/27)