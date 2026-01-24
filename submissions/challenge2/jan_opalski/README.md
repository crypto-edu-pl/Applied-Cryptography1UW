# Language
The code was written in Go. These instructions are based on assumption that user trying to run this solution has Go on their machine.
# Running the solution
- enter the directory
- `go run .` (alternatively: `go build` and then `./challenge1`)
## Flags
By default all three solutions will be launched. If you want to see results of execution of only chosen tasks, you can achieve that by passing a subset of flags `-easy`, `-medium`, `-hard` respectively (passing all 3 is effectively the same as passing none of these).

# Done tasks
Code is commented in parts I thought could be non-trivial, but general comments are here.
## [Easy](solutions/easy.go)
[Implement Diffie-Hellman](https://cryptopals.com/sets/5/challenges/33)

That's self-explanatory I believe, using provided p and g we generate private value for each client (a/b), which then can send the other g^a mod p. The session key is g^(ab) mod p.
## [Medium](solutions/medium.go)
[Hashing with CBC-MAC](https://cryptopals.com/sets/7/challenges/50)

In order to create a working JS which alerts given text, I want it to look like `alert('Ayo, the Wu is back!');//some-garbage-in-comment`. I'm exploiting the known property of CBC that each block of plaintext is xored with last block of ciphertext. Therefore after I learn the second block of ciphertext of my new plaintext, I can fabricate its third block so that after xoring it will give the same input to encrypting function as did the original plaintext, therefore the last block of ciphertext is the same, which means CBC-MAC is equal.

The produced [code](medium.js) was tested in console of my browser (Mozilla Firefox 140.7.0esr), produced the expected alert.
## [Hard](solutions/hard.go)
[Implement unpadded message recovery oracle](https://cryptopals.com/sets/6/challenges/41)

The attack is basically explained in the task. Attacker can't directly ask server to decrypt c, but can ask it to decrypt c'. The result of this decryption is sufficient to retrieve original message p for ciphertext c.
