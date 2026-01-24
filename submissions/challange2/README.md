### Usage
- `uv run easy.py` https://cryptopals.com/sets/5/challenges/33
- `uv run medium.py` https://cryptopals.com/sets/5/challenges/34
- `uv run hard.py` https://cryptopals.com/sets/5/challenges/40

### Easy
- Diffie-Hellman key exchange 
- Shared secret `s` computed both ways and checked for equality
- Key derivation via `SHA-256(s)` - 2 128bit keys

### Medium
- A DH-based protocol deriving `AES key = SHA1(s)[0:16]`
- AES-CBC with random ivs, an echo bot, and a Man in the Middle
- Parameter injection: MitM replaces public keys (in a real system over the network) with `p`, causing both parties to compute `s=0` => key is always `SHA1(0)[0:16]`

Showcases importance of authenticity.

### Hard
- RSA `e=3` broadcast attack with no padding
- Same plaintext `m` encrypted under three different moduli: `c_i = m^3 mod n_i`
- CRT reconstructs `X = m^3` when `m^3 < n0*n1*n2`, then integer cube root recovers `m`

Padding prevents this attack.
