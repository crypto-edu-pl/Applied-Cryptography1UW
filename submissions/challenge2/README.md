# Cryptopals Challenges 33, 34, 40

Solutions to three cryptopals challenges.

## Requirements

- Python 3.8+
- pycryptodome
- sympy

```bash
pip install pycryptodome sympy
```

## Challenges

### Challenge 33: Implement Diffie-Hellman

Implements DH key exchange with small parameters (p=37) and NIST 1024-bit parameters.

```bash
python challenge33.py
```

### Challenge 34: MITM Key-Fixing Attack

Demonstrates MITM attack where attacker replaces public keys with p, forcing shared secret to 0.

```bash
python challenge34.py
```

### Challenge 40: E=3 RSA Broadcast Attack

Demonstrates Hastad's broadcast attack using CRT to recover plaintext from 3 ciphertexts.

```bash
python challenge40.py
```