# Tomasz Kwiatkowski

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run a solution

```bash
python 33_sol.py
python 44_sol.py < 44.txt
python 51_sol.py
```

## 33: Diffie-Hellman notes

`33_sol.py` demonstrates basic Diffie-Hellman key exchange and shared secret derivation. Using constants from the statement.

## 44: DSA nonce reuse notes

`44_sol.py` recovers a DSA private key when the signing nonce is reused. Using constants from the statement. File `44.txt` with messages from the statement.

## 51: CRIME attack notes

`51_sol.py` implements two variants of the compression oracle attack:

1. Stream cipher case: try each next character and keep the one that makes the compressed message shortest. There is no block padding, so even small wins show up.
2. CBC case: ciphertext size jumps in 16-byte steps, so small compression wins are hidden. To recover the cookie, the code:
   - Compares each guess to a same-length dummy cookie (`sessionid=XXXX...`).
   - Tries different prefix and suffix padding to line up with block boundaries.
   - Uses a pad that does not compress so extra bytes always change the size.

Incompressible pad source: a deterministic LCG (high-entropy, so hard to compress) using the classic ANSI C `rand()` parameters (`seed = seed * 1103515245 + 12345`) mapped to printable characters.
