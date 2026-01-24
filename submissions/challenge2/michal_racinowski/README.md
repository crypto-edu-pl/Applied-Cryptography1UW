# Coding Challenge #2

Solutions by Michał Racinowski

## Implement Diffie-Hellman (33; easy)

Usage:
```
python3 easy.py
```

The program allows to establish a pair shared symmetric keys with 
another instance of a program or just verify that the two keys match.

## Implement RSA (39; medium)

Usage:
```
python3 medium.py keys/encrypt/decrypt/demo [OPTIONS]
```

One option is to launch a demo (`BITS` can be optionally specified to change key length):
```
python3 medium.py demo [BITS]
```

It demonstrates key generation and then encryption and decryption of a
message.

Another is to generate a key pair and encrypt and decrypt messages:
```
python3 medium.py keys [BITS]
python3 medium.py encrypt [MESSAGE] [E] [N]
python3 medium.py decrypt [MESSAGE] [D] [N]
```

## E=3 RSA Broadcast attack (40; hard)

Usage:
```
python3 hard.py [BITS]
```

The programs generate three RSA keys and then encrypts a message with 
all of them, then attacks them.

The default key length is 2048, but can be adjusted with `BITS` 
parameter. Note that to low a value won't work, because the the 
message will be too long and to high a value will take a long time 
generate the keys.
