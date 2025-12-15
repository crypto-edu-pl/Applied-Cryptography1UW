# The BEAST Attack

**Paper:** https://hpc-notes.soton.ac.uk/talks/bullrun/Beast.pdf

## OpenSSL countermeasures

To disable OpenSSL's BEAST countermeasures in an application, one has to:
* select TLS 1.0 as the protocol version,
* change security level to `0` to allow for insecure ciphers,
* enable the [SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS](https://wiki.openssl.org/index.php/List_of_SSL_OP_Flags#SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) option.

## Relevant standards

[Section 6.2.3.2. of RFC 2246](https://www.rfc-editor.org/rfc/rfc2246#section-6.2.3.2) describes CBC block cipher implementation, defines TLS record structure and provides the following passage:

> Note: With block ciphers in CBC mode (Cipher Block Chaining) the
>       initialization vector (IV) for the first record is generated with
>       the other keys and secrets when the security parameters are set.
>       The IV for subsequent records is the last ciphertext block from
>       the previous record.

Additionally, [section 3 of RFC7366](https://www.rfc-editor.org/rfc/rfc7366#section-3) describes the Encrypt-then-MAC extension, which changes the record structure if selected.
