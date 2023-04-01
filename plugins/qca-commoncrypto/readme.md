TODO

QCA Plugin based on Apple's CommonCrypto library

https://www.unix.com/man-page/mojave/3cc/CC_crypto/
https://github.com/apple-oss-distributions/CommonCrypto/tree/CommonCrypto-60198.60.2

Public documentation for this library is pretty thin. It would seem that it is 
distributed with at least some versions of macOS and possibly other Apple OSes.
It also seems to be a wrapper for an XNU cryptography service, which would 
imply that it is able to support hardware acceleration and other system-level
cryptography resources.
