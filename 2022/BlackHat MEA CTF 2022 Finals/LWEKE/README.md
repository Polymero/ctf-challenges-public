# LWEKE

### Overview
---
Category 		:: Cryptography
Difficulty		:: Hard
Primitive(s)	:: LWE
Topics			:: Key Exchange, Leak
Downloads		:: lweke.py

### Docker
---
Docker type 				:: Python
Connection attempts needed 	:: 1
Connection time required   	:: Long, 30 - 60 minutes

### Inspiration
---
Related papers		:: https://eprint.iacr.org/2020/1288.pdf
Related challenges	:: None

### Description
---
LWEKE? More like LWEAK am I right? Hehe...
<!-- insert netcat address -->
<!-- insert file downloads -->

### Exploration Summary
---
The server provides a LWE-based key exchange service with unlimited exchanges using a single key. This key is also used to encrypt the flag using AES, so it will be necessary to recover the private key.


### Exploitation Summary
---
The private key used by the server for the key exchange is constant, not emphereal. For key exchanges this might pose a problem as some protocols leak a, usually, insignificant part of the used private key(s). In this case, the LWE-based key exchange does indeed leak information about the server's private key. In order to succesfully conduct a key exchange, the server will send out information about the diagonal multiplication of its private key with the user's public key. In other words, the information that is leaked depends on the user's public key. By iterating through different public keys, the user will eventually learn enough information to succesfully recover the server's private key.

Step by step ::
1. Collect server public key and encrypted flag;
2. Craft public keys by iteratively increasing a row with a set step size for a set number of times for every row;
3. Obtain information (called the 'signal') by conducting handshakes with the server using the above public keys;
4. Count the times the signal flips bit for the ith row, this is the absolute value of the ith key element;
5. Craft public keys by iteratively increasing the first AND one other row with a set step size for a set number of times for every other row;
6. Obtain the signals by conducting handshakes;
7. Count the times the signal flips bit for the other ith row, if this does not equal the sum of the first and ith absolute key elements, negate the ith key element;
8. Decrypt the flag using both possible recovered private keys.