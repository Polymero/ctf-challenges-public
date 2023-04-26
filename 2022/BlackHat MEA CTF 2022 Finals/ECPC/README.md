# ECPC

### Overview
---
Category 		:: Cryptography
Difficulty		:: Easy / Medium
Primitive(s)	:: ECDSA, Sha256
Topics			:: Length Extension Attack, Public Key Recovery, Curve25519
Downloads		:: ecpc.py

### Docker
---
Docker type 				:: Python
Connection attempts needed 	:: 1
Connection time required   	:: Short

### Inspiration
---
Related papers		:: None
Related challenges	:: None

### Description
---
Don't be intimidated by the elliptic curve, sometimes dealing with problems can be easy peasy.
<!-- insert netcat address -->
<!-- insert file downloads -->

### Exploration Summary
---
The server presents the player with the hash of its ECDSA public key and the flag encrypted using a decisional ECDSA-variant scheme. The player is then allowed to send hex messages to be signed by the server using its ECDSA private key.

### Exploitation Summary
---
With this decisional ECDSA-variant scheme, knowledge of the private key allows encryption, whereas knowledge of the public key allows decryption. The security of the encrypted flag thus fully relies on witholding the public key from an adversary. This security is actualised by prepending the public key string in the hash function step of standard ECDSA, preventing the use of standard public key recovery. However, a hash of the public key is given to the player (as a means of identity) which allows for a length extension attack on the used hash function. This will allow the player to request a signature for a payload with known hash, as calculated by the server, and hence to recover the public key.
s
Step by step ::
1. Deploy a length extension attack on the hashed public key using `1` as inject message for all possible lengths of the public key string;
2. Recover all possible public key points using the above generated payload(s);
3. Find the correct public key by comparing its hash to the given hashed public key;
4. Decrypt the flag using the recovered public key.