# Ursa Major

by Polymero

for BlackHatMEA 2022 (15-17 Nov)


### Overview
---
Category		:: Cryptography
Difficulty		:: Medium
Primitive(s)	:: RSA
Topics			:: Public Key Recovery, Factorisation
Downloads		:: ursamajor.py


### Docker
---
Docker type				:: Python
Conn attempts needed	:: Few
Conn time required		:: Medium


### Inspiration
---
Related papers		:: None
Related challenges	:: Follow-up on '[Quals] Crypto - Easy 1' "Ursa Minor"


### Description
---
"Ursa Minor is already beautiful, but have you seen its big brother?"
<!-- insert netcat address -->
<!-- insert file downloads -->


### Exploration Summary
---
The server acts as a encryption and decryption RSA oracle with a few important differences. The modulus is constructed using smooth primes, but only a hash of it is shared to the player. Upon connection a flag is encrypted and shared, after which the public exponent is scrambled unpredictably and the server's private key is updated accordingly. The player can scramble the key on request, but it is automatically scrambled after ONE enryption and ONE decryption request.

Points to note ::
1. RSA modulus consists of smooth primes, but is hidden from the players;
2. The server gives a hash of the public key as identification;
3. Key is automatically scrambled after ONE encryption and ONE decryption request.


### Exploitation Summary
---
...

Step by step ::
1. 
2.


### Alternative Solutions
---
1. [Username] :: [Title]
2. [Username] :: [Title]


### CTF Statistics
---
First blood time 	::
Solvers (ordered)	::
Incidents			::
General feedback	::
1.
2.