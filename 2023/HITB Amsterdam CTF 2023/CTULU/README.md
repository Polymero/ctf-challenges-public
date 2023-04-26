# CTULU

by Polymero

for HITB CTF 2023 on (20, 21).04.2023


### Overview
---
Category		:: Cryptography
Difficulty		:: Hard
Type			:: TOY / imp / pzl
Primitive(s)	:: Arazi (DSA, DHE)
Topics			:: Diffie-Hellman Key Exchange, Digital Signature Algorithm, (Extended) Hidden Number Problem, Known Key Security
Downloads		:: ctulu.py


### Docker
---
Docker type					:: Python
Connection attempts needed	:: Significant search required (but can be reduced to just one if necessary)
Connection time required	:: Requires up to few hundreds of interactions plus brute-force time


### Inspiration
---
Related papers		:: 1. D. Brown - A Small Subgroup Attack on Arazi's Key Agreement Protocol
                       2. V. Vassilakis, I. Moscholios, B. Alohali - Security Analysis of Integrated Diffie-Hellman Digital Signature Algorithm Protocols
                       3. NIST - Digital Signature Standard (DSS)
Related challenges	:: None
Build process       :: Challenge build on the native Hidden Number Problem in Arazi with an added difficulty layer


### Description
---
CTULU has come down to us mortals to reign eternal suffering upon us. I sacrificed your flag to try to appease him, sorry about that. Maybe you can get it back?
<!-- insert connection address -->
<!-- insert file downloads -->


### Exploration Summary
---
...

Points to note ::
1. The challenge consists of a two-layered (DH) key exchange protocol based on DSA, where exchanges in the first layer are used to construc the domain of the second layer.
2. The chat functionality uses the shared key material of second layer exchanges without modification as OTP keys, allowing key material recovery through known plaintext.
3. The prime and subsequest DSA domain generation is following NIST standards, so no funny stuff there.
4. Diffie-Hellman based key exchanges have an inherent single LSB secret key leak, which in theory is already detrimental to any DSA scheme.
5. Players are able to generate new first layer domains by reconnecting and have unlimited exchanges in both layers.


### Exploitation Summary
---
...

Step by step ::
1. Reconnect to generate new first layer domains until a domain contains a prime p such that '2^k | p-1' for large enough k to solve HNP over (suggest k >= 7).
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