# Beastly Vault

### Overview
---
Category 		:: Cryptography
Difficulty		:: Insane
Primitive(s)	:: AES-CBC, AES-GCM
Topics			:: Malleability, Web Token, Oracle Creation
Downloads		:: beastly_vault.zip

### Docker
---
Docker type 				:: Python (w/ Flask)
Connection attempts needed 	:: 1
Connection time required   	:: Short, <1 minute

### Inspiration
---
Related papers		:: None
Related challenges	:: Somewhat a follow-up to '[Finals] Crypto - Easy 1' "Webbed"

### Description
---
We now also provide our trusted secure storage service online! However, we would not be ourselves if we did not strive to continuously further improve our services. Therefore, we are developing token authentication on top of our already secure token encryption, to be released in Q1 of 2023!
<!-- insert netcat address -->
<!-- insert file downloads -->

### Exploration Summary
---


### Exploitation Summary
---

Step by step ::
1. Forge a developer privileged token using simple XOR malleability and poor JSON parser;
2. Recover the GCM authentication key of the developer AES-GCM encryption oracle using a re-used nonce attack;
3. Turn the AES-GCM encryption oracle into an ECB encryption oracle;
4. Using the ECB oracle, commence a BEAST attack on encrypted tokens of various lengths in order to recover the vault access code;
5. Forge an admin token using the ECB oracle and the recovered access code;
6. Access the vault and read the flag from the page.