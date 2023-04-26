# Webbed

### Overview
---
Category 		:: Cryptography
Difficulty		:: Easy
Primitive(s)	:: AES-CBC
Topics			:: Malleability, Web token, JSON parsing
Downloads		:: webbed.zip

### Docker
---
Docker type 				:: Python (w/ Flask)
Connection attempts needed 	:: Few
Connection time required   	:: Short - Medium

### Inspiration
---
Related papers		:: None
Related challenges	:: Somewhat a precursor to '[Finals] Crypto - Insane 1' "Beastly Vault"

### Description
---
Crypto on the web? Let's just hope the spider isn't home.
<!-- insert netcat address -->
<!-- insert file downloads -->

### Exploration Summary
---
The server deploys a Flask web server that can be accessed through any web browser, or through Python's requests module. The website presents a cookie-based login system with custom tokens. A guest can obtain a token through visiting the register sub-page, and login through visiting the login sub-page. It appears admin permissions embedded in the encrypted token are required to obtain the flag.


### Exploitation Summary
---
By taking a long enough username, longer than one block size, we essentially have a free block in our token. As we manipulate the block with the admin permissions due to the malleability of AES-CBC the block before it will be scrambled unpredictably. So we will keep forging tokens using a few free bytes in our malleable block (attached to the username) until the scrambled block is parsable by the JSON parser. This will require a small amount of attempts, nothing excessive.


Step by step ::
1. Obtain a token for a known username;
2. Construct a forged token with a couple free bytes and the correct admin permissions;
3. Iterate over the free bytes until the forged token gets accepted by the login using a predicted username;
4. Grab the flag.
