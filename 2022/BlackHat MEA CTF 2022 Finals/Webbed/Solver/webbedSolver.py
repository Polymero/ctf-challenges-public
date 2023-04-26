#!/usr/bin/env python3
#
# Polymero
#

# Imports
import requests, time, json

# Server class
class Server:
    def __init__(self, addr):
        self.addr = addr

    def register(self, username):
        ret = requests.get(self.addr + 'register/' + username, allow_redirects=False)
        token = bytes.fromhex(ret.cookies['token'])
        return token

    def login(self, token, username):
        ret = requests.get(self.addr + 'login/' + username, cookies={'token': token}, allow_redirects=True)
        return ret

# Create communication class
s = Server("https://blackhat4-a42aeda8877ecee989372f617039a6fa-0.chals.bh.ctf.sa/")

# Appropriately sized username payload
USER = "polymeeeeeeeeeeero"


k = 0
while True:
    k += 1

    # Get encrypted token
    TOKEN = s.register(USER)
    print(TOKEN.hex())

    # Split encrypted token in 16-byte blocks
    enc_blocks = [TOKEN[i:i+16] for i in range(0, len(TOKEN), 16)]

    target = b'aaa","admin":tru' 
    differ = bytes(i^j for i,j in zip(target, b'", "admin": fals'))

    # Create forged token by XORing the XOR difference with the second to last ciphertext block
    enc_blocks[-3] = bytes(i^j for i,j in zip(enc_blocks[-3], differ))
    forged = b"".join(enc_blocks)

    # Get login response
    resp = s.login(forged.hex(), 'poaaa')

    # Check for succesful login
    if 'Successfully' in resp.text:
        print(resp.text)
        print(k)
        break
