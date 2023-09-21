#!/usr/bin/env python3
#
# by Polymero
#
# for CyberHub CTF 2023
#

# Native imports
import time, requests, base64, json

# Non-native imports
from Crypto.Cipher import AES         # pip install pycryptodome
from Crypto.Util.Padding import pad


def b64enc(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

def b64dec(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + '===')


# Oracle class object
class ORACLE:
    def __init__(self, address: str):
        if address[-1] != '/':
            address += '/'
        self.address = address

    def generateToken(self, username: str) -> str:
        response = requests.get(self.address + 'gettoken/' + username, allow_redirects=False)
        return response.cookies.get('token')
    
    def loadToken(self, token: str) -> str:
        content = requests.get(self.address, cookies={'token': token}, allow_redirects=False).content
        leftIndex = content.index(b'<strong>') + len(b'<strong>')
        rightIndex = content.index(b'</strong>')
        return content[leftIndex:rightIndex].decode()
    
    def getFlag(self, token: str) -> str:
        content = requests.get(self.address, cookies={'token': token}, allow_redirects=False).content
        try:
            leftIndex = content.index(b'Flag{')
            rightIndex = leftIndex + content[leftIndex:].index(b'}') + 1
            return content[leftIndex:rightIndex].decode()
        except:
            return content.decode()


oracle = ORACLE('http://127.0.0.1:5000/')

username = 'poly' * 8
# tokenPlaintext = json.dumps({
#     'username' : username,
#     'admin'    : False
# }).encode()
tokenPlaintext = json.dumps({
    'admin'    : False,
    'username' : username
}).encode()


token = oracle.generateToken('poly'*8)
print(token)

tokenIV, tokenCiphertext = b64dec(token)[:16], b64dec(token)[16:]

recoveredKey = []
for _ in range(16):

    for x in range(256):
        print(x, end='\r', flush=True)

        xor  = bytes([i ^ j for i,j in zip(recoveredKey, b' ' * 16)])
        xor += bytes([x])
        xor += b'\x00' * 16

        forgedIV = bytes([i ^ j ^ k for i,j,k in zip(tokenCiphertext[:16], tokenPlaintext[16:32], xor)])
        forgedCiphertext = tokenCiphertext[16:]
        forgedToken = b64enc(forgedIV + forgedCiphertext)

        responseFlash = oracle.loadToken(forgedToken)

        if 'invalid start byte' in responseFlash:

            try:

                if int(responseFlash[68:68+responseFlash[68:].index(':')]) == len(recoveredKey):

                    recoveredKey += [x ^ int(responseFlash[53:55], 16)]
                    print(recoveredKey)
                    break

            except:
                print('Error,', responseFlash)

forgedAES = AES.new(bytes(recoveredKey), AES.MODE_CBC, bytes(recoveredKey))
forgedAdminToken = b'\x00'*16 + forgedAES.encrypt(pad(json.dumps({
    'username' : 'poly',
    'admin'    : True
}).encode(), 16))

print(oracle.getFlag(b64enc(forgedAdminToken)))