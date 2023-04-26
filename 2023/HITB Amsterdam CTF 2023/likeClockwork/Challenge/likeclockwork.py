#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os, time, hashlib
from secrets import randbelow

# Non-native imports
from Crypto.Util.number import getPrime   # pip install pycryptodome

FLAG = os.environ.get('flag', 'poly{mero}')
if type(FLAG) == str:
    FLAG = FLAG.encode()

PSIZE = 1024

p = getPrime(PSIZE)
g = randbelow(p)

class SERVER:
    def __init__(self, bits):
        self.domainPrime = getPrime(bits)
        self.domainGenerator = randbelow(self.domainPrime)
        self.serverSecret = randbelow(self.domainPrime)
        
    def roll(self, x, y):
        y %= PSIZE
        return ((x >> (PSIZE - y)) | (x << y)) % 2**PSIZE
        
    def publicKey(self):
        return pow(self.domainGenerator, self.roll(self.serverSecret, int(time.time()*1000)), self.domainPrime)

server = SERVER(1024)

print('|\n|  ~ Domain ::')
print('|    p =', p)
print('|    g =', g)

otpKey = b''
while len(otpKey) < len(FLAG):
    otpKey += hashlib.sha256(b'OTP::' + str(server.serverSecret).encode() + b'::' + len(otpKey).to_bytes(2, 'big')).digest()

print('|\n|  ~ Encrypted flag ::')
print('|    flag =', bytes([x ^ y for x,y in zip(FLAG, otpKey)]).hex())

print('|\n\  ~ My flag cycles so fast you will have to request the public key often too ^w^')
while True:
    
    try:
    
        input()

        print('|    pk =', server.publicKey())
    
    except KeyboardInterrupt:
        break
        
    except:
        break