#!/usr/local/bin/python
#
# Polymero
#
# GITEX Africa CTF 2023
#


# Native imports
import os, time, hashlib
from secrets import randbelow

# Non-native imports
from Crypto.Util.number import getPrime   # pip install pycryptodome

# Local imports
FLAG = os.environ.get('flag', 'flag{th1s_1s_just_s0m3_d3bug_fl4g}')
if type(FLAG) == str:
    FLAG = FLAG.encode()

# Globals
PSIZE = 512


# Classes
class SERVER:
    def __init__(self, bits):
        while True:
            self.domainPrime = getPrime(bits)
            if (self.domainPrime - 1) % 4:
                break
        self.domainGenerator = randbelow(self.domainPrime)
        self.serverSecret    = randbelow(self.domainPrime)
        
    def roll(self, x, y):
        y %= PSIZE
        return ((x >> (PSIZE - y)) | (x << y)) % 2**PSIZE
        
    def publicKey(self):
        return pow(self.domainGenerator, self.roll(self.serverSecret, int(time.time()*1000)), self.domainPrime)


# Challenge
server = SERVER(PSIZE)

print('|\n|  ~ Domain ::')
print('|    p =', server.domainPrime)
print('|    g =', server.domainGenerator)

otpKey = b''
while len(otpKey) < len(FLAG):
    otpKey += hashlib.sha256(b'OTP::' + str(server.serverSecret).encode() + b'::' + len(otpKey).to_bytes(2, 'big')).digest()

print('|\n|  ~ Encrypted flag ::')
print('|    flag =', bytes([x ^ y for x,y in zip(FLAG, otpKey)]).hex())

print('|\n|  ~ My flag cycles so fast you will not be able to keep up ~ ^w^')


# Server loop
while True:
    try:
    
        input()
        print('|    pk =', server.publicKey())
    
    except KeyboardInterrupt:
        break
        
    except:
        break