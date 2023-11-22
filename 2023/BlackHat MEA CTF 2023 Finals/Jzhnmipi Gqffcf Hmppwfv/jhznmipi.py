#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Easy] Crypto - Jzhnmipi Gqffcf Hmppwfv
#

# Native imports
from secrets import randbelow
import os

# Non-native imports
from Crypto.Util.number import getPrime, inverse

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{{{}}}'.format(os.urandom(16).hex()))
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions
def GenerateDouble(primeSet):
    while True:
        pair = [list(primeSet)[randbelow(len(primeSet))] for _ in '01']
        if pair[0] != pair[1]:
            return pair
        
def KeyFromPair(pair):
    private = {
        'p' : pair[0],
        'q' : pair[1],
        'f' : (pair[0] - 1) * (pair[1] - 1)
    }
    public = {
        'n' : pair[0] * pair[1],
        'e' : 0x10001
    }
    private['d'] = inverse(public['e'], private['f'])
    return public, private

def EncryptFromPrimeSet(x: int, primeSet: set):
    pub, _ = KeyFromPair(GenerateDouble(primeSet))
    return pow(x, pub['e'], pub['n']).to_bytes(256, 'big').hex()


# Challenge set-up
PSET = set(getPrime(1024) for _ in range(32))


# Server loop
print('xlfk ::\n{}'.format(EncryptFromPrimeSet(int(FLAG.hex(), 16), PSET)))

while True:
    try:

        x = int(input('thcwa ::\n> (hex) ').lower(), 16)
        assert 0 < x < (2**2048)

        print('gonrel ::\n{}'.format(EncryptFromPrimeSet(x, PSET)))
        

    except KeyboardInterrupt:
        break

    except:
        continue
      