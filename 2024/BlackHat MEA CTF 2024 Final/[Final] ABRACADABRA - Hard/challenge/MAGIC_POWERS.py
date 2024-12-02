#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Hard] Crypto - Abracadabra
#
# by Polymero
#

# Native imports
import json, hashlib
from typing import List

# Non-native dependencies
from Crypto.Util.number import GCD, inverse


# Global parameters
HASH = hashlib.sha256


# Functions
def Hash(m: str) -> int:
    return int.from_bytes(HASH(m.encode()).digest(), 'big')

def MAGIC_FUNCTION(signatures: List[str], publicKey: int, p: int, g: int, s: int):
    
    for i in range(len(signatures) - 1):

        sigA, sigB = [json.loads(signatures[i + j]) for j in range(2)]

        ri = int(sigA['r'], 16)
        rn = int(sigB['r'], 16)
        sn = int(sigB['s'], 16)

        mn = sigB['m']
        hn = Hash(mn)

        if GCD(rn, p - 1) != 1:
            continue

        if GCD(pow(ri, s, p), p - 1) != 1:
            continue

        u = inverse(rn, p - 1)
        v = inverse(pow(ri, s, p), p - 1)
        w = (hn - sn * v) % (p - 1)
        
        x = (u * w) % (p - 1)
        y = pow(g, x, p)

        # Success
        if y == publicKey:
            return x
        
    # Fail
    return 0

        
