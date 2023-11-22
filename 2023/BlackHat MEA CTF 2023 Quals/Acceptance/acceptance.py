#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Quals
#
# [Medium] Crypto - Acceptance
#


# Native imports
from secrets import randbelow
import hashlib

# Non-native imports
from Crypto.Util.number import getStrongPrime     # pip install pycryptodome


# Domain parameters
P = getStrongPrime(1024)
G = randbelow(P)
assert pow(G, P-1, P) == 1


# Council member class
class Member:
    def __init__(self, public: int = 0):
        if public:
            assert 1 < public < (P - 1)
            self.private = None
            self.public = public
        else:
            self.private = randbelow(P)
            self.public  = pow(G, self.private, P)
        self.r = None
        
    def __aggregate(self, members):
        key = 1
        for member in members:
            key *= member.public
            key %= P
        return key

    def __hash(self, ctx, inputs):
        x = [str(ctx).encode()]
        for y in inputs:
            if isinstance(y, int):
                x += [y.to_bytes(-(-y.bit_length() // 8), 'big')]
            elif isinstance(y, bytes):
                x += [y]
            else:
                x += [str(y).encode()]
        return hashlib.sha256(b'::'.join(x)).digest()
    
    def generateCommitment(self):
        self.r = randbelow(P)
        R = pow(G, self.r, P)
        t = self.__hash('COM', [R]).hex()
        return R, t
    
    def verifyCommitments(self, R, t):
        return all(t[i] == self.__hash('COM', [R[i]]).hex() for i in range(max(len(R), len(t))))

    def generateSignature(self, members, R, m):
        x = 1
        for i in R:
            x *= i
            x %= P
        c = self.__hash('SIG', [self.__aggregate(members), x, m])
        s = (self.r + int.from_bytes(c, 'big') * self.private) % (P - 1)
        self.r = None
        return s
    
    def verifySignature(self, sig):
        assert set(sig) == {'L', 'R', 'S', 'm'}
        L, R, S = [int(sig[i], 16) for i in 'LRS']
        c = int.from_bytes(self.__hash('SIG', [L, R, sig['m']]), 'big')
        return pow(G, S, P) == (R * pow(L, c, P)) % P