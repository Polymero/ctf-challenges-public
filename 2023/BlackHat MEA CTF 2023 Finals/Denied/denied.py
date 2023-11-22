#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Medium] Crypto - Denied
#


# Native imports
from secrets import randbelow
import hashlib

# Non-native imports
from Crypto.Util.number import getPrime, isPrime     # pip install pycryptodome


# Set-up parameters
N = 24
while True:
    P = getPrime(1024)
    Q = (P - 1)
    for k in range(2, 256**2):
        while not Q % k:
            Q //= k
    if isPrime(Q):
        break
G = pow(randbelow(P), (P-1)//Q, P)
assert pow(G, Q, P) == 1


# Council member class
class Member:
    def __init__(self, public: int = 0):
        if public:
            assert 1 < public < (P - 1)
            self.private = None
            self.public  = public
        else:
            self.private = randbelow(Q)
            self.public  = pow(G, self.private, P)
            self.state   = int(self.__hash('RNG', [self.private, self.public]).hex(), 16)
            self.poly    = [randbelow(Q) for _ in range(N - 2)]
        self.r       = None
        
    def __aggregate(self, publics):
        key = 1
        for public in publics:
            key *= pow(public, self.__blind(publics, public), P)
            key %= P
        return key
    
    def __blind(self, publics, public):
        return int(self.__hash('AGG', sorted(publics) + [public]).hex(), 16)

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
    
    def __getrand(self):
        self.state = sum([(j * pow(self.state, i, Q)) % Q for i,j in enumerate(self.poly)]) % Q
        return self.state
    
    def generateCommitment(self):
        self.r = self.__getrand()
        R = pow(G, self.r, P)
        t = self.__hash('COM', [R]).hex()
        return R, t
    
    def verifyCommitments(self, R, t):
        return all(t[i] == self.__hash('COM', [R[i]]).hex() for i in range(max(len(R), len(t))))

    def generateSignature(self, publics, R, m):
        x = 1
        for i in R:
            x *= i
            x %= P
        c = self.__hash('SIG', [self.__aggregate(publics), x, m])
        s = (self.r + int.from_bytes(c, 'big') * self.__blind(publics, self.public) * self.private) % Q
        self.r = None
        return s
    
    def verifySignature(self, sig):
        assert set(sig) == {'L', 'R', 'S', 'm'}
        L = [int(sig['L'][i+2:i+258], 16) for i in range(0,len(sig['L'])-2,256)]
        R, S = [int(sig[i], 16) for i in 'RS']
        m = sig['m']
        assert (1 < R < P) and (1 < S < Q)
        c = int.from_bytes(self.__hash('SIG', [self.__aggregate(L), R, m]), 'big')
        return pow(G, S, P) == (R * pow(self.__aggregate(L), c, P)) % P