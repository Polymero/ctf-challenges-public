#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Hard] Crypto - Ping Pong
#


# Native imports
import os, hashlib

# Non-native imports
from Crypto.Util.number import inverse, isPrime, GCD     # pip install pycryptodome


# Set-up parameters
SIZES = (1024, 256)


# Crypto class
class PingPong:
    def __init__(self) -> object:
        self.sizes = None
        self.longPublic = None
        self.longSecret = None
        self.longDomain = None
        self.shortPublic = None
        self.shortSecret = None
        self.shortDomain = None

    @staticmethod
    def new(l: int, n: int, seed: bytes = None) -> object:
        if seed is None:
            seed = os.urandom(32)
        obj = PingPong()
        obj.sizes = (l, n)
        p, q, seeds = obj.RandomDomain(l, n, seed)
        longGenerator = obj.RandomGenerator(p, q, seeds, 1)
        obj.longDomain = {'p': p, 'q': q, 'g': longGenerator}
        obj.longSecret, obj.longPublic, _ = obj.RandomKey()
        return obj
    
    @staticmethod
    def load(domain: dict) -> object:
        obj = PingPong()
        assert set(domain) == {'p', 'q', 'g'}
        assert 1 < domain['g'] < domain['p'] - 1
        assert pow(domain['g'], domain['q'], domain['p']) == 1
        obj.sizes = tuple([len(bin(i)) - 2 for i in [domain['p'], domain['q']]])
        obj.longDomain = domain
        obj.longSecret, obj.longPublic, _ = obj.RandomKey()
        return obj
    
    def ShaweTaylorRandomPrime(self, bits: int, seed: bytes) -> (int, int, int):
        if type(seed) == bytes:
            seed = int.from_bytes(seed, 'big')
        if bits <= 32:
            pseed = seed
            pcntr = 0
            while True:
                c = int.from_bytes(bytes([i ^ j for i,j in zip(
                    hashlib.sha256(str(pseed).encode()).digest(),
                    hashlib.sha256(str(pseed + 1).encode()).digest()
                )]), 'big')
                c = 2**(bits - 1) + (c % 2**(bits - 1))
                c = (2 * (c // 2)) + 1
                pseed += 2
                pcntr += 1
                if isPrime(c):
                    return c, pseed, pcntr
        c0, pseed, pcntr = self.ShaweTaylorRandomPrime(-(-bits // 2) + 1, seed)
        iters = -(-bits // 256) - 1
        x = 0
        for i in range(iters):
            x += int.from_bytes(hashlib.sha256(str(pseed + i).encode()).digest(), 'big') * 2**(i * 256)
        pseed += iters + 1
        x = 2**(bits - 1) + (x % 2**(bits - 1))
        t = -(-x // (2 * c0))
        while True:
            if (2 * t * c0 + 1) > 2**bits:
                t = -(-2**(bits - 1) // (2 * c0))
            c = 2 * t * c0 + 1
            a = 0
            for i in range(iters):
                a += int.from_bytes(hashlib.sha256(str(pseed + i).encode()).digest(), 'big') * 2**(i * 256)
            pseed += iters + 1
            pcntr += 1
            a = 2 + (a % (c - 3))
            z = pow(a, 2 * t, c)
            t += 1
            if (GCD(z - 1, c) == 1) and (pow(z, c0, c) == 1):
                return c, pseed, pcntr
            
    def RandomDomain(self,  l: int, n: int, seed: bytes) -> (int, int, tuple):
        if type(seed) == bytes:
            seed = int.from_bytes(seed, 'big')
        q, qseed, qcntr = self.ShaweTaylorRandomPrime(n, seed)
        p0, pseed, pcntr = self.ShaweTaylorRandomPrime(-(-l // 2) + 1, qseed)
        iters = -(-l // 256) - 1
        x = 0
        for i in range(iters):
            x += int.from_bytes(hashlib.sha256(str(pseed + 1).encode()).digest(), 'big') * 2**(i * 256)
        pseed += iters + 1
        x = 2**(l - 1) + (x % (2**(l - 1)))
        t = -(-x // (2 * q * p0))
        while True:
            if (2 * t * q * p0 + 1) > 2**l:
                t = -(-2**(l - 1) // (2 * q * p0))
            p = 2 * t * q * p0 + 1
            a = 0
            for i in range(iters):
                a += int.from_bytes(hashlib.sha256(str(pseed + i).encode()).digest(), 'big') * 2**(i * 256)
            pseed += iters + 1
            pcntr += 1
            a = 2 + (a % (p - 3))
            z = pow(a, 2 * t * q, p)
            t += 1
            if (GCD(z - 1, p) == 1) and (pow(z, p0, p) == 1):
                return p, q, (seed, pseed, qseed)
            
    def RandomGenerator(self, p: int, q: int, seeds: tuple, index: int) -> int:
        assert 0 <= index < 256
        gseed = b''.join(i.to_bytes(128, 'big') for i in seeds)
        n = len(bin(q)[2:])
        e = (p - 1) // q
        cntr = 0
        while True:
            cntr += 1
            u = gseed + b'ggen' + index.to_bytes(1, 'big') + cntr.to_bytes(2, 'big')
            w = int.from_bytes(hashlib.sha256(u).digest(), 'big')
            g = pow(w, e, p)
            if g > 1:
                return g
            
    def RandomKey(self) -> (int, int, int):
        if self.shortDomain is None:
            domain = self.longDomain
        else:
            domain = self.shortDomain
        n = len(bin(domain['q'])[2:])
        c = int.from_bytes(os.urandom(-(-n // 8) + 16), 'big')
        x = (c % (domain['q'] - 1)) + 1
        y = pow(domain['g'], x, domain['p'])
        return x, y, inverse(x, domain['q'])
            
    def initiate(self) -> (int, (int, int)):
        if self.shortDomain is None:
            baseSecret, domain = self.longSecret, self.longDomain
        else:
            baseSecret, domain = self.shortSecret, self.shortDomain
        selfSecret, sigR, selfInverse = self.RandomKey()
        sigHash = int.from_bytes(hashlib.sha256(str(sigR).encode()).digest(), 'big')
        sigS = (selfInverse * (sigHash + baseSecret * sigR)) % domain['q']
        return selfSecret, (sigR, sigS)
    
    def receive(self, selfSecret: int, otherPublic: int, signature: (int, int)) -> int:
        if self.shortDomain is None:
            domain = self.longDomain
        else:
            domain = self.shortDomain
        sigR, sigS = signature
        assert (0 < sigR < domain['p']) and (0 < sigS < domain['q']) and (0 < otherPublic < domain['p'])
        sigHash = int.from_bytes(hashlib.sha256(str(sigR).encode()).digest(), 'big')
        u = (sigHash * inverse(sigS, domain['q'])) % domain['q']
        v = (sigR * inverse(sigS, domain['q'])) % domain['q']
        w = (pow(domain['g'], u, domain['p']) * pow(otherPublic, v, domain['p'])) % domain['p']
        assert sigR == w
        sharedSecret = pow(sigR, selfSecret, domain['p'])
        if self.shortDomain is None:
            p, q, seeds = self.RandomDomain(*self.sizes, sharedSecret)
            self.shortDomain = {'p': p, 'q': q, 'g': self.RandomGenerator(p, q, seeds, 1)}
            self.shortSecret, self.shortPublic, _ = self.RandomKey()
            return None
        else:
            return sharedSecret