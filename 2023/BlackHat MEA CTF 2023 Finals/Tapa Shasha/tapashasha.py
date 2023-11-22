#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Hard] Crypto - Tapa Shasha
#


# Native imports
from secrets import randbelow
from random import shuffle
import os

# Non-native imports
from Crypto.Util.number import getPrime, inverse


# Set-up parameters
BITSEC = 64
NMAX   = 16


# Polynomial class
class Polynomial:
    
    def __init__(self, c: list, m: int) -> object:
        while c and not c[0]:
            c = c[1:]
        self.c = [i % m for i in c]
        self.m = m
        
    def __call__(self, x: int) -> int:
        return sum(j * pow(x, i, self.m) for i,j in enumerate(self.c[::-1])) % self.m
    
    def __repr__(self) -> str:
        if self.c:
            s  = ' + '.join('{} x^{}'.format(j, len(self.c)-i-1) for i,j in enumerate(self.c[:-1])) 
            s += ' + ' + str(self.c[-1])
        else:
            s = '0'
        return s + ' mod ' + str(self.m)
    
    def __getitem__(self, i: int) -> int:
        return self.c[::-1][i]
    
    def __len__(self) -> int:
        return len(self.c)
    
    def __add__(self, other: object) -> object:
        assert self.m == other.m
        c1 = self.c
        c2 = other.c
        if len(c1) > len(c2):
            c2 = [0]*(len(c1)-len(c2)) + c2
        else:
            c1 = [0]*(len(c2)-len(c1)) + c1
        return Polynomial([(i + j) % self.m for i,j in zip(c1, c2)], self.m)
    
    def __mul__(self, other: int or object) -> object:
        if isinstance(other, int):
            return self.__rmul__(other)
        assert self.m == other.m
        c1 = self.c
        c2 = other.c
        c3 = [0]*(len(c1) + len(c2) - 1)
        for i in range(len(c1)):
            for j in range(len(c2)):
                c3[i + j] += (c1[i] * c2[j]) % self.m
        return Polynomial(c3, self.m)
    
    def __rmul__(self, k: int) -> object:
        return Polynomial([(i * k) % self.m for i in self.c], self.m)
    
    def cmul(self, other: object) -> object:
        assert self.m == other.m
        c1 = self.c
        c2 = other.c
        if len(c1) > len(c2):
            c2 = [0]*(len(c1)-len(c2)) + c2
        else:
            c1 = [0]*(len(c2)-len(c1)) + c1
        return Polynomial([(i * j) % self.m for i,j in zip(c1, c2)], self.m)
    
    def copy(self) -> object:
        return Polynomial(self.c, self.m)
    
    
# Crypto class
class TapaShasha:
    
    def __init__(self, bitSec: int, nMax: int) -> None:
        self.q = getPrime(bitSec)
        while True:
            self.kpos = [randbelow(self.q) for _ in range(nMax)]
            if len(self.kpos) == len(set(self.kpos)):
                break
        while True:
            self.spos = [randbelow(self.q) for _ in range(nMax)]
            if all(i not in self.kpos for i in self.spos):
                if len(self.spos) == len(set(self.spos)):
                    break
        
    def generate(self, secrets: list, n: int, t:int) -> dict:
        assert len(secrets) <= len(self.kpos)
        f = Polynomial([randbelow(self.q) for _ in range(t - len(secrets))], self.q)
        for i in range(len(secrets)):
            f *= Polynomial([1, -self.kpos[i]], self.q)
        for i in range(len(secrets)):
            h = Polynomial([secrets[i]], self.q)
            for j in range(len(secrets)):
                if i != j:
                    h *= Polynomial([1, -self.kpos[j]], self.q)
                    h *= inverse(self.kpos[i] - self.kpos[j], self.q)
            f += h
        shuffle(self.spos)
        sharing = { self.spos[i] : f(self.spos[i]) for i in range(n) }
        sharing['nkt'] = (n, len(secrets), t)
        return sharing
    
    def taper(self, sharing: dict, taper: list) -> dict:
        taperShares = self.generate(taper, len(self.spos), len(self.spos) - sharing['nkt'][2] + 1)
        taperedSharing =  { i : (sharing[i] * taperShares[i]) % self.q for i in list(sharing.keys()) if isinstance(i, int) }
        taperedSharing['nkt'] = (sharing['nkt'][0], sharing['nkt'][1], len(self.spos))
        return taperedSharing
