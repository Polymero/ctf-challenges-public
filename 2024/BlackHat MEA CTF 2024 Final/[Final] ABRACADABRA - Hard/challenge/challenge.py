#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Hard] Crypto - Abracadabra
#
# by Polymero
#

# Native imports
import os, json, hashlib
from secrets import randbelow
from typing import List, Tuple

# Non-native imports
from Crypto.Util.number import inverse, GCD, isPrime     # pip install pycryptodome

# Local imports
from MAGIC_POWERS import MAGIC_FUNCTION

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Global parameters
HASH = hashlib.sha256


# Functions & Classes
class Signer:
    def __init__(self, p: int, q: List[int], g: int, s: int) -> None:
        if not self.__CheckPrime(p):
            raise ValueError('Invalid prime')
        if not self.__CheckFactors(p, q):
            raise ValueError('Invalid (p - 1) factors')
        if not self.__CheckGenerator(p, g, q):
            raise ValueError('Invalid generator')
        self.p, self.g = p, g
        self.__k, self.__r = 0, pow(g, s, p)
        self.__sk, self.pk = None, None
    
    @classmethod
    def new(cls, p: int, q: List[int], g: int, s: int) -> Tuple[int, object]:
        obj = cls(p, q, g, s)
        sk, pk = obj.__KeyGen()
        obj.__sk, obj.pk = sk, pk
        return sk, obj
        
    def __repr__(self) -> str:
        return json.dumps({
            'p'  : '0x' + self.p.to_bytes(128, 'big').hex().strip('0').upper(),
            'g'  : '0x' + self.g.to_bytes(128, 'big').hex().strip('0').upper(),
            'pk' : '0x' + self.pk.to_bytes(128, 'big').hex().strip('0').upper()
        })
        
    def __CheckPrime(self, p: int) -> bool:
        return isPrime(p) and (len(bin(p)[2:]) == 1024)
    
    def __CheckFactors(self, p: int, q: List[int]) -> bool:
        x = 1
        for i in q:
            x *= i
        return p == x + 1
        
    def __CheckGenerator(self, p: int, g: int, q: List[int]) -> bool:
        return (1 < g < p - 1) and (not any([pow(g, (p - 1) // i, p) == 1 for i in q]))
    
    def __Hash(self, m: str) -> int:
        return int.from_bytes(HASH(m.encode()).digest(), 'big')
    
    def __Ratchet(self) -> int:
        if not self.__k:
            self.__k = randbelow(self.p - 1)
        while True:
            self.__k = pow(self.__r, self.__k, self.p)
            if GCD(self.__k, self.p - 1) == 1:
                break
        self.__k = inverse(self.__k, self.p - 1)
        return self.__k
    
    def __KeyGen(self) -> Tuple[int, int]:
        while True:
            sk = randbelow(self.p - 1)
            pk = pow(self.g, sk, self.p)
            if pk > 1:
                break
        return sk, pk
    
    def Sign(self, m: str) -> str:
        h = self.__Hash(m)
        k = self.__Ratchet()
        r = pow(self.g, k, self.p)
        assert GCD(k, self.p - 1) == 1
        s = (inverse(k, self.p - 1) * (h - self.__sk * r)) % (self.p - 1)
        return json.dumps({
            'm' : m,
            'r' : '0x' + r.to_bytes(128, 'big').hex().upper(),
            's' : '0x' + s.to_bytes(128, 'big').hex().upper()
        })
    
    def Verify(self, sig: str) -> bool:
        sig = json.loads(sig)
        assert sig.keys() == {'m', 'r', 's'}
        r, s = [int(sig[i], 16) for i in 'rs']
        u = pow(self.g, self.__Hash(sig['m']), self.p)
        v = pow(r, s, self.p)
        w = pow(self.pk, r, self.p)
        return all([
            0 < r < self.p,
            0 < s < self.p - 1,
            u == (v * w) % self.p
        ])


# Challenge parameters
TRIES  = 512
RNGBASE = randbelow(2**1023)

# Challenge set-up
HDR = r"""|
|    _____________  ______  ____________________________  _____________  ______  _______
|   (___________  \(_____ \(____________________________)(___________  \(_____ \(_______)
|    ___________)  )_____) )________       ________     _____________)  )_____) )_______
|   |  ___    __  (|  __  /|  ___   |     |  ___   |   /    ___    __  (|  __  /|  ___  |
|   | |   |  |__)  ) |  \ \| |   |  |_____| |   |  |__/ /| |   |  |__)  ) |  \ \| |   | |
|   |_|   |_______/|_|   \___|   |_\______)_|   |______/ |_|   |_______/|_|   \___|   |_|
|
|                             ~~~ Wanna see a MAGIC trick ? ~~~
|"""
print(HDR)


# Server loop
print("""|\n|  ~ Over which DOMAIN would you like to see this trick?
|    DOMAIN = {
|      (int)       p : 1024-bit prime
|      (List[int]) q : all factors of p - 1
|      (int)       g : multiplicative generator of Zp with order p - 1, i.e. primitive root of p
|    }""")

while True:
    try:

        userDomain = json.loads(input('|\n|  > (JSON) '))

        if userDomain.keys() != {'p', 'q', 'g'}:
            raise ValueError('Incorrect domain format')

        sk, signer = Signer.new(userDomain['p'], userDomain['q'], userDomain['g'], RNGBASE)

        break

    except ValueError as err:
        print('|\n|  [!] ERROR : {}'.format(err))

print("""|\n|  ~ Alright, take this key...
|    KEY = {{
|      pk = {}
|      sk = {}
|    }}""".format(signer.pk, sk))


print("""|\n|\n|  ~ Now I will take your key... 
|\n|  ...generate {} signatures without looking...
|\n|  ...and MAGICALLY steal your private key ~ !!!""".format(TRIES))

print("|\n|\n|  ~ Suspense ::")

signatures = []
for k in range(TRIES):

    if not TRIES % int(TRIES / 64):
        l = round(64 * k / TRIES)
        print('|   Suspense meter :: >' + l*'█' + (64 - l)*' ' + '<', end='\r', flush=True)

    m = os.urandom(16).hex()
    signatures.append(signer.Sign(m))

print('|   Suspense meter :: >' + l*'█' + (64 - l)*' ' + '<')


stolenSecret = MAGIC_FUNCTION(signatures, signer.pk, signer.p, signer.g, RNGBASE)

if stolenSecret:
    assert stolenSecret == sk

print("""|\n|  ~ ABRACADABRA, is this your PRIVATE key?
|    sk = {}
|""".format(stolenSecret if stolenSecret else FLAG.decode()))

if stolenSecret:
    print("|\n|  ~ Tadaa, you are right to be amazed, GOODBYE! *POOFS AWAY in VICTORY*\n|\n|")
else:
    print("|\n|  ~ Wait, NO!? How did THAT get there? *POOFS AWAY in SHAME*\n|\n|")

