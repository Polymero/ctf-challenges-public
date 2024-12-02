#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Elite] Crypto - Trouble in Pairs
#
# by Polymero
#

# Native imports
import os, json, hashlib
from secrets import randbelow
from typing import List, Tuple

# Non-native dependencies
from Crypto.Util.number import getPrime, inverse, isPrime, GCD     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Global parameters
HASH = hashlib.sha256
AALP = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[:]"


# Challenge class
class FiatSchnorr:
    def __init__(self, pbit: int, qbit: int) -> None:
        self.p, self.q = self.__SafePrimeGen(pbit, qbit)
        while True:
            self.g = pow(2, (self.p - 1) // self.q, self.p)
            if pow(self.g, self.q, self.p) == 1:
                break
        self.sk = [randbelow(self.q) for _ in '01']
        self.pk = [pow(self.g, i, self.p) for i in self.sk]
        
    def __repr__(self) -> str:
        return json.dumps({
            'p' : '0x' + self.__Int2Byte(self.p).hex(),
            'q' : '0x' + self.__Int2Byte(self.q).hex(),
            'g' : '0x' + self.__Int2Byte(self.g).hex()
        })
    
    def __Int2Byte(self, x: int) -> bytes:
        return x.to_bytes(-(-len(bin(x)[2:]) // 8), 'big')
    
    def __Hash(self, lst: List[int]) -> int:
        return int.from_bytes(HASH(b''.join([self.__Int2Byte(i) for i in lst])).digest(), 'big')
        
    def __SafePrimeGen(self, pbit: int, qbit: int) -> Tuple[int, int]:
        while True:
            q = getPrime(qbit)
            for k in range(256):
                r = getPrime(pbit - qbit - 1)
                p = (2 * q * r) + 1
                if len(bin(p)[2:]) != pbit:
                    continue
                if isPrime(p):
                    return p, q
                
    def __Encode(self, x: Tuple[int]) -> bytes:
        y = [self.__Int2Byte(i) for i in x]
        z = [len(i).to_bytes(2, 'big') + i for i in y]
        return b"".join(z)
    
    def __Decode(self, x: bytes) -> Tuple[int]:
        y = []
        while x:
            l  = int.from_bytes(x[:2], 'big')
            y += [int.from_bytes(x[2:l+2], 'big')]
            x  = x[l+2:]
        return tuple(y)
        
    def Encrypt(self, m: bytes) -> bytes:
        r, s = [randbelow(self.q) for _ in '01']
        A = pow(self.g, r, self.p)
        B = pow(self.g, s, self.p)
        C = (pow(self.pk[0], r, self.p) * int.from_bytes(m, 'big')) % self.p
        D = (pow(self.pk[1], s, self.p) * int.from_bytes(m, 'big')) % self.p
        u, v = [randbelow(self.q) for _ in '01']
        E = pow(self.g, u, self.p)
        F = pow(self.g, v, self.p)
        G = (pow(self.pk[0], u, self.p) * inverse(pow(self.pk[1], v, self.p), self.p)) % self.p
        t = self.__Hash([E, F, G])
        H = (u + t * r) % self.q
        I = (v + t * s) % self.q
        return self.__Encode((A, B, C, D, E, F, G, H, I))
    
    def Decrypt(self, ct: bytes) -> bytes:
        try:
            A, B, C, D, E, F, G, H, I = self.__Decode(ct)
            t = self.__Hash([E, F, G])
            assert pow(self.g, H, self.p) == (E * pow(A, t, self.p)) % self.p
            assert pow(self.g, I, self.p) == (F * pow(B, t, self.p)) % self.p
            assert (pow(self.pk[0], H, self.p) * inverse(pow(self.pk[1], I, self.p), self.p)) % self.p == (G * pow(C * inverse(D, self.p), t, self.p)) % self.p
            return self.__Int2Byte((C * inverse(pow(A, self.sk[0], self.p), self.p)) % self.p)
        except:
            return b""
        

# Challenge set-up
HDR = r"""|
|   ____  ____  _____  __  __  ____  __    ____ 
|  (_  _)(  _ \(  _  )(  )(  )(  _ \(  )  ( ___)
|    )(   )   / )(_)(  )(__)(  ) _ < )(__  )__)
|   (__) (_)\_)(_____)(______)(____/(____)(____)
|   ____  _  _     ____   __    ____  ____  ___
|  (_  _)( \( )   (  _ \ /__\  (_  _)(  _ \/ __)
|   _)(_  )  (     )___//(__)\  _)(_  )   /\__ \
|  (____)(_)\_)   (__) (__)(__)(____)(_)\_)(___/
|"""
print(HDR)

fiat = FiatSchnorr(1024, 1012)
assert b"T3ST" == fiat.Decrypt(fiat.Encrypt(b"T3ST"))
print("|\n|  FIAT = {}".format(fiat))


# Server loop
TUI = "|\n|  Menu:\n|    [L]eak\n|    [E]val\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input('|  > ').lower()

        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break

        elif choice == 'l':
            leak = fiat.Encrypt(os.urandom(32)).hex()
            print('|\n|  LEAK = {}'.format(leak))

        elif choice == 'e':
            userPacket  = input('|\n|  > (hex) ')
            userDecrypt = fiat.Decrypt(bytes.fromhex(userPacket))
            if all([i in AALP for i in userDecrypt]):
                response = eval(userDecrypt.decode())
            else:
                raise Exception('Invalid decryption')
            print('|\n|  RESP = {}'.format(fiat.Encrypt(response).hex()))

        else:
            print('|\n|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
