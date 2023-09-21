#!/usr/bin/env python3
#
# by Polymero
#
# for CyberHub CTF 2023
#

# Native imports
import time

# Non-native imports
from Crypto.Util.number import inverse, GCD   # pip install pycryptodome
from pwn import context, connect, process     # pip install pwntools


# Oracle class object
class ORACLE:
    def __init__(self, s):
        self.s = s

    @staticmethod
    def process(file: str, py='python3') -> object:
        return ORACLE(process([py, file]))

    @staticmethod
    def netcat(host: str, port: int) -> object:
        return ORACLE(connect(host, port))

    @staticmethod
    def snicat(host: str, port=443) -> object:
        return ORACLE(connect(host, port, ssl=True, sni=host))
    
    def close(self) -> None:
        self.s.close()

    # Interaction functions

    def getParameters(self) -> tuple:
        self.s.recvuntil(b'n = ')
        rsaPublic = int(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'b = ')
        flagBits = int(self.s.recvuntil(b'\n', drop=True).decode())
        return rsaPublic, flagBits
    
    def getEncryption(self) -> tuple:
        self.s.recv()
        self.s.sendline(b'e')
        self.s.recvuntil(b'e = ')
        rsaExponent = int(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'c = ')
        rsaCiphertext = int(self.s.recvuntil(b'\n', drop=True).decode())
        return rsaExponent, rsaCiphertext
    
    def getEncryptions(self, k: int) -> tuple:
        rsaPairs = []
        for _ in range(k):
            rsaPairs += [self.getEncryption()]
        return tuple(zip(*rsaPairs))
    

# Start
RUNTIME = int(time.time())
print("|\n|  ~ SOLVE SCRIPT for '...'")


# Stage 1
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Searching for two encryptions such that GCD(e1, e2) == 2...'.format(deltaTime // 60, deltaTime % 60))

def ExtendedEuclidean(a: int, b: int) -> tuple:
    if a == 0:
        return b, 0, 1
    r, s, t = ExtendedEuclidean(b % a, a)
    si = t - (b // a) * s
    ti = s
    return r, si, ti

while True:

    #oracle = ORACLE.process('./Challenge/chall.py')
    oracle = ORACLE.netcat('0.0.0.0', 5000)

    rsaPublic, flagBits = oracle.getParameters()

    for _ in range(10):

        rsaExponents, rsaCiphertexts = oracle.getEncryptions(2)

        gcd, x, y = ExtendedEuclidean(*rsaExponents)
        
        if gcd == 2:
            break

    if gcd == 2:
        break

    oracle.close()


# Stage 2
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Reconstructing FLAG**2 mod n...'.format(deltaTime // 60, deltaTime % 60))

if x < y:
    x, y = y, x

flagModSquared  = pow(rsaCiphertexts[0], x, rsaPublic) 
flagModSquared *= pow(inverse(rsaCiphertexts[1], rsaPublic), -y, rsaPublic)
flagModSquared %= rsaPublic


# Stage 3
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Searching for FLAG**2...'.format(deltaTime // 60, deltaTime % 60))

def iSqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

minimumMultiple = (2**(flagBits - 1))**2 // rsaPublic

k = minimumMultiple
while True:

    print(k, end='\r', flush=True)

    flagSquared = flagModSquared + k * rsaPublic
    flag = iSqrt(flagSquared)
    flag = flag.to_bytes(-(-flag.bit_length()//8), 'big')

    if b'Flag' in flag:
        break

    k += 1


# Done
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Done ~ {}'.format(deltaTime // 60, deltaTime % 60, flag.decode()))
