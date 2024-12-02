#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# SOLVE SCRIPT :: [Easy] Crypto - Trypanophobia
#
# by Polymero
#

# Native imports
import json
import time

from Crypto.Util.number import inverse, getPrime  # pip install pycryptodome
# Non-native imports
from pwn import connect, process  # pip install pwntools

# Sage imports
...     # sage --python solver.py

# Local imports
...


# Functions
def LegendreSymbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == (p - 1) else ls

def ModularSqrt(a, p):
    if LegendreSymbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while LegendreSymbol(n, p) != -1:
        n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)
        if m == 0:
            return x
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


# Oracle class object
class Oracle:
    def __init__(self, s):
        self.s = s

    # Connection methods

    @staticmethod
    def Process(file: str, py: str = 'python3') -> object:
        return Oracle(process([py, file]))
    
    @staticmethod
    def Netcat(host: str, port: int) -> object:
        return Oracle(connect(host, port))
    
    @staticmethod
    def Snicat(host: str, port: int = 443) -> object:
        return Oracle(connect(host, port, ssl=True, sni=host))
    
    def Close(self) -> None:
        self.s.close()

    # Interaction methods
    
    def Inject(self, p, q) -> None:
        self.s.recv()
        self.s.sendline(b'A')
        self.s.recv()
        self.s.sendline(json.dumps({'p': p, 'q': q}).encode())

    def EncryptFlag(self) -> int:
        self.s.recv()
        self.s.sendline(b'E')
        self.s.recvuntil(b'Flag = 0x')
        return int(self.s.recvuntil(b'\n', drop=True), 16)


# Challenge parameters
...

# Solver parameters
#context.log_level = 'debug'

def Stepify(stepstr, runtime):
    dt = int(time.time() - runtime)
    return '|\n|  ({}m {}s) {}'.format(dt // 60, dt % 60, stepstr)


# Start
RUNTIME = int(time.time())
print("|\n|  ~ SOLVE SCRIPT for 'Trypanophobia'")

while True:
    try:

        # STEP 0
        print(Stepify('Connecting to challenge server...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('127.0.0.1', 5000)


        # STEP 1 
        print(Stepify('Generating any two primes and injecting them into the server key, twice...', RUNTIME))

        P, Q = [getPrime(1024) for _ in range(2)]

        oracle.Inject(P, Q)
        encOne = oracle.EncryptFlag()

        oracle.Inject(P, Q)
        encTwo = oracle.EncryptFlag()


        # STEP 2
        print(Stepify('Recovering padding value...', RUNTIME))
        padding = None

        padPower8 = pow( inverse(encOne, P) * encTwo, inverse(0x10001, P-1), P )

        powers = [padPower8]
        for _ in range(3):

            sroots = []
            for x in powers:

                y = ModularSqrt(x, P)

                if 0 < y < P:
                    sroots += [y, P - y]

            powers = sroots[:]

        possiblePads = [i for i in powers if len(bin(i)) <= (256 + 2)]

        if len(possiblePads) == 1:
            padding = possiblePads[0]
            print('|    pad = {}'.format(padding))

        else:
            print('|    Failed to recover padding, retrying...\n|')
            oracle.Close()
            continue

        
        # STEP 3
        print(Stepify('Recovering flag...', RUNTIME))

        for k in range(8, 24):
            flag = ( inverse(pow(padding, k, P), P) * pow(encOne, inverse(0x10001, P-1), P) ) % P
            flag = flag.to_bytes(-(-len(bin(flag)[2:]) // 8), 'big')
            if b'BHFlagY' in flag:
                break

        if b'BHFlagY' in flag:
            print('|    flag = {}'.format(flag))
            break

        else:
            print('|    Failed to recover flag, retrying...\n|')
            oracle.Close()
            continue

    except Exception as e:
        print(e)
        break


# End
print(Stepify('Script END.\n', RUNTIME))
oracle.Close()
