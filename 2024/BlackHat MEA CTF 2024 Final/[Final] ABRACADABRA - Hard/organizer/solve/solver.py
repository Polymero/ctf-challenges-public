#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# SOLVE SCRIPT :: [Hard] Crypto - Abracadabra
#
# by Polymero
#

# Native imports
import hashlib
import json
import time
from typing import List, Dict

from Crypto.Util.number import isPrime, getPrime  # pip install pycryptodome
# Non-native dependencies
from pwn import connect, process  # pip install pwntools
# Sage imports
from sage.all import Primes, prod  # run "sage --python3 solve.py"

# Global parameters
HASH = hashlib.sha256


# Timing functions
def Stepify(stepstr: str, runtime: float) -> str:
    dt = int(time.time() - runtime)
    return '|\n|  ({}m {}s) {}'.format(dt // 60, dt % 60, stepstr)

# Helper functions
def GenGenerator(p: int, qlst: List[int]) -> int:
    g = 2
    while True:
        if (not any([pow(g, (p - 1) // qi, p) == 1 for qi in qlst])) and (pow(g, p - 1, p) == 1):
            break
        g += 1
    return g
    
# Solver functions
def SmallPhiPrimeWithBoundSubgroup(pbit: int, qbit: int) -> int:
    """ Randomly generates a prime (pbit bits) with small euler totient and minimum prime subgroup (qbit bits). """
    while True:
        pset = Primes()
        qlst = [pset(2)]
        while prod(qlst) < 2**(pbit - qbit):
            qlst += [pset.next(qlst[-1])]
        q = prod(qlst[:-1])
        for k in range(256):
            r = getPrime(int(1 + pbit - len(bin(q)[2:])))
            if r < 2**qbit:
                continue
            p = int((q * r) + 1)
            if len(bin(p)[2:]) != pbit:
                continue
            if isPrime(p):
                break
        if k == 255:
            continue
        return int(p), qlst[:-1] + [r]


# Oracle class object
class Oracle:
    def __init__(self, s: object) -> None:
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

    def SendDomain(self, domain: Dict[str, int]) -> None:
        self.s.recv()
        self.s.sendline(json.dumps(domain).encode())

    def GetFlag(self) -> str:
        self.s.recvuntil(b'ABRACADABRA')
        resp = self.s.recv()
        if b'Wait, NO!?' in resp:
            resp = resp[resp.index(b'sk = ') + 5:]
            resp = resp[:resp.index(b'\n')]
            return resp.decode()
        return ''


# Challenge parameters
TRIES  = 512

# Solver parameters
...

# To see all traffic uncomment the line below
# context.log_level = 'debug'


# Start
LOOPNUM = 0
RUNTIME = int(time.time())

while True:
    try:

        LOOPNUM += 1
        print("|\n|  [~] SOLVE SCRIPT for 'ABRACADABRA' (try {})".format(LOOPNUM))


        # STEP 0
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('34.252.33.37', '32291')

        # STEP 1
        print(Stepify('Generate prime with small euler totient...', RUNTIME))

        p, qlst = SmallPhiPrimeWithBoundSubgroup(1024, 6)
        fqr = float(prod([i - 1 for i in qlst]) / (p - 1))
        avg = round( 1 / (1 - (1 - (1 - fqr**2)**TRIES)))

        print('|\n|  [~] Successfully generated:\n|    p / q = {:.8f}\n|    requiring about {} tries.'.format(fqr, avg))


        # STEP 3
        print(Stepify('Generate correct generator of subgroup p - 1...', RUNTIME))

        g = GenGenerator(p, qlst)
        domain = {
            'p' : int(p),
            'g' : int(g),
            'q' : [int(i) for i in qlst]
        }

        oracle.SendDomain(domain)


        # STEP 4
        print(Stepify('Await magic trick...', RUNTIME))

        FLAG = oracle.GetFlag()

        if FLAG:
            print('|\n|  FLAG = {}\n|\n|  [~] Done ~ !'.format(FLAG))

        else:
            print('|\n|  [!] Failed to recover the flag, trying again...')
            oracle.Close()
            continue


        break

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
        break


# End
print(Stepify('Script END after try {}.\n'.format(LOOPNUM), RUNTIME))
oracle.Close()
