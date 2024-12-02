#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# SOLVE SCRIPT :: [Elite] Crypto - Trouble in Pairs
#
# by Polymero
#

# Native imports
import hashlib
import json
import time
from secrets import randbelow
from typing import Tuple, Dict

# Non-native dependencies
from Crypto.Util.number import inverse, isPrime  # pip install pycryptodome
from pwn import connect, process  # pip install pwntools

# Global parameters
HASH = hashlib.sha256


# Timing functions
def Stepify(stepstr: str, runtime: float) -> str:
    dt = int(time.time() - runtime)
    return '|\n|  ({}m {}s) {}'.format(dt // 60, dt % 60, stepstr)

# Helper functions
def Int2Byte(x: int) -> bytes:
    return x.to_bytes(-(-len(bin(x)[2:]) // 8), 'big')

def Encode(x: Tuple[int]) -> bytes:
    y = [Int2Byte(i) for i in x]
    z = [len(i).to_bytes(2, 'big') + i for i in y]
    return b"".join(z)
    
def Decode(x: bytes) -> Tuple[int]:
    y = []
    while x:
        l  = int.from_bytes(x[:2], 'big')
        y += [int.from_bytes(x[2:l+2], 'big')]
        x  = x[l+2:]
    return tuple(y)
    
# Solver functions
def DerivePublicKeys(encOne: bytes, encTwo: bytes, dom: Dict[str, int]) -> Tuple[int]:
    encOne, encTwo = Decode(encOne), Decode(encTwo)
    tOne = int.from_bytes(HASH(b''.join([Int2Byte(i) for i in [encOne[4], encOne[5], encOne[6]]])).digest(), 'big')
    aOne = pow(encOne[6] * pow(encOne[2] * inverse(encOne[3], dom['p']), tOne, dom['p']), inverse(encOne[7], dom['q']), dom['p'])
    bOne = (encOne[8] * inverse(encOne[7], dom['q'])) % dom['q']
    tTwo = int.from_bytes(HASH(b''.join([Int2Byte(i) for i in [encTwo[4], encTwo[5], encTwo[6]]])).digest(), 'big')
    aTwo = pow(encTwo[6] * pow(encTwo[2] * inverse(encTwo[3], dom['p']), tTwo, dom['p']), inverse(encTwo[7], dom['q']), dom['p'])
    bTwo = (encTwo[8] * inverse(encTwo[7], dom['q'])) % dom['q']
    yTwo = pow(aOne * inverse(aTwo, dom['p']), inverse(bTwo - bOne, dom['q']), dom['p'])
    yOne = (aOne * pow(yTwo, bOne, dom['p'])) % dom['p']
    return (yOne, yTwo)

def ForgeCiphertext(m: bytes, dom: Dict[str, int], pk: Tuple[int]) -> bytes:
    u, v, w, x, y = [randbelow(dom['q']) for _ in range(5)]
    E, F, G = [pow(dom['g'], i, dom['p']) for i in [u, v, w]]
    H, I = x, y
    t = int.from_bytes(HASH(b''.join([i.to_bytes(-(-len(bin(i)[2:]) // 8), 'big') for i in [E, F, G]])).digest(), 'big')
    z = inverse(t, dom['q'])
    A = pow(pow(dom['g'], x, dom['p']) * inverse(E, dom['p']), z, dom['p'])
    B = pow(pow(dom['g'], y, dom['p']) * inverse(F, dom['p']), z, dom['p'])
    C = (int.from_bytes(m, 'big') * pow(pow(pk[0], x, dom['p']) * inverse(pow(pk[0], u, dom['p']), dom['p']), z, dom['p'])) % dom['p']
    D = (C * inverse(pow(pow(pk[0], x, dom['p']) * inverse(pow(pk[1], y, dom['p']), dom['p']) * inverse(G, dom['p']), z, dom['p']), dom['p'])) % dom['p']
    return Encode((A, B, C, D, E, F, G, H, I))


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

    def GetDomain(self) -> Dict[str, int]:
        self.s.recvuntil(b'FIAT = ')
        dom = json.loads(self.s.recvuntil(b'\n', drop=True).decode())
        for i in dom:
            dom[i] = int(dom[i], 16)
        return dom
    
    def GetLeak(self) -> bytes:
        self.s.recv()
        self.s.sendline(b'l')
        self.s.recvuntil(b'LEAK = ')
        return bytes.fromhex(self.s.recvuntil(b'\n', drop=True).decode())
    
    def GetEvaluate(self, packet: bytes) -> bytes:
        self.s.recv()
        self.s.sendline(b'e')
        self.s.recv()
        self.s.sendline(packet.hex().encode())
        resp = self.s.recvuntil(b'Menu:')
        if b'ERROR' in resp:
            return b''
        if b'RESP = ' in resp:
            resp = resp[resp.index(b'=') + 2:]
            resp = resp[:resp.index(b'\n')]
            return bytes.fromhex(resp.decode())
        raise Exception('Unexpected response')


# Solver parameters
#context.log_level = 'debug'
FLAG_ALP = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_'


# Start
RUNTIME = int(time.time())
print("|\n|  [~] SOLVE SCRIPT for '???'")

while True:
    try:

        # STEP 0
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('34.252.33.37', 31900)


        # STEP 1
        print(Stepify('Collecting domain parameters...', RUNTIME))

        domain = oracle.GetDomain()
        assert isPrime(domain['p'])
        assert isPrime(domain['q'])
        assert pow(domain['g'], domain['q'], domain['p']) == 1


        # STEP 2
        print(Stepify('Deriving public keys...', RUNTIME))

        encOne, encTwo = [oracle.GetLeak() for _ in '01']
        public = DerivePublicKeys(encOne, encTwo, domain)
        assert pow(public[0], domain['q'], domain['p']) == 1
        assert pow(public[1], domain['q'], domain['p']) == 1


        # STEP 3
        print(Stepify('Collecting flag characters...', RUNTIME))
        print('|')

        charMap = { pow(i, domain['q'], domain['p']) : bytes([i]) for i in FLAG_ALP }

        FLAG = b''

        i = -1
        while True:
            i += 1

            forge = ForgeCiphertext('FLAG[{}:{}]'.format(i, i+1).encode(), domain, public)
            feval = Decode(oracle.GetEvaluate(forge))

            FLAG += charMap[pow(feval[2], domain['q'], domain['p'])]

            print('|  FLAG = {}'.format(FLAG.decode()), end='\r', flush=True)

            if FLAG[-1] == ord('}'):
                break

        print('|  FLAG = {}\n|\n|  [~] Done ~ !'.format(FLAG.decode()))


        break

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
        break


# End
print(Stepify('Script END.\n', RUNTIME))
oracle.Close()

