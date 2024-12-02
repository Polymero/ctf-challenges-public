#!/usr/bin/env python3
#
# BlackHat MEA CTF 2024 - Final
#
# SOLVE SCRIPT :: [Elite] Crypto - Hypsophobia
#
# by Polymero
#

# Native imports
import os, time, json, hashlib, base64
from secrets import randbelow
from typing import List, Tuple, Dict

# Non-native dependencies
from pwn import connect, process, context                          # pip install pwntools
from Crypto.Util.number import GCD, inverse, getPrime, isPrime     # pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Sage imports
from sage.all import ECM, prime_factors, jacobi_symbol, EllipticCurve, GF, crt     # run "sage --python3 solve.py"


# Global parameters
HASH      = hashlib.sha256
RUNTIME   = int(time.time())
CTR_LOOP  = 0
CTR_CALL  = 0
DATA_RECV = 0
DATA_SEND = 0


# Timing functions
def Stepify(stepstr: str, runtime: float) -> str:
    dt = int(time.time() - runtime)
    return '|\n|  ({}m {}s) {}'.format(dt // 60, dt % 60, stepstr)

# Helper functions
def B64Decode(x: bytes) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(x.encode() + b'==='), 'big')

def LCM(x: List[int]) -> int:
    y = (x[0] * x[1]) // GCD(x[0], x[1])
    if len(x) == 2:
        return y
    return LCM(x[2:] + [y])

def Add2Set(k: int, kset: set) -> set:
    while k < 256**2:
        k <<= 1
    while not (k & 1):
        k >>= 1
        if k < 256:
            break
        kset.add(k)
    return kset

def GetKs(k: int, kdic: Dict[int, int]) -> Tuple[int, int]:
    for i in range(1,16):
        if (k << i) in kdic:
            return k, k << i
        if (k >> i) in kdic:
            return k >> i, k
        
def Differ(kx: int, ky: int, x: int, y: int, a: int, b: int) -> int:
    u = (x**2 - a)**2 - 8*b*x
    v = 4*(x**3 + a*x + b)
    ky >>= 1
    while ky != kx:
        un = u**4 - 2*a*u**2*v**2 + a**2*v**4 - 8*b*u*v**3
        vn = 4*u**3*v + 4*a*u*v**3 + 4*b*v**4
        u, v = un, vn
        ky >>= 1
    return y*v - u

def GetTwists(ps: List[int], a: int, b: int) -> List[int]:
    ts = []
    for p in ps:
        Ep = EllipticCurve(GF(p), [a, b])
        Op = Ep.order()
        ts += [p + 1 - Op]
    return ts
    
# Solver functions
def Elevator(x: int, floor: int, n: int, plan = {}) -> Tuple[int, Dict[int, int]]:
    """ Returns the value x taken to the floor-th floor. You know, like an elevator would. """
    if floor in plan:
        return plan[floor], plan
    if floor == 1:
        return x, { floor : x % n }
    u, plan = Elevator(x, floor // 2, n, plan = plan)
    if floor % 2:
        v, plan = Elevator(x, floor // 2 + 1, n, plan = plan)
        y = ((2 * (u * v + A) * (u + v) + 4 * B) * inverse(int(pow(v - u, 2, n)), n) - x) % n
        plan[floor] = y
        return y, plan
    y = ((pow(pow(u, 2, n) - A, 2, n) - 8 * B * u) * inverse(int(4 * (pow(u, 3, n) + A * u + B)), n)) % n
    plan[floor] = y
    return y, plan

def FactorBoundedECM(n: int, b: int) -> List[int]:
    factors = set()
    it = 0
    while it < 3:
        x, y = ECM().one_curve(n, B1 = b)
        if x == 1:
            it += 1
            continue
        factors = factors.union(set(prime_factors(x)))
        n  = y
        it = 0
    return factors.union(set(prime_factors(y)))


# Oracle class object
class Oracle:
    def __init__(self, tube: object) -> None:
        self.tube = tube
        self.recv = 0
        self.send = 0

    # Connection methods

    @classmethod
    def Process(cls, file: str, py: str = 'python3') -> object:
        return cls(process([py, file]))
    
    @classmethod
    def Netcat(cls, host: str, port: int) -> object:
        return cls(connect(host, port))
    
    @classmethod
    def Snicat(cls, host: str, port: int = 443) -> object:
        return cls(connect(host, port, ssl=True, sni=host))

    # Tube interaction methods

    def Recv(self, timeout: int = 10) -> bytes:
        ret = self.tube.recv(timeout=timeout)
        self.recv += len(ret)
        return ret
    
    def RecvUntil(self, end: bytes, drop: bool = True) -> bytes:
        ret = self.tube.recvuntil(end, drop=drop)
        self.recv += len(ret)
        return ret
    
    def SendLine(self, line: bytes) -> None:
        self.tube.sendline(line)
        self.send += len(line) + 1

    def Close(self) -> None:
        self.Recv(timeout=1)
        self.tube.close()

    # Challenge interaction methods

    def Go(self) -> Tuple[int, int]:
        self.Recv()
        self.SendLine(b'g')
        self.RecvUntil(b'floor ')
        x = int(self.RecvUntil(b' ').decode())
        self.RecvUntil(b'BLEUUUURGHHH')
        y = B64Decode(self.RecvUntil(b'\n').decode())
        return x, y


# Challenge parameters
Pn = 64
Pl = 32
Dn = (Pn * Pl) // 8
Up = Dn * Dn

# Solver parameters
...


# To see all traffic uncomment the line below
# context.log_level = 'debug'


# Start
print("|\n|  [~] SOLVE SCRIPT for 'Hypsophobia'")



# STEP -1
# print(Stepify('Doing something...', RUNTIME))

# ...



# Loop
while True:
    try:

        CTR_LOOP += 1
        print("|\n|  [~] Starting solver loop {}...".format(CTR_LOOP))


        # STEP 0
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        #oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('34.252.33.37', 31934)

        print('|\n|  [~] Successfully connected to challenge instance.')



        # STEP 1
        print(Stepify('Collecting data from different floors...', RUNTIME))

        Kgot = []
        Kset = set()
        Kdic = {}
        while True:
            print('|    ...visited {} floors so far'.format(len(Kdic)), end='\r', flush=True)

            k, x = oracle.Go()

            if k in Kdic:
                continue

            Kdic[k] = x

            if k in Kset:
                if len(Kgot) < 2:
                    Kgot += [k]
                    continue
                else:
                    break

            Kset = Add2Set(k, Kset)

        print('|\n|  [~] Found enough data ~ !')


        # STEP 2
        print(Stepify('Sieving through (A, B) to find N... (restart script if too slow!)', RUNTIME))

        k1x, k1y = GetKs(Kgot[0], Kdic)
        k2x, k2y = GetKs(Kgot[1], Kdic)

        RUN = True
        for wa in range(256):

            for wb in range(256):
                print('|    ... A : ({:> 3d}/256), B : ({:> 3d}/256)'.format(wa, wb), end='\r', flush=True)

                d1 = Differ(k1x, k1y, Kdic[k1x], Kdic[k1y], wa, wb)
                d2 = Differ(k2x, k2y, Kdic[k2x], Kdic[k2y], wa, wb)

                n = GCD(d1, d2)
                if n > 2**256:
                    RUN = False
                    break

            if not RUN:
                break

        A, B, N = wa, wb, n

        while not (N % 2):
            N >>= 1

        for i in range(3, 257, 2):
            if not (N % i):
                N //= i

        print('|\n|  [~] Recovered the following parameters:\n|    A = {}\n|    B = {}\n|    N = {}'.format(A, B, N))


        # STEP 3
        print(Stepify('Factoring N...', RUNTIME))

        Ps = list(FactorBoundedECM(N, 2000))

        print('|\n|  [~] Fully factored:\n|    Ps = {}'.format(Ps))


        # STEP 4
        print(Stepify('Finding elliptic twists...', RUNTIME))

        Ts = GetTwists(Ps, A, B)

        print('|\n|  [~] Twists a plenty:\n|    Ts = {}'.format(Ts))


        # FINAL STEP
        print(Stepify('Retrieving flag...', RUNTIME))

        FLAG = b''

        for k in Kdic:

            x = Kdic[k]
            y = (x**3 + A*x + B) % N

            ni = [p + 1 - jacobi_symbol(y, p) * Ts[i] for i,p in enumerate(Ps)]
            di = [inverse(k, i) if GCD(k, i) == 1 else 0 for i in ni]

            ai = [Elevator(x, di[i], Ps[i])[0] if di[i] else 0 for i in range(len(Ps))]
            pi = [Ps[i] if di[i] else 1 for i in range(len(Ps))]

            FLAG = int(crt([int(i) for i in ai], [int(j) for j in pi]))
            FLAG = FLAG.to_bytes(-(-FLAG.bit_length()//8), 'big')

            if any(i in FLAG for i in [b'FlagY', b'FLAG', b'flag']):
                break


        if FLAG:
            print('|\n|  FLAG = {}\n|\n|  [~] Done ~ !'.format(FLAG))

        else:
            print('|\n|  [!] Failed to recover the flag, restarting loop...')

            oracle.Close()
            DATA_RECV += oracle.recv
            DATA_SEND += oracle.send
            continue


        break

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
        break

    except KeyboardInterrupt:
        break


# End
print(Stepify('Script END.', RUNTIME))

try: 
    oracle.Close()
    DATA_RECV += oracle.recv
    DATA_SEND += oracle.send
except: 
    pass

print("""|
|  [~] Solver stats:
|    Loops         : {}
|    Total Calls   : {}
|    Data Received : {:.3f} MB
|    Data Send     : {:.3f} MB
|""".format(CTR_LOOP, CTR_CALL, DATA_RECV/1000000, DATA_SEND/1000000))
