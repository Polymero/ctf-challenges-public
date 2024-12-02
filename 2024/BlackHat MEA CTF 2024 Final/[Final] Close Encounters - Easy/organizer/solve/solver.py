#!/usr/bin/env python3
#
#
# SOLVE SCRIPT :: [Easy] Crypto - Close Encounters of the Gorgon Kind
#
# by Polymero
#

# Native imports
import os, time, json, hashlib
from secrets import randbelow
from typing import List, Tuple, Dict

# Non-native dependencies
from pwn import connect, process, context                     # pip install pwntools
from Crypto.Util.number import inverse, isPrime, getPrime     # pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Sage imports
from sage.all import factor, PolynomialRing, Zmod, ideal, crt, ZZ, GF     # run "sage --python3 solve.py"


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
...
    
# Solver functions
...


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

    def GetParams(self) -> Dict[str, int]:
        self.RecvUntil(b'LVL: ')
        LVL = int(self.RecvUntil(b'\n'))
        self.RecvUntil(b'BASKET = ')
        BASKET = int(self.RecvUntil(b','))
        self.RecvUntil(b'SNAKES = ')
        SNAKES = eval(self.RecvUntil(b'\n'))
        return {
            'LVL'    : LVL,
            'BASKET' : BASKET,
            'SNAKES' : SNAKES
        }
    
    def Look(self) -> int:
        self.Recv()
        self.SendLine(b'l')
        self.Recv()
        self.SendLine(b'0')
        self.RecvUntil(b'GAZE = ')
        return int(self.RecvUntil(b'\n'))
    
    def Play(self, key: int) -> bytes:
        key = list(key.to_bytes(SNAKE_BIT*SNAKE_NUM//8, 'big'))
        for _ in range(32):
            self.Recv()
            self.SendLine(str(key.pop(0)).encode())
        return self.RecvUntil(b'}')
    

# Challenge parameters
SNAKE_NUM = 8
SNAKE_BIT = 32
ROUND_NUM = 8   

# Solver parameters
...


# To see all traffic uncomment the line below
# context.log_level = 'debug'


# Start
print("|\n|  [~] SOLVE SCRIPT for '...'")



# STEP -1
print(Stepify('Doing something...', RUNTIME))

...



# Loop
while True:
    try:

        CTR_LOOP += 1
        print("|\n|  [~] Starting solver loop {}...".format(CTR_LOOP))


        # STEP 0
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('blackhat.flagyard.com', 32219)

        print('|\n|  [~] Successfully connected to challenge instance.')



        # STEP 1
        print(Stepify('Doing something...', RUNTIME))

        STUFF = oracle.GetParams()
        print(STUFF)

        LVL = STUFF['LVL']
        BASKET = STUFF['BASKET']
        SNAKES = STUFF['SNAKES']

        pt = 0
        ct = oracle.Look()

        print(pt, ct)


        # STEP 2
        print(Stepify('Doing something...', RUNTIME))

        nfac = [i[0] for i in list(factor(BASKET))]
        print(nfac)

        names  = ['k']

        crtVals = []
        for k,fac in enumerate(nfac):
            print('{}/{}'.format(k, len(nfac)), end='\r', flush=True)

            PR = PolynomialRing(GF(fac), names = names)

            y = (PR(pt) + PR.gens()[0]) ** 3
            for i in range(ROUND_NUM - 1):
                y += PR.gens()[0]
                y += PR(SNAKES[i])
                y = y ** 3
            y += PR.gens()[0] - PR(ct)

            yfac = list(y.factor()) 
            #print(yfac)

            val  = [int(-i[0].coefficients()[0]) for i in yfac if len(i[0].monomials()) == 2]
            print(val)

            crtVals += [val]


        # STEP 3
        print(Stepify('Doing something...', RUNTIME))

        print(crtVals)

        while True:

            key = crt( [int(i[randbelow(len(i))]) for i in crtVals], [int(i) for i in nfac] )
            # key = (ct - pow(crtSol, 3, BASKET)) % BASKET

            # print(crtSol)
            # print(key)

            if int(HASH(str(key).encode()).hexdigest(), 16) % 2**32 == LVL:
                break


        # FINAL STEP
        print(Stepify('Recovering flag...', RUNTIME))

        RESPONSE = oracle.Play(key)

        print(RESPONSE)

        # if FLAG:
        #     print('|\n|  FLAG = {}\n|\n|  [~] Done ~ !'.format(FLAG))

        # else:
        #     print('|\n|  [!] Failed to recover the flag, restarting loop...')

        #     oracle.Close()
        #     DATA_RECV += oracle.recv
        #     DATA_SEND += oracle.send
        #     continue


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