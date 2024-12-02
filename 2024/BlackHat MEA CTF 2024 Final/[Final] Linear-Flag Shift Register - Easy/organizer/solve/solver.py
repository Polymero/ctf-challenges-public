#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# SOLVE SCRIPT :: [Easy] Crypto - Linear-Flag Shift Register
#
# by Polymero
#

# Native imports
import os, time, hashlib

# Non-native dependencies
from pwn import connect, process  # pip install pwntools
from Crypto.Cipher import AES

# Sage imports
from sage.all import Matrix, GF                               # run "sage --python3 solve.py"
from sage.matrix.berlekamp_massey import berlekamp_massey


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

    def GetFlagLength(self) -> int:
        self.RecvUntil(b'is your ')
        return int(self.RecvUntil(b' char').decode())

    def SendGuess(self, guess: str) -> int:
        self.Recv()
        self.SendLine(guess.encode())
        self.RecvUntil(b'RETURN = ')
        return int(self.RecvUntil(b'\n').decode())


# Challenge parameters
TAPNUM = 32
RUNNUM = 1337

# Solver parameters
...


# To see all traffic uncomment the line below
# context.log_level = 'debug'


# Start
print("|\n|  [~] SOLVE SCRIPT for 'Linear-Flag Shift Register'")


# Loop
while True:
    try:

        CTR_LOOP += 1
        print("|\n|  [~] Starting solver loop {}...".format(CTR_LOOP))


        # STEP 0
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('blackhat.flagyard.com', 31079)

        print('|\n|  [~] Successfully connected to challenge instance.')



        # STEP 1
        print(Stepify('Sending guess...', RUNTIME))

        flagLength = oracle.GetFlagLength()

        guess = '0' * flagLength
        respInt  = oracle.SendGuess(guess)
        respBits = [int(i) for i in '{:0{n}b}'.format(respInt, n = 2**(8 - 1) + 2**(8 + 1))][::-1]


        # STEP 2
        print(Stepify('Guessing missing tail (16 bits)...', RUNTIME))

        for tailInt in range(2**16):
            print('|    ... ({}/65536)'.format(tailInt), end='\r', flush=True)

            tailBits = [int(i) for i in '{:016b}'.format(tailInt)]

            minPoly = berlekamp_massey([GF(2)(respBits[0])] + respBits[1:] + tailBits)

            minPows = [8 * flagLength - i for i in list(minPoly.dict())[1:]]
            if len(minPows) == TAPNUM:
                break

        if len(minPows) != TAPNUM:
            raise ValueError('Failed to find a minimal polynomial...')

        print('|\n|  [~] Found a minimal polynomial at {}:\n|    POLY = {}'.format(tailInt, minPoly))


        # STEP 3
        print(Stepify('Finding all possible taps...', RUNTIME))

        possibleTaps = [[(i - j) % minPoly.degree() for i in minPows] for j in range(8 * flagLength)]
        possibleTaps = [i for i in possibleTaps if (8 * flagLength - 1) in i]



        # FINAL STEP
        print(Stepify('Recovering flag...', RUNTIME))

        respVector = Matrix(GF(2), respBits[:8 * flagLength][::-1]).T

        for taps in possibleTaps:

            lfsrMatrix = Matrix(GF(2), [[1 if i in taps else 0 for i in range(8 * flagLength)]] + [[0]*i + [1] + [0]*(8 * flagLength - i - 1) for i in range(8 * flagLength - 1)])
            
            seedInt = sum([int(j) * 2**i for i,j in enumerate(((lfsrMatrix.inverse() ** RUNNUM) * respVector).list()[::-1])])
            
            FLAG = int(seedInt ^ int.from_bytes(guess.encode(), 'big')).to_bytes(flagLength, 'big')
            if any(i in FLAG for i in [b'BHFlagY', b'FlagY', b'FLAG', b'flag', b'flagy']):
                FLAG = FLAG.decode()
                break
            else:
                FLAG = None

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
