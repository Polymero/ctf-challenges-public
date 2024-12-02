#!/usr/bin/env python3
#
# BlackHat MEA CTF 2024 - Final
#
# SOLVE SCRIPT :: [Hard] Crypto - GachaFlag
#
# by Polymero
#

# Native imports
import os, time, json, hashlib, base64
from typing import List, Tuple, Dict, Union
from random import Random as _Random
from secrets import randbelow
import itertools

# Non-native dependencies
from pwn import connect, process, context                     # pip install pwntools
from Crypto.Util.number import inverse, isPrime, getPrime     # pip install pycryptodome
from Crypto.Cipher import AES
from z3 import BitVec, LShR, Solver, Extract, If, BitVecVal   # pip install z3-solver

# Sage imports
# from sage.all import ...                                    # run "sage --python3 solve.py"


# Global parameters
HASH      = hashlib.sha256
RUNTIME   = int(time.time())
CTR_LOOP  = 0
CTR_CALL  = 0
DATA_RECV = 0
DATA_SEND = 0

FREE = 1000

DROPS = ['common', 'rare', 'epic', 'legendary', 'mythic']
DROP_TABLE = {}
DROP_TABLE['mythic']    = ( 2**32, lambda: FLAG.decode() ) 
DROP_TABLE['legendary'] = (   320, lambda: chr(FLAG[randbelow(len(FLAG))]) )
DROP_TABLE['epic']      = (    80, lambda: 'x' + FLAG.hex()[randbelow(len(FLAG)*2)] )
DROP_TABLE['rare']      = (    10, lambda: 'b' + str(int(0 != int.from_bytes(FLAG, 'big') & 2**randbelow(len(FLAG)*8))) )
DROP_TABLE['common']    = (  None, lambda: ' ' )

SYMBOLIC_COUNTER = itertools.count()


# Timing functions
def Stepify(stepstr: str, runtime: float) -> str:
    dt = int(time.time() - runtime)
    return '|\n|  ({}m {}s) {}'.format(dt // 60, dt % 60, stepstr)

# Helper functions
def B64Enc(x: int) -> str:
    return base64.urlsafe_b64encode(x.to_bytes(-(-x.bit_length() // 8), 'big')).decode().strip('=')

def B64Dec(x: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(x.encode() + b'==='), 'big')

def PullSplitter(pullstr: str) -> List[str]:
    out = []
    idx = 0
    while idx < len(pullstr):
        if pullstr[idx] == ' ':
            out += ['common']
            idx += 1
        elif pullstr[idx] == 'b':
            if pullstr[idx+1] in '01':
                out += ['rare']
                idx += 2
            else:
                out += ['legendary']
                idx += 1
        elif pullstr[idx] == 'x':
            if pullstr[idx+1] in '0123456789abcdef':
                out += ['epic']
                idx += 2
            else:
                out += ['legendary']
                idx += 1
        else:
            out += ['legendary']
            idx += 1
    return out

def U32(x: int) -> int:
    return x & 0xffffffff

def InitGenRand(s):
    mt = [0 for _ in range(SEED_LEN)]
    mt[0] = BitVecVal(s, 32)
    mti = 1
    while mti < SEED_LEN:
        mt[mti] = U32( 1812433253 * (mt[mti-1] ^ LShR(mt[mti-1], 30)) + mti )
        mti += 1
    return mt, mti

def InitByArray(initKey):
    keyLen = len(initKey)
    mt, mti = InitGenRand(19650218)
    i, j = 1, 0
    k = SEED_LEN if SEED_LEN > keyLen else keyLen
    while k:
        mt[i] = U32( (mt[i] ^ ((mt[i-1] ^ LShR(mt[i-1], 30)) * 1664525)) + initKey[j] + j )
        i, j = i + 1, j + 1
        if i >= SEED_LEN:
            mt[0] = mt[SEED_LEN-1]
            i = 1
        if j >= keyLen:
            j = 0
        k -= 1
    k = SEED_LEN - 1
    while k:
        mt[i] = U32( (mt[i] ^ ((mt[i-1] ^ LShR(mt[i-1], 30)) * 1566083941)) - i )
        i += 1
        if i >= SEED_LEN:
            mt[0] = mt[SEED_LEN-1]
            i = 1
        k -= 1
    mt[0] = 0x80000000;
    return mt
        
    
# Solver functions
def GetRandOuts(pullstr: str) -> List[Union[int, None]]:
    pulls = PullSplitter(pullstr)
    randouts = []
    for drop in ['rare', 'epic', 'legendary']:
        pity = DROP_TABLE[drop][0]
        subs = [pulls[i:i+pity] for i in range(0, FREE, pity)]
        for sub in subs:
            hits = [i == drop for i in sub]
            if True in hits:
                randouts += [hits.index(True)]
            else:
                randouts += [None]
    return randouts


# Challenge classes
class Random(_Random):
    def __init__(self, seed: int) -> None:
        super().__init__(seed)
        self.buffer = ''

    def GetRandBits(self, bits: int) -> int:
        while len(self.buffer) <= bits:
            self.buffer += '{:032b}'.format(self.getrandbits(32))
        out, self.buffer = self.buffer[:bits], self.buffer[bits:]
        return int(out, 2)


# Solver classes
class _Untwister:
    """ Credits to Nuno Sabino :: https://github.com/icemonster/symbolic_mersenne_cracker/blob/main/main.py """
    def __init__(self):
        name = next(SYMBOLIC_COUNTER)
        self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
        self.index = 0
        self.solver = Solver()

    def SymbolicUntamper(self, solver, y):
        name = next(SYMBOLIC_COUNTER)
        y1 = BitVec(f'y1_{name}', 32)
        y2 = BitVec(f'y2_{name}' , 32)
        y3 = BitVec(f'y3_{name}', 32)
        y4 = BitVec(f'y4_{name}', 32)
        equations = [
            y2 == y1 ^ (LShR(y1, 11)),
            y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
            y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
            y  == y4 ^ (LShR(y4, 18))
        ]
        solver.add(equations)
        return y1

    def SymbolicTwist(self, MT, n=624, upper_mask=0x80000000, lower_mask=0x7FFFFFFF, a=0x9908B0DF, m=397):
        MT = [i for i in MT]
        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = LShR(x, 1)
            xB = If(x & 1 == 0, xA, xA ^ a)
            MT[i] = MT[(i + m) % n] ^ xB
        return MT

    def GetSymbolic(self, guess):
        name = next(SYMBOLIC_COUNTER)
        ERROR = 'Must pass a string like "?1100???1..." where ? represents an unknown bit'
        assert type(guess) == str, ERROR
        assert all(map(lambda x: x in '01?', guess)), ERROR
        assert len(guess) == 32, "Check input size"
        self.symbolicGuess = BitVec(f'symbolicGuess_{name}', 32)
        guess = guess[::-1]
        for i, bit in enumerate(guess):
            if bit != '?':
                self.solver.add(Extract(i, i, self.symbolicGuess) == bit)
        return self.symbolicGuess

    def Submit(self, guess):
        if self.index >= 624:
            name = next(SYMBOLIC_COUNTER)
            next_mt = self.SymbolicTwist(self.MT)
            self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
            for i in range(624):
                self.solver.add(self.MT[i] == next_mt[i])
            self.index = 0
        symbolicGuess = self.GetSymbolic(guess)
        symbolicGuess = self.SymbolicUntamper(self.solver, symbolicGuess)
        self.solver.add(self.MT[self.index] == symbolicGuess)
        self.index += 1

class Untwister(_Untwister):
    """ Credits to Si Yuan :: https://imp.ress.me/blog/2022-11-13/seccon-ctf-2022/#janken-vs-kurenaif """
    def __init__(self):
        super().__init__()
        self.firstMT = self.MT
        self.index = 624

    def GetRandom(self):
        self.solver.add(self.firstMT[0] == 0x80000000)
        self.solver.check()
        model = self.solver.model()
        state = [
            model[x].as_long() if model[x] is not None else 0
            for x in self.firstMT
        ]
        resultState = (3, tuple(state + [624]), None)
        rand = Random(0)
        rand.setstate(resultState)
        return rand


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

    def GetPulls(self, username: str) -> str:
        self.Recv()
        self.SendLine(b'l')
        self.Recv()
        self.SendLine(username.encode())
        self.Recv()
        self.SendLine(b'p')
        self.RecvUntil(b"pulls = '")
        return self.RecvUntil(b"'\n").decode()


# Challenge parameters
...

# Solver parameters
COLL_NUM = 256

pityList  = []
pityList += [DROP_TABLE['rare'][0]] * -(-FREE // DROP_TABLE['rare'][0])
pityList += [DROP_TABLE['epic'][0]] * -(-FREE // DROP_TABLE['epic'][0])
pityList += [DROP_TABLE['legendary'][0]] * -(-FREE // DROP_TABLE['legendary'][0])
pityLens  = [i.bit_length() for i in pityList]
requiredBits = sum(pityLens)

SEED_LEN = 624


# To see all traffic uncomment the line below
# context.log_level = 'debug'


# Start
print("|\n|  [~] SOLVE SCRIPT for 'GachaFlag'")



# # STEP -1
# print(Stepify('Doing something...', RUNTIME))

# ...



# Loop
while True:
    try:

        CTR_LOOP += 1
        print("|\n|  [~] Starting solver loop {}...".format(CTR_LOOP))


        # STEP 0
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('34.252.33.37', 31731)

        print('|\n|  [~] Successfully connected to challenge instance.')



        # STEP 1
        print(Stepify('Collecting pull samples...', RUNTIME))

        # Generate random usernames
        collNames = [os.urandom(16).hex() for _ in range(COLL_NUM)]
        # Generate corresponding Random objects
        collRands = [Random(B64Dec(i)) for i in collNames]
        # Generate corresponding Random output bits
        collBits  = ['{:01024b}'.format(i.GetRandBits(1024)) for i in collRands]
        # Collect corresponding pulls from server
        collPulls = []
        for i in range(COLL_NUM):
            print('|    ... ({}/{})'.format(i, COLL_NUM), end='\r', flush=True)
            collPulls += [GetRandOuts(oracle.GetPulls(collNames[i]))]


        # STEP 2
        print(Stepify('Finding fits for FLAG-based RNG output...', RUNTIME))

        trackers = [[0, 0] for _ in range(COLL_NUM)]
        bestFits = []

        while True:
            fits = []
            for i,tracker in enumerate(trackers):
                idx, jdx = tracker

                if pityLens[idx] > 4:
                    fits += [None]
                    continue

                if collPulls[i][idx] is None:
                    fits += [None]
                    trackers[i] = [idx + 1, jdx + pityLens[idx]]
                    continue

                bits  = collBits[i][jdx : jdx + pityLens[idx]]
                fits += [( collPulls[i][idx] - int(bits, 2) ) % 2**4]

            fitSet = list(set(fits))
            try:
                fitSet.remove(None)
            except:
                pass

            if len(fitSet) < 2:
                break

            fitCount = [fits.count(i) for i in fitSet]

            firstMax  = max(fitCount)
            secondMax = max(fitCount[:fitCount.index(firstMax)] + fitCount[fitCount.index(firstMax) + 1:])

            if (firstMax / secondMax) < 3:
                break

            fitBest = fitSet[fitCount.index(firstMax)]

            for i in range(len(trackers)):

                if fits[i] is None:
                    continue
                else:
                    trackers[i][1] += pityLens[trackers[i][0]]

                if bin(fitBest).startswith(bin(fits[i])) or bin(fits[i]).startswith(bin(fitBest)):
                    trackers[i][0] += 1

            bestFits += [fitBest]

        recoveredBits = ''.join(['{:04b}'.format(i) for i in bestFits])

        print('|\n|  [~] Managed to recover {} outputs for a total of {} bits:\n|    BITS = {}'.format(len(bestFits), 4*len(bestFits), recoveredBits))

        if len(recoveredBits) < requiredBits:
            print('|\n|  [!] Failed to recover enough bits, restarting loop...')
            oracle.Close()
            DATA_RECV += oracle.recv
            DATA_SEND += oracle.send
            continue


        # STEP 3
        print(Stepify('Calculating target RNG outputs...', RUNTIME))

        bitBins  = [0]
        bitBins += [sum(pityLens[:i+1]) for i in range(len(pityLens))]
        bitBins += [sum(pityLens) + 32]

        targets = []
        for i in range(len(bitBins) - 1):

            idx, jdx = bitBins[i], bitBins[i+1]
            recoveredInt = int(recoveredBits[idx:jdx], 2)
            targetInt = (-recoveredInt) % 2**(jdx - idx)

            targets += ['{:0{n}b}'.format(targetInt, n=jdx-idx)]

        targetBits = ''.join(targets)
        while len(targetBits) % 32:
            targetBits += '?'

        targetBitVecs = [targetBits[i:i+32] for i in range(0, len(targetBits), 32)]

        print('|\n|  [~] Successfully generated {} target bit vectors:\n|    VECS = {}'.format(len(targetBitVecs), targetBitVecs))


        # STEP 4
        print(Stepify('Solving for Mersenne Twister internal state...', RUNTIME))

        untwister = Untwister()
        for target in targetBitVecs:
            untwister.Submit(target)

        untwisterRand = untwister.GetRandom()
        untwisterRandState = untwisterRand.getstate()[1][:-1]

        print('|\n|  [~] Successfully recovered the Mersenne Twister internal state ~ !')


        # STEP 5
        print(Stepify('Solving for Mersenne Twister seed...', RUNTIME))

        seedVars = [BitVec('seed_{}'.format(i), 32) for i in range(SEED_LEN)]
        seedRandState = InitByArray(seedVars)

        solver = Solver()
        for x, y in zip(seedRandState, untwisterRandState):
            solver.add( x == y )

        solver.check()

        solverModel = solver.model()
        seedInitKey = [solverModel[i].as_long() if solverModel[i] is not None else 0 for i in seedVars]
        seedInt = sum([j * 2**(i * 32) for i,j in enumerate(seedInitKey)])
        seedB64 = B64Enc(seedInt)

        print('\n|  [~] Successfully recovered the Mersenne Twister seed:\n|    SEED = {}'.format(seedB64))


        # FINAL STEP
        print(Stepify('Recovering flag...', RUNTIME))

        luckyPull = oracle.GetPulls(seedB64)

        if any([i in luckyPull for i in ['FlagY', 'flag', 'Flag']]):
            FLAG = luckyPull[:luckyPull.index('}') + 1]
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
