#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# SOLVE SCRIPT :: [Hard] Crypto - SaqrSign
#
# by Polymero
#

# Native imports
import os, time, json, hashlib
from secrets import randbelow

# Non-native imports
from pwn import connect, process  # pip install pwntools

# Sage imports
...     # sage --python solver.py

# Local imports
from ntt_full import NTTDomain, NTTPoints


# Functions
def Stepify(stepstr, runtime):
    dt = int(time.time() - runtime)
    return '|\n|  ({}m {}s) {}'.format(dt // 60, dt % 60, stepstr)

def HashBall(m: bytes, tau: int, n: int, q: int) -> list:
    """ Copied from challenge file 'challenge.py', slightly altered. """
    if isinstance(m, str):
        m = m.encode()
    h = hashlib.sha256(m).digest()
    c = n * [0]
    for i in range(n - tau, n):
        hi = int(hashlib.sha256(h + i.to_bytes(2, 'big')).hexdigest(), 16)
        hi //= i; j = hi % i; hi //= i
        hi //= 2; k = hi % 2; hi //= 2
        c[i] = c[j]
        c[j] = (1 - 2 * k) % q
    return c

def Hex2NTTPoints(hex: str, n: int, ntt: NTTDomain):
    ptsSum = int(hex, 16)
    pts = []
    while len(pts) < n:
        pts += [ptsSum % ntt.q]
        ptsSum //= ntt.q
    return ntt.fromPoints(pts)


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

    def GetPublicKey(self) -> dict:
        self.s.recvuntil(b'Public = ')
        return json.loads(self.s.recvuntil(b'\n', drop=True).decode())
    
    def Sign(self, msg: str) -> dict:
        self.s.recv()
        self.s.sendline(b's')
        self.s.recv()
        self.s.sendline(msg.encode())
        self.s.recvuntil(b'Sig = ')
        return json.loads(self.s.recvuntil(b'\n', drop=True).decode())
    
    def Compare(self, D: NTTPoints) -> str:
        self.s.recv()
        self.s.sendline(b'c')
        self.s.recv()
        self.s.sendline(str(D).encode())
        return self.s.recvuntil(b'...')


# Challenge parameters
N, Q, W, P = 1024, 12289, 4324, 9389
ntt = NTTDomain(Q, W, P)

# Solver parameters
#context.log_level = 'debug'
SIG_SAMPLE_SIZE_MAX = 500
SIG_SAMPLE_SIZE_STEP = 25
GPOLY_LOWER_BOUND = -0.5
GPOLY_UPPER_BOUND =  0.5


# Start
RUNTIME = int(time.time())
print("|\n|  ~ SOLVE SCRIPT for 'SaqrSign'")

while True:
    try:

        # STEP 0
        print(Stepify('Connecting to challenge server...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('127.0.0.1', 5000)
        public = oracle.GetPublicKey()
        for i in public:
            public[i] = Hex2NTTPoints(public[i], N, ntt)


        # STEP 1 
        print(Stepify('Generating NNTs for all shifted convolutions...\n|', RUNTIME))

        kNTTs = [ntt.fromPoly(k*[0] + [1] + (N-k-1)*[0]) for k in range(N)]

        CALLS = 0
        sampleNum = 0
        samplePoly = N*[0]
        while CALLS < SIG_SAMPLE_SIZE_MAX:

            print(Stepify('Collecting samples... ({}/{}) ({} samples)      '.format(CALLS, SIG_SAMPLE_SIZE_MAX, sampleNum), RUNTIME)[2:], end='\r', flush=True)

            CALLS += 1
            msg = os.urandom(32).hex()
            sig = oracle.Sign(msg)

            r = bytes.fromhex(sig['r'])
            V = Hex2NTTPoints(sig['V'], N, ntt)

            cPoly = HashBall(msg.encode() + r, 38, N, Q)
            cPts  = ntt.fromPoly(cPoly)

            for kPts in kNTTs:

                convPts  = kPts * cPts
                convPoly = convPts.toPoly()

                if convPoly[0] == 1:
                    zPts  = kPts * V
                    zPoly = zPts.toPoly()

                elif convPoly[0] == Q - 1:
                    zPts  = kPts * V
                    zPoly = [(-i) % Q for i in zPts.toPoly()]
    
                else:
                    continue

                sampleNum += 1
                for i,j in enumerate(zPoly):
                    samplePoly[i] += j - Q * (j > Q//2)


            if CALLS % SIG_SAMPLE_SIZE_STEP == 0:

                # STEP 2
                print(Stepify('Recovering secret element G...', RUNTIME))

                GPoly = [-1 if i/sampleNum < GPOLY_LOWER_BOUND else 1 if i/sampleNum > GPOLY_UPPER_BOUND else 0 for i in samplePoly]


                # STEP 3
                print(Stepify('Recovering secret element D...', RUNTIME))

                GPts = ntt.fromPoly(GPoly)
                DPts = public['E'] * GPts - public['A']


                # STEP 4
                print(Stepify('Getting flag...', RUNTIME))

                resp = oracle.Compare(DPts)
                if b'BHFlagY' in resp:
                    print('|\n|  Gottem ::\n{}'.format(resp))
                    break
                else:
                    print('|\n|  Not quite. Continuing...')

        break


    except Exception as e:
        print(e)
        break


# End
print(Stepify('Script END.\n', RUNTIME))
oracle.Close()
