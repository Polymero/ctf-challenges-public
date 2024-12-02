#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# SOLVE SCRIPT :: [Medium] Crypto - Slippery Slope
#
# by Polymero
#

# Native imports
import os, time, json, hashlib
from secrets import randbelow
from typing import List, Dict

# Non-native dependencies
from pwn import connect, process, context                     # pip install pwntools

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
def GenBinomInts(n, k):
    s = []
    v = (1 << k) - 1
    while v < (2 << (n - 1)):
        s.append(v)
        t = (v | (v - 1)) + 1
        v = t | ((((t & -t) // (v & -v)) >> 1) - 1)
    return s
    
# Solver functions
...


# Oracle class object
class Oracle:
    def __init__(self, tube: object) -> None:
        self.tube = tube
        self.recv = 0
        self.send = 0

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

    # Interaction methods

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

    # Challenge methods

    def GenIV(self) -> Dict[str, str]:
        self.Recv()
        self.SendLine(b'g')
        self.RecvUntil(b'RESP = ')
        return json.loads(self.RecvUntil(b'\n').decode())
    
    def LoadIV(self, packet: Dict[str, str]) -> bool:
        self.Recv()
        self.SendLine(b'l')
        self.Recv()
        self.SendLine(json.dumps(packet).encode())
        self.RecvUntil(b'RESP = ')
        resp = b'True' == self.RecvUntil(b'\n')
        self.Recv()
        self.SendLine(b'')
        return resp
    
    def LoadIVBatch(self, packets: List[Dict[str, str]]) -> List[bool]:
        self.Recv()
        self.SendLine(b'l')
        self.Recv()
        self.SendLine(b'\n'.join([json.dumps(i).encode() for i in packets]))
        resps = []
        for _ in range(len(packets)):
            self.RecvUntil(b'RESP = ')
            resps += [b'True' == self.RecvUntil(b'\n')]
        self.Recv()
        self.SendLine(b'')
        return resps
    
    def InitMessage(self, msg: str) -> Dict[str, str]:
        self.Recv()
        self.SendLine(b'i')
        self.Recv()
        self.SendLine(msg.encode())
        self.RecvUntil(b'RESP = ')
        return json.loads(self.RecvUntil(b'\n').decode())
    
    def SendPacket(self, packet: Dict[str, str]) -> str:
        self.Recv()
        self.SendLine(b's')
        self.Recv()
        self.SendLine(json.dumps(packet).encode())
        resp = self.Recv()
        if b'FLAG' in resp:
            resp = resp[resp.index(b'FLAG = ') + 7:]
            resp = resp[:resp.index(b'\n')]
            return resp.decode()
        return ''


# Challenge parameters
...

# Solver parameters
FLAG_ALP = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}'
BATCH_SIZE = 512
HAMMING = 3


# To see all traffic uncomment the line below
# context.log_level = 'debug'


# Start
print("|\n|  [~] SOLVE SCRIPT for 'Slippery Slope'")


# STEP 0
print(Stepify('Generating list of 32-bit integers with hamming weight of {}...'.format(HAMMING), RUNTIME))

GINTS = GenBinomInts(32, HAMMING)

print('|\n|  [~] Generated a total of {} integers.'.format(len(GINTS)))


# Loop
while True:
    try:

        CTR_LOOP += 1
        print("|\n|  [~] Starting solver loop {}...".format(CTR_LOOP))

        # STEP 1
        print(Stepify('Connecting to challenge instance...', RUNTIME))

        # oracle = Oracle.Process('./challenge.py')
        oracle = Oracle.Netcat('blackhat.flagyard.com', 32497)
        oracle.RecvUntil(b'successfully set up')

        print('|\n|  [~] Successfully connected to challenge instance.')


        # STEP 2
        print(Stepify('Looking for LEAF forgery...', RUNTIME))

        target = oracle.GenIV()
        CTR_CALL += 1

        iv   = target['iv']
        leaf = int(target['leaf'], 16)
        llen = len(target['leaf']) // 2

        RUN = True
        for k in range(128):
            print('|    ... ({}/128)'.format(k), end='\r', flush=True)

            kleaf = leaf ^ 2**(k + 32)

            frgs = [{
                'iv'   : iv,
                'leaf' : (kleaf ^ g).to_bytes(llen, 'big').hex()
            } for g in GINTS]

            chunks = [frgs[i:i + BATCH_SIZE] for i in range(0, len(frgs), BATCH_SIZE)]

            for chunk in chunks:

                resp = oracle.LoadIVBatch(chunk)
                CTR_CALL += 1

                if any(resp):
                    RUN = False
                    break

            if not RUN:
                break

        if RUN:
            print('|\n|  [!] Failed to find colliding LEAFs, restarting loop...')

            oracle.Close()
            DATA_RECV += oracle.recv
            DATA_SEND += oracle.send
            continue

        forgery  = int(chunk[resp.index(True)]['leaf'], 16) ^ leaf
        original = oracle.InitMessage('flag')
        forged   = {
            'iv'   : original['iv'],
            'ct'   : original['ct'],
            'leaf' : (int(original['leaf'], 16) ^ forgery).to_bytes(llen, 'big').hex()
        }

        print('|\n|  [~] Found colliding LEAFs:\n|    1: {}\n|    2: {}'.format(original['leaf'], forged['leaf']))


        # STEP 3
        print(Stepify('Collecting the flag...', RUNTIME))

        FLAG = oracle.SendPacket(forged)
        CTR_CALL += 1

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
