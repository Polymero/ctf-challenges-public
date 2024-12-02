#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# SOLVE SCRIPT :: [Medium] Crypto - Trypanophobia
#
# by Polymero
#

# Native imports
import json
import time

# Non-native imports
from pwn import connect, process  # pip install pwntools

# Sage imports
...     # sage --python solver.py

# Local imports
...


# Functions
...


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
    
    def Insert(self, f, i, j):
        self.s.recv()
        self.s.sendline(b'I')
        self.s.recv()
        self.s.sendline(json.dumps({'f': f, 'i': i, 'j': j}).encode())
        self.s.recvuntil(b'0x')
        return bytes.fromhex(self.s.recvuntil(b'\n', drop=True).decode())
    
    def InsertAsyncSend(self, f, i, j):
        self.s.recv()
        self.s.sendline(b'I')
        self.s.recv()
        self.s.sendline(json.dumps({'f': f, 'i': i, 'j': j}).encode())

    def InsertAsyncRecv(self):
        self.s.recvuntil(b'0x')
        return bytes.fromhex(self.s.recvuntil(b'\n', drop=True).decode())


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
        print(Stepify('Connecting to TWO challenge servers...', RUNTIME))

        oracleOne = Oracle.Netcat('127.0.0.1', 5000)
        oracleTwo = Oracle.Netcat('127.0.0.1', 5000)

        lenCheck = oracleOne.Insert('flag', 0, 0)
        t, enc = lenCheck[:4], lenCheck[4:]
        flagLength = len(enc)

        _ = oracleTwo.Insert('flag', 0, 0)


        # STEP 1 
        print(Stepify('Requesting simultaneous insert requests...', RUNTIME))

        oracleOne.InsertAsyncSend('flag', 0, 1)
        oracleTwo.InsertAsyncSend('flag', len(enc), 1)

        ctOne = oracleOne.InsertAsyncRecv()
        ctTwo = oracleTwo.InsertAsyncRecv()

        tOne, ctOne = ctOne[:4], ctOne[4:]
        tTwo, ctTwo = ctTwo[:4], ctTwo[4:]

        print(tOne, ctOne)
        print(tTwo, ctTwo)

        assert tOne == tTwo


        # STEP 2
        print(Stepify('Recovering the flag...', RUNTIME))

        rec = b'\x00\x01'
        for i in range(len(ctOne)):
            rec += bytes([rec[-1] ^ ctOne[i] ^ ctTwo[i]])

        print(rec[2:-1])



        break

    except Exception as e:
        print(e)
        break


# End
print(Stepify('Script END.\n', RUNTIME))
oracleOne.Close()
oracleTwo.Close()
