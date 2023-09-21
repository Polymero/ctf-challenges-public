#!/usr/bin/env python3
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os
from secrets import randbelow

# Non-native imports
from pwn import connect, process, context   # pip install pwntools


# RNG function
def randBitstring(x: bytes or str):
    return ''.join('01'[randbelow(2)] for _ in range(x))

# Packet function (augmented from challenge file)
PACKET_SIZE = 1024
CMDBYT_SIZE = 1
SERIAL_SIZE = 2
LENGTH_SIZE = 2
MACTAG_SIZE = 32

def PackForSending(bitstringList: list) -> list:

    bufferSize = 8 * (PACKET_SIZE - CMDBYT_SIZE - SERIAL_SIZE - LENGTH_SIZE)

    packetList = []
    for i, bitstring in enumerate(bitstringList):
        packetList += [b''.join([
            (1 - int(i == 0)).to_bytes(CMDBYT_SIZE, 'big'),
            (i).to_bytes(SERIAL_SIZE, 'big'),
            (len(bitstring)).to_bytes(LENGTH_SIZE, 'big'),
            int(bitstring + randBitstring(bufferSize - len(bitstring)), 2).to_bytes(bufferSize // 8, 'big')
        ])]

    packetList += [b''.join([
        (2).to_bytes(CMDBYT_SIZE, 'big'),
        (i + 1).to_bytes(SERIAL_SIZE, 'big'),
        (8 * MACTAG_SIZE).to_bytes(LENGTH_SIZE, 'big'),
        os.urandom(bufferSize // 8)
    ])]

    return packetList

# SHA256 pad function
def SHA256Pad(l1, l2):
    return '1' + ((512 - 1 - 64 - l1) % 512) * '0' + '{:064b}'.format(l2)

# Injection function
def generateInject(streams, inject):

    xl = (1 + '{:08b}'.format(inject[-1])[::-1].index('1'))
    xb = '{:0{n}b}'.format(int.from_bytes(inject, 'big'), n=8*len(inject))[:-xl]

    k = 8 * (len(b'InnerStream::' + b'::01') + 32)
    r = 512 - k
    s = len(xb)
    t = 512 - (s % 512)
    b = 512
    
    p1 = sum(len(i) for i in streams[0])
    p2 = sum(len(i) for i in streams[1])

    x = xb
    y = randBitstring(s)
    z = randBitstring(t)

    if not streams[0]:
        w = randBitstring(r)
        S1  = [w + x]
        S1 += [y + SHA256Pad(s, (2 + s // b) * b + s) + z]
        S2  = [w + x + SHA256Pad(s,  (1 + s // b) * b + s) + y]
        S2 += [z]
        
    else:
        S1  = [x]
        S1 += [y + SHA256Pad(s, k + p1 + (1 + s // b) * b + s) + z]
        S2  = [x + SHA256Pad(s, k + p2 + (s // b) * b + s) + y]
        S2 += [z]

    return [streams[0] + S2, streams[1] + S1]

# Oracle class
class ORACLE:

    @staticmethod
    def snicat(host, port=443):
        oracle = ORACLE()
        oracle.s = connect(host, port, ssl=True, sni=host)
        return oracle
    
    @staticmethod
    def netcat(host, port):
        oracle = ORACLE()
        oracle.s = connect(host, port)
        return oracle
    
    @staticmethod
    def process(file, py='python3'):
        oracle = ORACLE()
        oracle.s = process([py, file])
        return oracle

    def get_challenge(self):
        self.s.recvuntil(b'::\n')
        self.s.recvuntil(b'm1 = ')
        m1 = self.s.recvuntil(b'\n', drop=True)
        self.s.recvuntil(b'm2 = ')
        m2 = self.s.recvuntil(b'\n', drop=True)
        self.s.recvuntil(b'r1 = ')
        r1 = self.s.recvuntil(b'\n', drop=True)
        self.s.recvuntil(b'r2 = ')
        r2 = self.s.recvuntil(b'\n', drop=True)
        return m1, m2, r1, r2
    
    def send_stream(self, stream):
        for i in stream:
            #self.s.recv()
            self.s.sendline(i.hex().encode())

    def print_recv(self):
        print(self.s.recv())


oracle = ORACLE.snicat('hitb-e0eb5c52d4994b5e9d190fd776484664-1.chal.game.ctf.ae')
#context.log_level = 'debug'

m1, m2, r1, r2 = oracle.get_challenge()

TRIES = 0
while True:
    TRIES += 1

    firstInject  = [m1, r1]
    secondInject = [m2, r2]

    r = 512 - 8 * (len(b'InnerStream::' + b'::01') + 32)
    w = randBitstring(r)

    firstStream  = []
    secondStream = []

    for inject in firstInject:
        firstStream, secondStream = generateInject([firstStream, secondStream], inject)

    for inject in secondInject:
        secondStream, firstStream = generateInject([secondStream, firstStream], inject)

    firstData  = int(''.join(firstStream),  2).to_bytes(len(''.join(firstStream))  // 8, 'big')
    secondData = int(''.join(secondStream), 2).to_bytes(len(''.join(secondStream)) // 8, 'big')

    firstValid  = all([m1 in firstData,  m2 not in firstData,  r1 in firstData,  r2 not in firstData ])
    secondValid = all([m1 not in secondData, m2 in secondData, r1 not in secondData, r2 in secondData])

    if firstValid and secondValid:
        break

oracle.send_stream(PackForSending(firstStream))
oracle.send_stream(PackForSending(secondStream))

while True:
    try:
        oracle.print_recv()
    except:
        break
