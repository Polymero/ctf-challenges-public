#!/usr/bin/env python3
#
# Polymero
#
# HITB CTF 2023
#

#
import os, time, hashlib
from secrets import randbelow
from Crypto.Util.number import getPrime, inverse
from pwn import connect, process, context

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
    
    def close(self):
        self.s.close()

    def getDomainAndFlag(self):
        self.s.recvuntil(b'p = ')
        p = int(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'g = ')
        g = int(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'flag = ')
        flag = bytes.fromhex(self.s.recvuntil(b'\n', drop=True).decode())
        return p, g, flag
    
    def getKey(self):
        self.s.sendline(b'')
        self.s.recvuntil(b'pk = ')
        pk = int(self.s.recvuntil(b'\n', drop=True).decode())
        return pk
    

# Header
RUNTIME = int(time.time())
print('|\n|  ~ SOLVE SCRIPT for likeClockwork')


print('|\n|  ~ Finding good prime ::')

BITCUT = 9

CALLS = 0
while True:
    CALLS += 1

    oracle = ORACLE.snicat('hitb-e5fc770d890afae76178373254344301-1.chal.game.ctf.ae')

    p, g, flag = oracle.getDomainAndFlag()

    pbit = '{:0512b}'.format(p)
    print(CALLS, pbit[:10], len(pbit.split('0')[0]))

    if pbit[:BITCUT] == '1'*BITCUT:
        
        # order = p - 1
        # while not order % 2:
        #     order //= 2

        # assert (inverse(2, order) * 2) % order == 1

        # if pow(g, order, p) == 1:
        #     break

        # print('Invwawid owdaw QwQ')

        break

    oracle.close()

print(CALLS, pbit[:10], len(pbit.split('0')[0]))


print('|\n|  ~ Collecting keys ::')

keys = set()

CALLS = 0
while len(keys) < 512:
    CALLS += 1

    print('|  ({}m {}s) {} {}'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, CALLS, len(keys)), end='\r', flush=True)

    keys.add(oracle.getKey())

print(CALLS, len(keys))


print('|\n|  ~ Recovering secret ::')

rec = ''
fMSB = inverse(pow(g, 2**511, p), p)
fLSB = g

a = list(keys)[0]
for _ in range(512):

    # print(rec, end='\r', flush=True)

    if pow(a, 2, p) in keys:
        rec += '0'
        a = pow(a, 2, p)

    else:
        rec += '1'
        a = (pow(fMSB * a, 2, p) * fLSB) % p
        assert a in keys

print(rec)

PSIZE = 512
def roll(x, y):
    y %= PSIZE
    return ((x >> (PSIZE - y)) | (x << y)) % 2**PSIZE

for i in range(PSIZE):
    secret = roll(int(rec), i)

    otpKey = b''
    while len(otpKey) < len(flag):
        otpKey += hashlib.sha256(b'OTP::' + str(secret).encode() + b'::' + len(otpKey).to_bytes(2, 'big')).digest()

    posflag = bytes([x ^ y for x,y in zip(flag, otpKey)])
    if b'flag' in posflag:
        print(posflag)