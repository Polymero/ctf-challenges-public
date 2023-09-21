#!/usr/bin/env python3
#
# Polymero
#
# HITB CTF 2023
#

#
import time, hashlib
from secrets import randbelow
from Crypto.Util.number import inverse
from pwn import connect, process, context

class ORACLE:

    @staticmethod
    def snicat(host, port=443):
        """ Connect to a CTFd Snicat address """
        oracle = ORACLE()
        oracle.s = connect(host, port, ssl=True, sni=host)
        return oracle
    
    @staticmethod
    def netcat(host, port):
        """ Connect to a Netcat address """
        oracle = ORACLE()
        oracle.s = connect(host, port)
        return oracle
    
    @staticmethod
    def process(file, py='python3'):
        """ Run and connect to a local file """
        oracle = ORACLE()
        oracle.s = process([py, file])
        return oracle
    
    def close(self):
        """ Close connection """
        self.s.close()

    def getDomainAndFlag(self):
        """ Retrieve domain parameters (p, g) and flag from server """
        self.s.recvuntil(b'p = ')
        p = int(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'g = ')
        g = int(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'flag = ')
        flag = bytes.fromhex(self.s.recvuntil(b'\n', drop=True).decode())
        return p, g, flag
    
    def getKey(self):
        """ Retrieve a public key from server """
        self.s.sendline(b'')
        self.s.recvuntil(b'pk = ')
        pk = int(self.s.recvuntil(b'\n', drop=True).decode())
        return pk
    

# Header
RUNTIME = int(time.time())
print('|\n|  ~ SOLVE SCRIPT for likeClockwork')


print('|\n|  ~ Finding good prime ::')

BITCUT = 9
PSIZE  = 512

CALLS = 0
while True:
    CALLS += 1

    #oracle = ORACLE.snicat('hitb-e5fc770d890afae76178373254344301-1.chal.game.ctf.ae')
    oracle = ORACLE.process('../Challenge/likeclockwork.py')

    p, g, flag = oracle.getDomainAndFlag()

    pbit = '{:0{n}b}'.format(p, n=PSIZE)
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
while len(keys) < PSIZE:
    CALLS += 1

    print('|  ({}m {}s) {} {}'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, CALLS, len(keys)), end='\r', flush=True)

    keys.add(oracle.getKey())

print(CALLS, len(keys))


print('|\n|  ~ Recovering secret ::')

rec = ''
fMSB = inverse(pow(g, 2**(PSIZE - 1), p), p)
fLSB = g

a = list(keys)[0]
for _ in range(PSIZE):

    # print(rec, end='\r', flush=True)

    if pow(a, 2, p) in keys:
        rec += '0'
        a = pow(a, 2, p)

    else:
        rec += '1'
        a = (pow(fMSB * a, 2, p) * fLSB) % p
        assert a in keys

print(rec)


def roll(x, y):
    y %= PSIZE
    return ((x >> (PSIZE - y)) | (x << y)) % 2**PSIZE

for i in range(PSIZE):
    secret = roll(int(rec, 2), i)

    otpKey = b''
    while len(otpKey) < len(flag):
        otpKey += hashlib.sha256(b'OTP::' + str(secret).encode() + b'::' + len(otpKey).to_bytes(2, 'big')).digest()

    posflag = bytes([x ^ y for x,y in zip(flag, otpKey)])
    if b'flag' in posflag:
        print(posflag)