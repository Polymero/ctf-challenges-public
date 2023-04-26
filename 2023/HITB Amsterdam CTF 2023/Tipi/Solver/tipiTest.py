#!/usr/bin/env python3
#
# Polymero
#
# HITB CTF 2023
#

import time, hashlib

from pwn import connect, process, context
from Crypto.Util.number import inverse

RUNTIME = int(time.time())

# Static parameters
P = 0xe27773f2a561ed14ba9b1b64042378bc6d221cf5e65af2a43bcfe4e42f938f201575bbbb1a99dfe5468e3ae6a961eb7f97771caca495ea9e00b927fbf2d2b81a78edb9f109a62fbc101b4393de05f7f2d7d3bf947e7ef4b32ee5ab30f30a35fefb72433e0de7e1ffa4f5040acd6d75ecf8061f471fe938d8961300a6c73f4dd9
G = 0x66ba6e0d85fbe037153fca9b8bdfce8052311bda17e19c000ef8acb1ccbaf8c02d2cbb0c5ed1e40989b615ebcd8d8598b793a752867fb873dc36f5f64be05520fb47b01dd804e15abc5f79a8c2ebe7c5abcfa392b85df638a24244279cb2b7042ab8c66ff8d0d005b3cf4f8e492e06ca8f25896dc9a4df5a3ba055ac89118d01


# Functions
def Pad(x):
    x = (int(time.time()*1000) % 2**40).to_bytes(5, 'big') + x
    x += (16 - len(x) % 16) * bytes([16 - len(x) % 16])
    return x

def UnPad(x):
    assert x[-x[-1]:] == x[-1] * bytes([x[-1]])
    assert int.from_bytes(x[:5], 'big') <= int(time.time()*1000) % 2**40
    return x[5:-x[-1]]


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

    def close(self):
        self.s.close()

    def get_leak(self):
        self.s.recvuntil(b'::\n')
        leak = eval(self.s.recvuntil(b'\n', drop=True).decode())
        self.s.recvuntil(b'::\n')
        return leak

    def key_exchange(self, pk: int) -> int:
        self.s.sendline(pk.to_bytes(128, 'big').hex().encode())
        pk_server = int(self.s.recvuntil(b'\n', drop=True).decode(), 16)
        return pk_server
    
    def get_iv(self):
        iv = bytes.fromhex(self.s.recvuntil(b'\n', drop=True).decode())
        return iv
    
    def send_packet(self, packet: bytes) -> bytes:
        self.s.sendline(packet.hex().encode())
        return self.s.recvuntil(b'\n', drop=True)
    


oracle = ORACLE.snicat('hitb-25bbb472589a45f45f5f0f8695eccd2a-0.chal.game.ctf.ae')

LEAK = oracle.get_leak()
LEAK_t = int(hashlib.sha256(str(int(1681563399)).encode()).hexdigest(), 16)
LEAK_pk = int(LEAK[0], 16)
LEAK_li = bytes.fromhex(LEAK[3])

GARBAGE_pk = G
_ = oracle.key_exchange(GARBAGE_pk)

print('|  ~ Collecting raw timing trace:')

tms = []
for _ in range(100):
    riv = oracle.get_iv()
    t0 = time.time()
    rsp = oracle.send_packet(10*LEAK_li)
    tms += [time.time() - t0]
    print(tms[-1], end='\r', flush=True)

tmax = max(tms)
tsum = sum(tms)
tlen = len(tms)
tcut = (0.3, 0.7)
tnum = sum([tcut[0] < i < tcut[1] for i in tms])

print('|    tmax =', tmax)
print('|    tsum =', tsum)
print('|    tlen =', tlen)
print('|    tcut =', tcut)
print('|    tnum =', tnum)

oracle.close()


print('|\n|  ~ Collecting timing trace:')

oracle = ORACLE.snicat('hitb-25bbb472589a45f45f5f0f8695eccd2a-0.chal.game.ctf.ae')

LEAK = oracle.get_leak()
LEAK_t = int(hashlib.sha256(str(int(1681563399)).encode()).hexdigest(), 16)
LEAK_pk = int(LEAK[0], 16)
LEAK_li = bytes.fromhex(LEAK[3])

while True:
    time.sleep(1)
    t = int(hashlib.sha256(str(int(time.time())).encode()).hexdigest(), 16)
    if (t * inverse(t, P - 1)) % (P - 1) == 1:
        break

FORGE_pk = pow(LEAK_pk, LEAK_t * inverse(t, P - 1), P)
_ = oracle.key_exchange(FORGE_pk)

print('|  ~ Collecting raw timing trace:')

tms = []
for _ in range(100):
    riv = oracle.get_iv()
    t0 = time.time()
    rsp = oracle.send_packet(10*LEAK_li)
    tms += [time.time() - t0]
    print(tms[-1], end='\r', flush=True)

tmax = max(tms)
tsum = sum(tms)
tlen = len(tms)
tcut = (0.3, 0.7)
tnum = sum([tcut[0] < i < tcut[1] for i in tms])

print('|    tmax =', tmax)
print('|    tsum =', tsum)
print('|    tlen =', tlen)
print('|    tcut =', tcut)
print('|    tnum =', tnum)

oracle.close()