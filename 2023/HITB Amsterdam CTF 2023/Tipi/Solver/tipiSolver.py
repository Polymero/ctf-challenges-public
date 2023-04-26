#!/usr/bin/env python3
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os, time, json, hashlib

# Non-native imports
from pwn import connect, process, context   # pip install pwntools
from Crypto.Util.number import inverse      # pip install pycryptodome
from Crypto.Cipher import AES

# Header
RUNTIME = int(time.time())
print('|\n|  ~ SOLVE SCRIPT for Tipi')


# Static parameters
P = 0xe27773f2a561ed14ba9b1b64042378bc6d221cf5e65af2a43bcfe4e42f938f201575bbbb1a99dfe5468e3ae6a961eb7f97771caca495ea9e00b927fbf2d2b81a78edb9f109a62fbc101b4393de05f7f2d7d3bf947e7ef4b32ee5ab30f30a35fefb72433e0de7e1ffa4f5040acd6d75ecf8061f471fe938d8961300a6c73f4dd9
G = 0x66ba6e0d85fbe037153fca9b8bdfce8052311bda17e19c000ef8acb1ccbaf8c02d2cbb0c5ed1e40989b615ebcd8d8598b793a752867fb873dc36f5f64be05520fb47b01dd804e15abc5f79a8c2ebe7c5abcfa392b85df638a24244279cb2b7042ab8c66ff8d0d005b3cf4f8e492e06ca8f25896dc9a4df5a3ba055ac89118d01

print('|\n|  ~ Chall parameters ::')
print('|    P = {} ({} bits)'.format(P, len(bin(P)) - 2))
print('|    G = {} ({} bits)'.format(G, len(bin(G)) - 2))


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

TCUT = (0.3, 0.7)
ELEN = 10
PNUM = 10
PCUT = PNUM // 5

# Key spoofing
print('|\n|  ({}m {}s) Phase 1 :: Key Spoofing'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60))

while True:

    # context.log_level = 'debug'
    # oracle = ORACLE.process('Challenge/tipi.py')
    oracle = ORACLE.snicat('hitb-25bbb472589a45f45f5f0f8695eccd2a-0.chal.game.ctf.ae')

    LEAK    = oracle.get_leak()
    LEAK_t  = int(hashlib.sha256(str(int(1681563399)).encode()).hexdigest(), 16)
    LEAK_pk = int(LEAK[0], 16)
    LEAK_li = bytes.fromhex(LEAK[3])

    while True:
        time.sleep(1)
        t = int(hashlib.sha256(str(int(time.time())).encode()).hexdigest(), 16)
        if (t * inverse(t, P - 1)) % (P - 1) == 1:
            break

    FORGE_pk = pow(LEAK_pk, LEAK_t * inverse(t, P - 1), P)
    _ = oracle.key_exchange(FORGE_pk)

    print('|\n|  ~  Trying t = {}'.format(t))

    tms = []
    for _ in range(50):
        riv  = oracle.get_iv()
        t0   = time.time()
        rsp  = oracle.send_packet(ELEN*LEAK_li)
        tms += [time.time() - t0]
        print('|    t = {}'.format(tms[-1]), end='\r', flush=True)

    tmax = max(tms)
    tsum = sum(tms)
    tlen = len(tms)
    tnum = sum([TCUT[0] < i < TCUT[1] for i in tms])

    print('|    tmax =', tmax)
    print('|    tsum =', tsum)
    print('|    tlen =', tlen)
    print('|    tcut =', TCUT)
    print('|    tnum =', tnum)

    if tnum > PCUT:
        break

    oracle.close()

print('|\n|    Spoofed key succesfully ~ !')

print('|\n|  ~ Leaked data ::')
print('|    Time hash    = {} ({} bits)'.format(LEAK_t, len(bin(LEAK_t)) - 2))
print('|    Public key   = {} ({} bits)'.format(LEAK_pk, len(bin(LEAK_pk)) - 2))
print('|    Login packet = {} ({} bytes)'.format(LEAK_li.hex(), len(LEAK_li)))


# POA
print('|\n|  ({}m {}s) Phase 2 :: Timing Padding Oracle Attack'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60))

print('|\n|  ~ TPOA paramters ::')
print('|    Elongation factor   = {}'.format(ELEN))
print('|    Probabilistic tries = {}'.format(PNUM))

CALLS = 0
REC_PT = b''
for i in range(0, len(LEAK_li) - 16, 16): # For each block

    print('|\n|  ~ Recovering [-{}:-{}] ::'.format(i+16, i))

    ENC = (ELEN * LEAK_li)[:len(LEAK_li) * ELEN - i]

    REC_BL = b''
    for j in range(16): # For each byte

        X = (16 - len(REC_BL)) * b'\x00' + len(REC_BL) * bytes([len(REC_BL) + 1])
        Y = ENC[-32:-16]
        Z = (16 - len(REC_BL)) * b'\x00' + REC_BL

        FRG  = ENC[:-32]
        FRG += bytes([x ^ y ^ z for x,y,z in zip(X, Y, Z)])
        FRG += ENC[-16:]

        pos_values = {}

        likely_values = list(range(1,11)) + list(range(32, 127))
        for k in likely_values: # For each possible byte value

            frg  = FRG[:-(len(REC_BL) + 16 + 1)]
            frg += bytes([FRG[-(len(REC_BL) + 16 + 1)] ^ (len(REC_BL) + 1) ^ k])
            frg += FRG[-(len(REC_BL) + 16):]

            tms = []
            for _ in range(PNUM): # Probabilistic PO

                if (not REC_BL and k == 1):
                    break

                CALLS += 1
                #print('|    {} calls so far...'.format(CALLS), end='\r', flush=True)

                riv = oracle.get_iv()

                t0 = time.time()
                rsp = oracle.send_packet(frg)
                t1 = time.time()

                print(bytes([k]), t1 - t0, end='\r', flush=True)

                tms += [t1 - t0]

            if sum([TCUT[0] < i < TCUT[1] for i in tms]) > PCUT:
                print([i for i in tms if TCUT[0] < i < TCUT[1]])
                REC_BL = bytes([k]) + REC_BL
                print('|    {}'.format(REC_BL))
                break

            if len(REC_BL) > j:
                break

    REC_PT = REC_BL + REC_PT

oracle.close()

password = REC_PT[:-REC_PT[-1]]
print('|\n|  ~ Recovered password :: __{}'.format(password.decode()))


# Remaining brute-force 
print('|\n|  ({}m {}s) Phase 3 :: Brute-Force Remaining Chars'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60))

oracle = ORACLE.snicat('hitb-25bbb472589a45f45f5f0f8695eccd2a-0.chal.game.ctf.ae')
_  = oracle.get_leak()
_  = oracle.key_exchange(1)
ek = hashlib.sha256(str(1).encode()).digest()[:32]

ALP = b'ABCDEFGHIJKLMNOPQRSTRUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'

print('|')
for k in range(len(ALP)**2):

    try_password = bytes([ALP[k // len(ALP)], ALP[k % len(ALP)]]) + password
    print('|  ~ Trying {} '.format(try_password.decode(), end='\r', flush=True))

    riv  = oracle.get_iv()[-16:]
    pck  = len('admin').to_bytes(2, 'big') + 'admin'.encode() 
    pck += len(try_password).to_bytes(2, 'big') + try_password

    rsp_enc = oracle.send_packet(AES.new(ek, AES.MODE_CBC, riv).encrypt(Pad(pck)))

    if rsp_enc != b'00':
        rsp_dec = AES.new(ek, AES.MODE_CBC, riv).decrypt(bytes.fromhex(rsp_enc.decode()))

        print('|  ~ Found password :: {}'.format(try_password))
        print('|\n|  ~ FLAG :: {}'.format(UnPad(rsp_dec)[2:].decode()))
        print('|')

        oracle.close()
        break

print('|\n|  ({}m {}s) CODE END.'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60))
print('|')
