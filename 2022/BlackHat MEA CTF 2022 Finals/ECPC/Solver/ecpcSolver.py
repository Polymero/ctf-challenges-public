#!/usr/bin/env python3
#
# Polymero
#

# Imports
from Crypto.Util.number import inverse
from secrets import randbelow
from hashlib import sha256
import os, base64
from pwn import *


# Curve 25519 :: By^2 = x^3 + Ax^2 + x  mod P 
P = 2**255 - 19
A = 486662
B = 1
O = 7237005577332262213973186563042994240857116359379907606001950938285454250989

# ECC Class
class Point:
    def __init__(self, x, y=None):
        self.x = x
        if y:
            self.y = y
        else:
            self.y = self.__class__.lift_x(x)
            
        if not self.is_on_curve():
            raise ValueError("Point NOT on Curve 25519!")
        
    def is_on_curve(self):
        if self.x == 0 and self.y == 1:
            return True
        if ((self.x**3 + A * self.x**2 + self.x) % P) == ((B * self.y**2) % P):
            return True
        return False
    
    @staticmethod
    def lift_x(x):
        y_sqr = ((x**3 + A * x**2 + x) * inverse(B, P)) % P
        v = pow(2 * y_sqr, (P - 5) // 8, P)
        i = (2 * y_sqr * v**2) % P
        return Point(x, (y_sqr * v * (1 - i)) % P)
    
    def __repr__(self):
        return "Point ({}, {}) on Curve 25519".format(self.x, self.y)
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
        
    def __add__(self, other):
        if self == self.__class__(0, 1):
            return other
        if other == self.__class__(0, 1):
            return self
        
        if self.x == other.x and self.y != other.y:
            return self.__class__(0, 1)
        
        if self.x != other.x:
            l = ((other.y - self.y) * inverse(other.x - self.x, P)) % P
        else:
            l = ((3 * self.x**2 + 2 * A * self.x + 1) * inverse(2 * self.y, P)) % P
            
        x3 = (l**2 - A - self.x - other.x) % P
        y3 = (l * (self.x - x3) - self.y) % P
        return self.__class__(x3, y3)
    
    def __rmul__(self, k):

        # Added functionality for negative multiplication
        if k < 0:
            tmp = self.__class__(self.x, P - self.y)
            k *= -1

        else:
            tmp = self.__class__(self.x, self.y)

        out = self.__class__(0, 1)
        while k:
            if k & 1:
                out += tmp
            tmp += tmp
            k >>= 1
        return out

# Base Point
G = Point.lift_x(9)


# SHA256 LEA Class
def ROT(x, a, size=32):
    return (x >> a) | (x << size - a)

def SIG0(x):
    return ROT(x, 7) ^ ROT(x, 18) ^ (x >> 3)

def SIG1(x):
    return ROT(x, 17) ^ ROT(x, 19) ^ (x >> 10)

def CAPSIG0(x):
    return ROT(x, 2) ^ ROT(x, 13) ^ ROT(x, 22)

def CAPSIG1(x):
    return ROT(x, 6) ^ ROT(x, 11) ^ ROT(x, 25)

def CH(x, y, z):
    return (x & y) ^ (~x & z)

def MAJ(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

class SHA256_LEA:
    def __init__(self):
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x9b05688c, 0x510e527f, 0x1f83d9ab, 0x5be0cd19]
        self.nbits = 0

    def pad(self, msg, extra_msg_bitlen=0):
        nbits = len(msg) * 8 + extra_msg_bitlen
        msg += b"\x80"
        while (len(msg) * 8 + 64) % 512:
            msg += b"\x00"
        msg += nbits.to_bytes(8, "big")
        return msg

    def inject(self, pre_hash, pre_len):
        assert len(pre_hash) == 32
        self.pre_hash = pre_hash
        self.pre_len  = pre_len

        self.H = [int.from_bytes(pre_hash[4*i:4*(i+1)], 'big') for i in range(8)]
        self.nbits = -(-pre_len // 64) * 512

    def digest(self, msg):
        h0, h1, h2, h3, h4, h5, h6, h7 = self.H

        # Pad
        padmsg = self.pad(msg, self.nbits)
        blocks = [padmsg[i:i+64] for i in range(0, len(padmsg), 64)]

        # Hash computation
        for block in blocks:

            # Create message schedule
            schedule = []
            for i in range(64):

                if i <= 15:
                    schedule += [int.from_bytes(block[4*i:4*(i+1)], 'big')]

                else:
                    t1 = SIG1(schedule[i-2])
                    t2 = schedule[i-7]
                    t3 = SIG0(schedule[i-15])
                    t4 = schedule[i-16]
                    schedule += [(t1 + t2 + t3 + t4) % 2**32]

            # Working variables
            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

            for i in range(64):

                t1 = (h + CAPSIG1(e) + CH(e, f, g) + self.K[i] + schedule[i]) % 2**32
                t2 = (CAPSIG0(a) + MAJ(a, b, c)) % 2**32

                h, g, f, e, d, c, b, a = g, f, e, (d + t1) % 2**32, c, b, a, (t1 + t2) % 2**32

            h0 = (h0 + a) % 2**32
            h1 = (h1 + b) % 2**32
            h2 = (h2 + c) % 2**32
            h3 = (h3 + d) % 2**32
            h4 = (h4 + e) % 2**32
            h5 = (h5 + f) % 2**32
            h6 = (h6 + g) % 2**32
            h7 = (h7 + h) % 2**32

        hsh = b"".join(i.to_bytes(4, 'big') for i in [h0, h1, h2, h3, h4, h5, h6, h7])
        payload = self.pad(b"\x00" * self.pre_len)[self.pre_len:] + msg
        
        return hsh, payload


# Connection
host = '0.0.0.0'
port = 5000

s = connect(host, port)

s.recvuntil(b"Connection_ID = ")
Qhash = int(s.recvuntil(b"\n", drop=True).decode()).to_bytes(32, 'big')

s.recvuntil(b"Encrypted_Flag = ")
encflag = s.recvuntil(b"\n", drop=True)

Qtrue = None
for Qlen in [179, 178, 177, 176, 175]:
    print("|\n|  ~ Now trying Qlen = {} ::".format(Qlen))

    msg = b"1"
    sha_lea = SHA256_LEA()

    sha_lea.inject(Qhash, Qlen)

    lea_hash, lea_payload = sha_lea.digest(msg)
    print("|    Payload = {}".format(lea_payload.hex()))

    s.recv()
    s.sendline(lea_payload.hex().encode())

    s.recvuntil(b"(r, s) = ")
    R, S = [int(i) for i in s.recvuntil(b"\n", drop=True).decode()[1:-1].split(', ')]
    print("|    Signature = ({})".format(R, S))

    Rinv = inverse(R, O)
    lea_hint = int.from_bytes(lea_hash, 'big')

    for cof in range(8):

        try:

            Rp = Point.lift_x(R + cof * O)
            Rm = Point(Rp.x, P - Rp.y)

            Qp = Rinv * S * Rp + (-Rinv * lea_hint) * G
            Qm = Rinv * S * Rm + (-Rinv * lea_hint) * G

            for Q in [Qp, Qm]:

                print("|    Found {}".format(Q))

                if sha256(str(Q).encode()).digest() == Qhash:
                    Qtrue = Q

        except Exception as e:
            print("|    ERROR -- {}".format(e))
            continue

if Qtrue:
    print("|\n|  ~ Found the public key! ::")
    print("|    Q = {}".format(Qtrue))
else:
    print("|\n|  ~ Something went wrong while recovering the public key...\n|")
    exit(1)

s.close()


# Decryption
def ecdsa_verify(h, sig, Q):
    r, s = sig
    if r > 0 and r < O and s > 0 and s < O:
        u1 = (h * inverse(s, O)) % O
        u2 = (r * inverse(s, O)) % O
        if r == (u1 * G + u2 * Q).x % O:
            return True
    return False

def decrypt(cip, pub, h):
    out = ''
    sigs = [cip[i:i+86] for i in range(0, len(cip), 86)]
    for sig in sigs:
        r, s = [int.from_bytes(base64.urlsafe_b64decode(i + b"==="), 'big') for i in (sig[:43], sig[43:])]
        if ecdsa_verify(h, (r, s), pub):
            out += '1'
        else:
            out += '0'
    return int(out, 2).to_bytes(-(-len(out)//8), 'big')

flag = decrypt(encflag, Qtrue, int.from_bytes(sha256(str(Qtrue).encode() + msg).digest(), 'big'))
print("|\n|  ~ Recovered the flag ::")
print("|    {}".format(flag))

print("|")