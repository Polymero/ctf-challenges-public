#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Quals
#
# [Hard] Crypto - Sulfur
#


# Native imports
from secrets import randbelow
import base64

# Non-native imports
from Crypto.Util.number import inverse     # pip install pycryptodome


# Encoding functions
def B64Encode(x):
    return base64.urlsafe_b64encode(x).rstrip(b'=').decode()

def B64Decode(x):
    return base64.urlsafe_b64decode(x + '===')


# Elliptic curve parameters
P = 0x8b0efec5088f5bfef9caff56aa590adee016f3e9b547c533629e31488b91c80b
A = 0x3
B = 0x2
O = 0x8b0efec5088f5bfef9caff56aa590adee1ea84ac80fa556a82d7e05d0b86693a


# Elliptic curve point class
class Point:

    def __init__(self, x, y=None):
        self.x = x
        if y:
            self.y = y
        else:
            self.y = self.__class__.lift(x)
            
        if not self.onCurve():
            raise ValueError("Point NOT on Curve ~ !")
        
    def onCurve(self):
        if self.x == 0 and self.y == 1:
            return True
        if ((self.y**2) % P) == ((self.x**3 + A*self.x + B) % P):
            return True
        return False
    
    def encode(self):
        x = int(self.x).to_bytes(-(-P.bit_length() // 8), 'big')
        y = self != self.__class__.lift(self.x)
        return y.to_bytes(1, 'big') + x
    
    @staticmethod
    def decode(xy):
        pbyt = -(-P.bit_length()//8)
        if len(xy) == 2 * pbyt:
            return Point(*[int.from_bytes(i, 'big') for i in [xy[:pbyt], xy[:pbyt]]])
        if len(xy) == pbyt + 1:
            return Point.lift(int.from_bytes(xy[1:], 'big'), yinv=xy[0])
        if len(xy) == pbyt:
            return Point.lift(int.from_bytes(xy, 'big'))
        else:
            raise ValueError("Invalid Point encoding ~ !")
    
    @staticmethod
    def lift(x, yinv=False):
        ySqr = (x**3 + A*x + B) % P
        if yinv:
            return Point(x, (-pow(ySqr, (P + 1) // 4, P)) % P)
        else:
            return Point(x, pow(ySqr, (P + 1) // 4, P))
    
    @staticmethod
    def random():
        while True:
            try:
                return Point.lift(randbelow(P))
            except:
                continue
    
    def __repr__(self):
        return "Point({}, {})".format(self.x, self.y)
    
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
            l = ((3 * self.x**2 + A) * inverse(2 * self.y, P)) % P
            
        x3 = (l**2 - self.x - other.x) % P
        y3 = (l * (self.x - x3) - self.y) % P
        return self.__class__(x3, y3)
    
    def __sub__(self, other):
        if self == self.__class__(0, 1):
            return other
        if other == self.__class__(0, 1):
            return self
        return self + self.__class__(other.x, -other.y)
    
    def __rmul__(self, k):
        out = self.__class__(0, 1)
        tmp = self.__class__(self.x, self.y)
        while k:
            if k & 1:
                out += tmp
            tmp += tmp
            k >>= 1
        return out

# Base point
G = Point(
    0xdc91578d78807c9aab7a9ffbb38d23a45e5f92b3f496873d77753bddbf9214,
    0x762df8582c1685c24749ed45d3ffda62f7941fd5fe83c847435c46669cb097b8
)


# Sulfur encryption class
class Sulfur:
    def __init__(self, key: bytes, n: int) -> object:
        self.N = n
        keyLength = 2 * self.N
        if len(key) != keyLength:
            raise ValueError('Key needs to be {} bytes long ~ !'.format(keyLength))
        keyPiece = [int.from_bytes(key[i:i+2], 'big') for i in range(0,keyLength,2)]
        superInc = [(2 << (self.N + i)) - keyPiece[i] for i in range(self.N)]
        assert all(sum(superInc[:i]) < superInc[i] for i in range(self.N))
        assert sum(superInc) < P
        e = randbelow(P)
        d = inverse(e, P)
        s = [(e * i) * G for i in superInc]
        t = [(e * i) % P for i in superInc]
        p = list(range(self.N))
        p = [p.pop(randbelow(len(p))) for _ in range(len(p))]
        self.public = {
            'S' : [s[i] for i in p],
            'T' : [t[i] for i in p]
        }
        self.private = {
            'e' : e,
            'd' : d,
            'p' : p,
            'q' : superInc
        }
        
    def liftInteger(self, msg: int) -> list:
        xlst = []
        mbit = '{:0{n}b}'.format(msg, n=-(-msg.bit_length()//8)*8)
        for bit in mbit:
            while True:
                x = randbelow(P)
                x = ((x >> 1) << 1) + int(bit)
                try:
                    assert x < P
                    xlst += [Point.lift(x)]
                    break
                except:
                    continue
        return xlst
    
    def encryptMessage(self, msg: bytes) -> bytes:
        plst = self.liftInteger(int.from_bytes(msg,'big'))[::-1]
        pckt = []
        while plst:
            kint = randbelow(P)
            cvec = (kint * G).encode()
            tint = 0
            for i in range(self.N):
                if randbelow(2):
                    try:
                        m = plst.pop(0)
                    except:
                        m = self.liftInteger(0)[0]
                    cvec += (m + kint * self.public['S'][i]).encode()
                    tint += self.public['T'][i]
                else:
                    cvec += Point.random().encode()
            cvec += int(tint % P).to_bytes(1-(-P.bit_length()//8),'big')
            pckt += [cvec]
        return b''.join(pckt)
    
    def solveKnapsack(self, x: int) -> list:
        y = []
        for i in self.private['q'][::-1]:
            if x >= i:
                y += [1]
                x -= i
            else:
                y += [0]
        y = y[::-1]
        return [y[i] for i in self.private['p']]
    
    def decryptMessage(self, msg: bytes) -> bytes:
        pbyt = -(-P.bit_length()//8)
        clst = [msg[i:i+pbyt+1] for i in range(0,len(msg),pbyt+1)]
        cvec = [clst[i:i+(self.N+2)] for i in range(0,len(clst),self.N+2)]
        avec = [self.private['q'][i] for i in self.private['p']]
        mbit = ''
        for c in cvec:
            tint = int.from_bytes(c[-1], 'big')
            xvec = self.solveKnapsack((self.private['d'] * tint) % P)
            kpnt = Point.decode(c[0])
            pvec = [Point.decode(i) for i in c[1:-1]]
            mvec = [pvec[i] - ((self.private['e'] * avec[i]) * kpnt) for i in range(self.N) if xvec[i]]
            mbit += ''.join(str(int(i.x) % 2) for i in mvec)
        mint = int(mbit[::-1], 2)
        return mint.to_bytes(-(-mint.bit_length()//8), 'big')