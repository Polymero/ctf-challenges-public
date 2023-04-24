#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os

# Local imports
FLAG = os.environ.get('FLAG', 'CTFae{d3bug_fl4g}')
if type(FLAG) == str:
    FLAG = FLAG.encode()


# SHA256 hash implementation
class SHA256:

    K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    def __init__(self):
        self.H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        self.buffer = ''
        self.size = 0

    def __roll(self, x: int, r: int) -> int:
        return (x >> r) | ((x << (32 - r)) & 0xffffffff)

    def __compress(self):
        buffer = int(self.buffer[:512], 2).to_bytes(64, 'big')
        w = [int.from_bytes(buffer[i:i + 4], 'big') for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = self.__roll(w[i - 15], 7) ^ self.__roll(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self.__roll(w[i - 2], 17) ^ self.__roll(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w += [(w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff]
        a, b, c, d, e, f, g, h = self.H
        for i in range(64):
            s1 = self.__roll(e, 6) ^ self.__roll(e, 11) ^ self.__roll(e, 25)
            ch = (e & f) ^ ((e ^ 0xffffffff) & g)
            t1 = (h + s1 + ch + self.K[i] + w[i]) & 0xffffffff
            s0 = self.__roll(a, 2) ^ self.__roll(a, 13) ^ self.__roll(a, 22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + mj) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        self.H = [(self.H[i] + j) & 0xffffffff for i,j in enumerate([a,b,c,d,e,f,g,h])]
        self.buffer = self.buffer[512:]

    def update(self, bitString: str or bytes):
        if type(bitString) == bytes:
            bitString = '{:0{n}b}'.format(int.from_bytes(bitString, 'big'), n=8*len(bitString))
        self.buffer += bitString
        self.size += len(bitString)
        while len(self.buffer) >= 512:
            self.__compress()

    def digest(self) -> bytes:
        self.buffer += '1'
        self.buffer += ((512 - 64 - len(self.buffer)) % 512) * '0'
        self.buffer += '{:064b}'.format(self.size)
        while self.buffer:
            self.__compress()
        return b''.join(i.to_bytes(4, 'big') for i in self.H)
    
    def copy(self):
        h = SHA256()
        h.buffer = self.buffer
        h.size = self.size
        h.H = self.H
        return h
    

# Keyed HMAC implementation using SHA256
class HMAC:
    def __init__(self, key: bytes):
        self.inner = SHA256()
        self.outer = SHA256()
        self.inner.update(b'InnerStream::' + key + b'::01')
        self.outer.update(b'OuterStream::' + key + b'::02')

    def update(self, data: str):
        self.inner.update(data)

    def digest(self) -> bytes:
        outer = self.outer.copy()
        inner = self.inner.digest()
        outer.update(inner)
        return outer.digest()
    
    def hexdigest(self) -> str:
        return self.digest().hex()
    

# Pack and unpack functions for fragmented data streams
PACKET_SIZE = 1024
CMDBYT_SIZE = 1
SERIAL_SIZE = 2
LENGTH_SIZE = 2
MACTAG_SIZE = 32

def PackForSending(imacKey: bytes, data: bytes) -> list:
    imacObject = HMAC(imacKey)
    bufferSize = PACKET_SIZE - CMDBYT_SIZE - SERIAL_SIZE - LENGTH_SIZE
    packetList = []
    for i in range(0, len(data), bufferSize):
        bufferData = data[ i : i + bufferSize ]
        imacObject.update(bufferData)
        imacTag = imacObject.digest()
        packetList += [b''.join([
            (1 - int(i == 0)).to_bytes(CMDBYT_SIZE, 'big'),
            (i // bufferSize).to_bytes(SERIAL_SIZE, 'big'),
            (8 * len(bufferData)).to_bytes(LENGTH_SIZE, 'big'),
            bufferData + os.urandom(bufferSize - len(bufferData))
        ])]
    packetList += [b''.join([
        (2).to_bytes(CMDBYT_SIZE, 'big'),
        (i // bufferSize + 1).to_bytes(SERIAL_SIZE, 'big'),
        (8 * MACTAG_SIZE).to_bytes(LENGTH_SIZE, 'big'),
        imacTag + os.urandom(bufferSize - len(imacTag))
    ])]
    return packetList

def UnpackForReceiving(imacKey: bytes, packets: list) -> bytes:
    try:
        unpackets = []
        for packet in packets:
            assert len(packet) == PACKET_SIZE
            unpackets += [{
                'CMD'    : int.from_bytes(packet[ : CMDBYT_SIZE ], 'big'),
                'SERIAL' : int.from_bytes(packet[ CMDBYT_SIZE : SERIAL_SIZE + CMDBYT_SIZE ], 'big'),
                'LENGTH' : int.from_bytes(packet[ SERIAL_SIZE + CMDBYT_SIZE : LENGTH_SIZE + SERIAL_SIZE + CMDBYT_SIZE ], 'big'),
                'DATA'   : packet[ LENGTH_SIZE + SERIAL_SIZE + CMDBYT_SIZE : ]
            }]
        serialised = [[i for i in unpackets if i['SERIAL'] == j][0] for j in range(len(packets))]
        assert len(serialised) == len(packets)
        assert serialised[ 0]['CMD'] == 0
        assert serialised[-1]['CMD'] == 2
        assert all(i['CMD'] == 1 for i in serialised[ 1 : -1 ])
        dataSize = 8 * (PACKET_SIZE - CMDBYT_SIZE - SERIAL_SIZE - LENGTH_SIZE)
        dataBuffer = ''
        imacObject = HMAC(imacKey)
        for packet in serialised[ : -1 ]:
            dataInteger = int.from_bytes(packet['DATA'], 'big') >> (dataSize - packet['LENGTH'])
            dataBitstring = '{:0{n}b}'.format(dataInteger, n=packet['LENGTH'])
            dataBuffer += dataBitstring
            imacObject.update(dataBitstring)
            imacTag = imacObject.digest()
        return int(dataBuffer, 2).to_bytes(-(-len(dataBuffer) // 8), 'big'), imacTag
    except:
        return None
    

# Challenge
m1 = b'CAN I HAB'
m2 = b'FLAG PLS?'
r1 = os.urandom(8).hex().encode()
r2 = os.urandom(8).hex().encode()

imacKey = os.urandom(32)

print('|\n|  ~ Given the following strings ::')
print('|    m1 =', m1.decode())
print('|    m2 =', m2.decode())
print('|    r1 =', r1.decode())
print('|    r2 =', r2.decode())

print('|\n|  ~ Please provide me two streams of fragmented messages such that ::')
print('|    1. The first stream contains m1 and r1, but NOT m2 and r2;')
print('|    2. The second stream contains m2 and r2, but NOT m1 and r1;')
print('|    3. Both streams yield the same HMAC tag.')

print('|\n|  ~ First stream ::')
firstStream = [input()]
while firstStream[-1][1] != '2':
    firstStream += [input()]

print('|\n|  ~ Second stream ::')
secondStream = [input()]
while secondStream[-1][1] != '2':
    secondStream += [input()]

firstStream  = [bytes.fromhex(i) for i in firstStream]
secondStream = [bytes.fromhex(i) for i in secondStream]

firstStream, firstTag = UnpackForReceiving(imacKey, firstStream)
secondStream, secondTag = UnpackForReceiving(imacKey, secondStream)

if all([
    m1     in firstStream,
    m2 not in firstStream,
    r1     in firstStream,
    r2 not in firstStream,
    m1 not in secondStream,
    m2     in secondStream,
    r1 not in secondStream,
    r2     in secondStream,
    firstTag == secondTag
]):
    print(FLAG)