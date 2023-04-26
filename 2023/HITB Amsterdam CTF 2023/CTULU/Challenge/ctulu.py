#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os, json, hashlib

# Non-native imports
from Crypto.Util.number import inverse, isPrime, GCD   # pip install pycryptodome

# Local imports
FLAG = os.environ.get('FLAG', 'CTFae{d3bug_fl4g}')
if type(FLAG) == str:
    FLAG = FLAG.encode()


# +-----------------------------------------------------------------------------------------------+
# |  CHALLENGE CLASS                                                                              |
# +-----------------------------------------------------------------------------------------------+
class CTULU:
    def __init__(self):
        self.bitSizes = None
        self.staticPublic = None
        self.staticSecret = None
        self.staticDomain = None
        self.ephemeralPublic = None
        self.ephemeralSecret = None
        self.ephemeralDomain = None

    @staticmethod
    def new(l, n, seed=None):
        if seed is None:
            seed = os.urandom(32)
        obj = CTULU()
        obj.bitSizes = (l, n)
        p, q, seeds = obj.generateDomain(l, n, seed)
        staticGenerator = obj.generateGenerator(p, q, seeds, 1)
        obj.staticDomain = {'p': p, 'q': q, 'g': staticGenerator}
        obj.staticSecret, obj.staticPublic, _ = obj.generateKey()
        return obj
    
    @staticmethod
    def fromDomain(domain):
        obj = CTULU()
        assert set(domain) == {'p', 'q', 'g'}
        assert 1 < domain['g'] < domain['p'] - 1
        assert pow(domain['g'], domain['q'], domain['p']) == 1
        obj.bitSizes = tuple([len(bin(i)) - 2 for i in [domain['p'], domain['q']]])
        obj.staticDomain = domain
        obj.staticSecret, obj.staticPublic, _ = obj.generateKey()
        return obj
    
    def generatePrime(self, bits, seed):
        """ Shawe-Taylor Random Prime Generator """
        if type(seed) == bytes:
            seed = int.from_bytes(seed, 'big')
        if bits <= 32:
            pseed = seed
            pcntr = 0
            while True:
                c = int.from_bytes(bytes([i ^ j for i,j in zip(
                    hashlib.sha256(str(pseed).encode()).digest(),
                    hashlib.sha256(str(pseed + 1).encode()).digest()
                )]), 'big')
                c = 2**(bits - 1) + (c % 2**(bits - 1))
                c = (2 * (c // 2)) + 1
                pseed += 2
                pcntr += 1
                if isPrime(c):
                    return c, pseed, pcntr
        c0, pseed, pcntr = self.generatePrime(-(-bits // 2) + 1, seed)
        iters = -(-bits // 256) - 1
        x = 0
        for i in range(iters):
            x += int.from_bytes(hashlib.sha256(str(pseed + i).encode()).digest(), 'big') * 2**(i * 256)
        pseed += iters + 1
        x = 2**(bits - 1) + (x % 2**(bits - 1))
        t = -(-x // (2 * c0))
        while True:
            if (2 * t * c0 + 1) > 2**bits:
                t = -(-2**(bits - 1) // (2 * c0))
            c = 2 * t * c0 + 1
            a = 0
            for i in range(iters):
                a += int.from_bytes(hashlib.sha256(str(pseed + i).encode()).digest(), 'big') * 2**(i * 256)
            pseed += iters + 1
            pcntr += 1
            a = 2 + (a % (c - 3))
            z = pow(a, 2 * t, c)
            t += 1
            if (GCD(z - 1, c) == 1) and (pow(z, c0, c) == 1):
                return c, pseed, pcntr
            
    def generateDomain(self,  l, n, seed):
        """ Constructive Digital Signature Algorithm Generator """
        if type(seed) == bytes:
            seed = int.from_bytes(seed, 'big')
        q, qseed, qcntr = self.generatePrime(n, seed)
        p0, pseed, pcntr = self.generatePrime(-(-l // 2) + 1, qseed)
        iters = -(-l // 256) - 1
        x = 0
        for i in range(iters):
            x += int.from_bytes(hashlib.sha256(str(pseed + 1).encode()).digest(), 'big') * 2**(i * 256)
        pseed += iters + 1
        x = 2**(l - 1) + (x % (2**(l - 1)))
        t = -(-x // (2 * q * p0))
        while True:
            if (2 * t * q * p0 + 1) > 2**l:
                t = -(-2**(l - 1) // (2 * q * p0))
            p = 2 * t * q * p0 + 1
            a = 0
            for i in range(iters):
                a += int.from_bytes(hashlib.sha256(str(pseed + i).encode()).digest(), 'big') * 2**(i * 256)
            pseed += iters + 1
            pcntr += 1
            a = 2 + (a % (p - 3))
            z = pow(a, 2 * t * q, p)
            t += 1
            if (GCD(z - 1, p) == 1) and (pow(z, p0, p) == 1):
                return p, q, (seed, pseed, qseed)
            
    def generateGenerator(self, p, q, seeds, index):
        """ Verifiable Canonical Domain Generator Generator """
        assert 0 <= index < 256
        gseed = b''.join(i.to_bytes(128, 'big') for i in seeds)
        n = len(bin(q)[2:])
        e = (p - 1) // q
        cntr = 0
        while True:
            cntr += 1
            u = gseed + b'ggen' + index.to_bytes(1, 'big') + cntr.to_bytes(2, 'big')
            w = int.from_bytes(hashlib.sha256(u).digest(), 'big')
            g = pow(w, e, p)
            if g > 1:
                return g
            
    def generateKey(self):
        """ Finite Field Cryptography Key Generator """
        if self.ephemeralDomain is None:
            domain = self.staticDomain
        else:
            domain = self.ephemeralDomain
        n = len(bin(domain['q'])[2:])
        c = int.from_bytes(os.urandom(-(-n // 8) + 16), 'big')
        x = (c % (domain['q'] - 1)) + 1
        y = pow(domain['g'], x, domain['p'])
        return x, y, inverse(x, domain['q'])
            
    def initiateHandshake(self):
        if self.ephemeralDomain is None:
            baseSecret, domain = self.staticSecret, self.staticDomain
        else:
            baseSecret, domain = self.ephemeralSecret, self.ephemeralDomain
        selfSecret, sigR, selfInverse = self.generateKey()
        sigHash = int.from_bytes(hashlib.sha256(str(sigR).encode()).digest(), 'big')
        sigS = (selfInverse * (sigHash + baseSecret * sigR)) % domain['q']
        return selfSecret, (sigR, sigS)
    
    def receiveHandshake(self, selfSecret, otherPublic, signature):
        if self.ephemeralDomain is None:
            domain = self.staticDomain
        else:
            domain = self.ephemeralDomain
        sigR, sigS = signature
        assert (0 < sigR < domain['p']) and (0 < sigS < domain['q']) and (0 < otherPublic < domain['p'])
        sigHash = int.from_bytes(hashlib.sha256(str(sigR).encode()).digest(), 'big')
        u = (sigHash * inverse(sigS, domain['q'])) % domain['q']
        v = (sigR * inverse(sigS, domain['q'])) % domain['q']
        w = (pow(domain['g'], u, domain['p']) * pow(otherPublic, v, domain['p'])) % domain['p']
        assert sigR == w
        sharedSecret = pow(sigR, selfSecret, domain['p'])
        if self.ephemeralDomain is None:
            p, q, seeds = self.generateDomain(*self.bitSizes, sharedSecret)
            self.ephemeralDomain = {'p': p, 'q': q, 'g': self.generateGenerator(p, q, seeds, 1)}
            self.ephemeralSecret, self.ephemeralPublic, _ = self.generateKey()
            return None
        else:
            return sharedSecret


# +-----------------------------------------------------------------------------------------------+
# |  CHALLENGE SET-UP                                                                             |
# +-----------------------------------------------------------------------------------------------+
ctulu = CTULU.new(1024, 256)

print('|\n|  ~ Ctulu ::')
print('|    ' + json.dumps({
    'p': ctulu.staticDomain['p'],
    'q': ctulu.staticDomain['q'],
    'g': ctulu.staticDomain['g'],
    'y': ctulu.staticPublic
}))


# +-----------------------------------------------------------------------------------------------+
# |  MY PRIVATE CONVERSATION WITH CTULU                                                           |
# +-----------------------------------------------------------------------------------------------+
poly = CTULU.fromDomain(ctulu.staticDomain)
polySecret,  polySignature  = poly.initiateHandshake()

print('|\n|\n|  ~ Polymero -> Ctulu ::')
print('|    ' + json.dumps({
    'y': poly.staticPublic,
    'r': polySignature[0],
    's': polySignature[1]
}))

ctuluSecret, ctuluSignature = ctulu.initiateHandshake()
ctulu.receiveHandshake(ctuluSecret, poly.staticPublic, polySignature)

print('|\n|  ~ Ctulu -> Polymero ::')
print('|    ' + json.dumps({
    'r': ctuluSignature[0],
    's': ctuluSignature[1]
}))

poly.receiveHandshake(polySecret, ctulu.staticPublic, ctuluSignature)
assert ctulu.ephemeralDomain == poly.ephemeralDomain

ctuluSecret, ctuluSignature = ctulu.initiateHandshake()

print('|\n|  ~ Ctulu -> Polymero ::')
print('|    ' + json.dumps({
    'y': ctulu.ephemeralPublic,
    'r': ctuluSignature[0],
    's': ctuluSignature[1]
}))

polySecret, polySignature = poly.initiateHandshake()
polyOTPKey = poly.receiveHandshake(polySecret, ctulu.ephemeralPublic, ctuluSignature)

print('|\n|  ~ Polymero -> Ctulu ::')
print('|    ' + json.dumps({
    'y': poly.ephemeralPublic,
    'r': polySignature[0],
    's': polySignature[1]
}))

ctuluOTPKey = ctulu.receiveHandshake(ctuluSecret, poly.ephemeralPublic, polySignature)


polyMessage  = b'Here is a gift, oh Old One :: ' + FLAG
ctuluMessage = b''

for i in range(0, len(polyMessage), 128 - 1):

    polyBlock = polyMessage[ i : i + (128 - 1) ]
    polyBlock = len(polyBlock).to_bytes(1, 'big') + polyBlock
    polyBlock += os.urandom(128 - len(polyBlock))
    polyCipher = bytes([x ^ y for x,y in zip(polyBlock, polyOTPKey.to_bytes(128, 'big'))])

    polySecret, polySignature = poly.initiateHandshake()

    print('|\n|  ~ Polymero -> Ctulu ::')
    print('|    ' + json.dumps({
        'c': polyCipher.hex(),
        'r': polySignature[0],
        's': polySignature[1]
    }))

    ctuluPacket = bytes([x ^ y for x,y in zip(polyCipher, ctuluOTPKey.to_bytes(128, 'big'))])
    ctuluMessage += ctuluPacket[ 1 : ctuluPacket[0] + 1 ]

    ctuluSecret, ctuluSignature = ctulu.initiateHandshake()
    ctuluOTPKey = ctulu.receiveHandshake(ctuluSecret, poly.ephemeralPublic, polySignature)

    print('|\n|  ~ Ctulu -> Polymero ::')
    print('|    ' + json.dumps({
        'r': ctuluSignature[0],
        's': ctuluSignature[1]
    }))

    polyOTPKey = poly.receiveHandshake(polySecret, ctulu.ephemeralPublic, ctuluSignature)

assert polyMessage == ctuluMessage


ctuluMessage = b' Eternal thanks, my young Adeen '
while len(ctuluMessage) < 128:
    ctuluMessage = b'~' + ctuluMessage + b'~'

ctuluCipher = bytes([x ^ y for x,y in zip(ctuluMessage[:128], ctuluOTPKey.to_bytes(128, 'big'))])

print('|\n|  ~ Ctulu -> Polymero ::')
print('|    ' + json.dumps({
    'c': ctuluCipher.hex()
}))


# +-----------------------------------------------------------------------------------------------+
# |  NOW IT'S YOUR TURN TO TALK TO CTULU                                                          |
# +-----------------------------------------------------------------------------------------------+
ctulu.ephemeralDomain = None
ctulu.ephemeralPublic = None
ctulu.ephemeralSecret = None
ctuluOTPKey = None

while True:

    try:

        print('|\n|  ~ You -> Ctulu ::')
        yourInput = json.loads(input('|    > (JSON) '))


        if set(yourInput) == {'y', 'r', 's'}:
            
            yourStaticPublic = yourInput['y']
            yourSignature = (yourInput['r'], yourInput['s'])

            ctulu.ephemeralDomain = None
            ctulu.ephemeralPublic = None
            ctulu.ephemeralSecret = None
            ctuluSecret, ctuluSignature = ctulu.initiateHandshake()

            print('|\n|  ~ Ctulu -> You ::')
            print('|    ' + json.dumps({
                'r': ctuluSignature[0],
                's': ctuluSignature[1]
            }))

            ctulu.receiveHandshake(ctuluSecret, yourStaticPublic, yourSignature)
            ctuluSecret, ctuluSignature = ctulu.initiateHandshake()

            print('|\n|  ~ Ctulu -> You ::')
            print('|    ' + json.dumps({
                'y': ctulu.ephemeralPublic,
                'r': ctuluSignature[0],
                's': ctuluSignature[1]
            }))

            print('|\n|  ~ You -> Ctulu ::')
            yourInput = json.loads(input('|    > (JSON) '))

            assert set(yourInput) == {'y', 'r', 's'}

            yourEphemeralPublic = yourInput['y']
            yourSignature = (yourInput['r'], yourInput['s'])

            ctuluOTPKey = ctulu.receiveHandshake(ctuluSecret, yourEphemeralPublic, yourSignature)


        if set(yourInput) == {'c', 'r', 's'}:
            
            yourCipher = bytes.fromhex(yourInput['c'])
            yourSignature = (yourInput['r'], yourInput['s'])

            yourMessage = bytes([x ^ y for x,y in zip(yourCipher, ctuluOTPKey.to_bytes(128, 'big'))])
            yourMessage = yourMessage[ 1 : yourMessage[0] + 1 ]

            ctuluSecret, ctuluSignature = ctulu.initiateHandshake()
            ctuluOTPKey = ctulu.receiveHandshake(ctuluSecret, yourEphemeralPublic, yourSignature)

            print('|\n|  ~ Ctulu -> You ::')
            print('|    ' + json.dumps({
                'r': ctuluSignature[0], 
                's': ctuluSignature[1]
                }))
            
            if b'flag' in yourMessage:

                ctuluMessage = ' That is beyond your light cone, young Adeen '
                while len(ctuluMessage) < 128:
                    ctuluMessage = b'~' + ctuluMessage + b'~'

                ctuluCipher = bytes([x ^ y for x,y in zip(ctuluMessage[:128], ctuluOTPKey.to_bytes(128, 'big'))])
                ctuluSecret, ctuluSignature = ctulu.initiateHandshake()

                print('|\n|  ~ Ctulu -> You ::')
                print('|    ' + json.dumps({
                    'c': ctuluCipher.hex(),
                    'r': ctuluSignature[0],
                    's': ctuluSignature[1]
                }))

                print('|\n|  ~ You -> Ctulu ::')
                yourInput = json.loads(input('|    > (JSON) '))

                assert set(yourInput) == {'r', 's'}

                yourSignature = (yourInput['r'], yourInput['s'])

                ctuluOTPKey = ctulu.receiveHandshake(ctuluSecret, yourEphemeralPublic, yourSignature)


    except KeyboardInterrupt:
        break

    except:
        continue
