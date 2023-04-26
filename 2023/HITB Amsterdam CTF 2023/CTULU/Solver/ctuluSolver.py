#!/usr/bin/env python3
#
# Polymero
#

# Native imports
import os, time, json, hashlib
from secrets import randbelow

# Non-native imports
from pwn import connect, process, context              # pip install pwntools
from Crypto.Util.number import inverse, isPrime, GCD   # pip install pycryptodome

# Sage imports
from sage.all import matrix, QQ, log                   # sage --python ctulupwn.py

# Challenge imports
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



# Solves Hidden Number Problem over known nonce LSBs in DSA signatures
def SolveHNP(sigs, hshs, lsbs, bits, q):

    qbits = len(bin(q)[2:])
    
    print('Expect Solution :: {} ({})'.format(
        len(sigs) * bits > qbits, 
        float(len(sigs) * bits / qbits)
    ))
    
    Rs, Ss = list(zip(*sigs))
    Hs = hshs
    Ks = lsbs

    a = []
    b = []
    X = 2**(qbits - bits)
    
    for h, r, s, k in zip(Hs, Rs, Ss, Ks):
        
        inv = inverse(2**bits, q)
        a += [[(inv * inverse(s, q) * r) % q]]
        b += [inv * (inverse(s, q) * h - k)]

    B = matrix(QQ, len(a) + 2, len(a) + 2)
    
    for i in range(len(a)):
        
        B[len(a), i] = a[i][0]
        B[i, i] = q
        B[len(a) + 1, i] = b[i] - X // 2

    B[len(a), len(a)] = QQ(X) / QQ(q)
    B[len(a) + 1, len(a) + 1] = X

    BLLL = B.LLL()
    
    
    if any(vec[-2] in [X, -X] for vec in BLLL):
        print('Shortest Vector :: True')
    else:
        print('Shortest Vector :: False')
        
    print('Possible Solutions :: {}'.format([vec[-1] // X for vec in BLLL]))

    for vec in BLLL:
        
        if vec[len(a) + 1] == X:
            
            ks = [int(vec[i] + X // 2) for i in range(len(a))]
            xs = (int(vec[len(a)] * q) // X) % q
            print(xs)
            
            if (0 < xs < q) and all(0 < i < q for i in ks):
                print('Found Solution :: True')
                return ks, xs
            
        if vec[len(a) + 1] == -X:
            
            ks = [int(-vec[i] + X // 2) for i in range(len(a))]
            xs = (int(-vec[len(a)] * q) // X) % q
            print(xs)
            
            if (0 < xs < q) and all(0 < i < q for i in ks):
                print('Found Solution :: True')
                return ks, xs
    
    print('Found Solution :: False')
    return None, None


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
    
    def receive(self):
        self.s.recvuntil(b'::\r\n')
        return json.loads(self.s.recvuntil(b'\r\n', drop=True).decode()[5:])
    
    def send(self, handshake):
        self.s.recv()
        self.s.sendline(json.dumps(handshake).encode())
    
    def close(self):
        self.s.close()


# Header
RUNTIME = int(time.time())
print('|\n|  ~ SOLVE SCRIPT for CTULU')

BITLIMIT = 7
N_SEARCH = 200
N_LEAKS  = 64

print('|\n|  ({}m {}s) Searching for server with 2^k | (p - 1) for k >= {}...'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, BITLIMIT))

CALLS = 0
while True:
    CALLS += 1

    # oracle = ORACLE.process('Challenge/ctulu.py')
    oracle = ORACLE.snicat('hitb-25700c5e4b959325ad701052bfc7189e-1.chal.game.ctf.ae')

    staticDomain = oracle.receive()

    a = (staticDomain['p'] - 1) // staticDomain['q']
    K = 0
    while not a & 1:
        K += 1
        a //= 2

    print('|  ({}m {}s) {}, 2^{} | (p - 1)'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, CALLS, K))

    if K < BITLIMIT:
        oracle.close()
        continue

    print('|\n|  ({}m {}s) Looking for r such that order(r) >= {}...'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, 2**BITLIMIT))

    for i in range(N_SEARCH):

        w = randbelow(staticDomain['q'])
        r = pow(w, (staticDomain['p'] - 1) // 2**K, staticDomain['p'])
        s = r % staticDomain['q']
        h = int.from_bytes(hashlib.sha256(str(r).encode()).digest(), 'big')
        y = (r * inverse(pow(staticDomain['g'], h * inverse(r, staticDomain['q']), staticDomain['p']), staticDomain['p'])) % staticDomain['p']

        a = r
        k = 1
        while a != 1:
            k += 1
            a *= r
            a %= staticDomain['p']

        verify = r == (pow(staticDomain['g'], h * inverse(s, staticDomain['q']), staticDomain['p']) * pow(y, r * inverse(s, staticDomain['q']), staticDomain['p'])) % staticDomain['p']

        if (k >= 2**BITLIMIT) and verify:
            break

    if i < N_SEARCH - 1:
        break
    
    print('|    Failed to find an invalid order generator, continuing search...\n|')
    oracle.close()

print('|\n|  ~ Found a server with 2^k = {} ::'.format(k))
print('|    ' + json.dumps(staticDomain))


polyHandshake1 = oracle.receive() # --> y, r, s
polyHandshake2 = oracle.receive() # <-- r, s
polyHandshake3 = oracle.receive() # <-- y', r', s'
polyHandshake4 = oracle.receive() # --> y', r', s'
polyHandshake5 = oracle.receive() # --> c(r', s'), r'', s''
polyHandshake6 = oracle.receive() # <-- r'', s''
polyHandshake7 = oracle.receive() # --> c(r'', s''), r''', s'''
polyHandshake8 = oracle.receive() # <-- r''', s'''
polyHandshake9 = oracle.receive() # <-- c(r'''', s'''')


myInvalidHandshake = {
    'y': y,
    'r': r,
    's': s
    }

print('|\n|  ~ Forged handshake with order(r) = {} ::'.format(k))
print('|    ' + json.dumps(myInvalidHandshake))


print('|\n|  ({}m {}s) Constructing possible ephemeral domains ::'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60))

dummy = CTULU()

domains = []
for i in range(k):

    print('|    {}/{}'.format(i+1, k), end='\r', flush=True)

    sharedSecret = pow(myInvalidHandshake['r'], i, staticDomain['p'])

    p, q, seeds = dummy.generateDomain(1024, 256, sharedSecret)
    g = dummy.generateGenerator(p, q, seeds, 1)

    domains += [{'p': p, 'q': q, 'g': g}]

print('|    Constructed all {} domains.'.format(k))


print('|\n|  ({}m {}s) Farming {} signatures with leaked nonce LSBs ::'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, N_LEAKS))

leaks = []
while len(leaks) < N_LEAKS:

    oracle.s.recvuntil(b'You')

    oracle.send(myInvalidHandshake)

    ctuluStaticResponse    = oracle.receive()
    ctuluEphemeralResponse = oracle.receive()

    for i,domain in enumerate(domains):

        p, q, g = [domain[x] for x in 'pqg']

        h = int.from_bytes(hashlib.sha256(str(ctuluEphemeralResponse['r']).encode()).digest(), 'big')
        u = (h * inverse(ctuluEphemeralResponse['s'], q)) % q
        v = (ctuluEphemeralResponse['r'] * inverse(ctuluEphemeralResponse['s'], q)) % q
        w = (pow(g, u, p) * pow(ctuluEphemeralResponse['y'], v, p)) % p

        if ctuluEphemeralResponse['r'] == w:

            leak = {
                'r': ctuluStaticResponse['r'],
                's': ctuluStaticResponse['s'],
                'h': int.from_bytes(hashlib.sha256(str(ctuluStaticResponse['r']).encode()).digest(), 'big'),
                'k': i
            }

            leaks += [leak]

            print('|    k{:02d} mod {} = {}'.format(len(leaks), k, leak['k']))
            break

    oracle.send({})


sigs = [[i['r'], i['s']] for i in leaks]
hshs = [i['h'] for i in leaks]
lsbs = [i['k'] for i in leaks]

nonces, secret = SolveHNP(sigs, hshs, lsbs, int(log(k) / log(2)), staticDomain['q'])

print(secret, secret % staticDomain['q'])
print(staticDomain['y'] == pow(staticDomain['g'], secret, staticDomain['p']))


h = int.from_bytes(hashlib.sha256(str(polyHandshake2['r']).encode()).digest(), 'big')
ctuluTempSecret = (inverse(polyHandshake2['s'], staticDomain['q']) * (h + polyHandshake2['r'] * secret)) % staticDomain['q']
polySharedSecret = pow(polyHandshake1['r'], ctuluTempSecret, staticDomain['p'])

p, q, seeds = dummy.generateDomain(1024, 256, polySharedSecret)
g = dummy.generateGenerator(p, q, seeds, 1)


ctuluMessage = b' Eternal thanks, my young Adeen '
while len(ctuluMessage) < 128:
    ctuluMessage = b'~' + ctuluMessage + b'~'
print(ctuluMessage)

ctuluOTPKey = bytes([x ^ y for x,y in zip(ctuluMessage[:128], bytes.fromhex(polyHandshake9['c']))])
print(ctuluOTPKey)

polyEphemeralPublic  = polyHandshake4['y']
ctuluEphemeralPublic = polyHandshake3['y']

R, S = polyHandshake8['r'], polyHandshake8['s']
r, s = polyHandshake7['r'], polyHandshake7['s']
h, H = [int.from_bytes(hashlib.sha256(str(i).encode()).digest(), 'big') for i in [r, R]]

u = (H * inverse(S, q)) % q
v = (R * inverse(S, q)) % q
w = (pow(g, u, p) * pow(ctuluEphemeralPublic, v, p)) % p
print(w == R)

u = (h * inverse(s, q)) % q
v = (r * inverse(s, q)) % q
w = (pow(g, u, p) * pow(polyEphemeralPublic, v, p)) % p
print(w == r)

a = pow(g, h * H * inverse(s, q) * inverse(S, q), p)
b = pow(ctuluEphemeralPublic, h * R * inverse(s, q) * inverse(S, q), p)
c = pow(polyEphemeralPublic, H * r * inverse(s, q) * inverse(S, q), p)

GAB = pow(int.from_bytes(ctuluOTPKey, 'big') * inverse(a * b * c, p), s * S * inverse(r, q) * inverse(R, q), p)
print(GAB)


R, S = polyHandshake3['r'], polyHandshake3['s']
r, s = polyHandshake4['r'], polyHandshake4['s']
h, H = [int.from_bytes(hashlib.sha256(str(i).encode()).digest(), 'big') for i in [r, R]]

u = (H * inverse(S, q)) % q
v = (R * inverse(S, q)) % q
w = (pow(g, u, p) * pow(ctuluEphemeralPublic, v, p)) % p
print(w == R)

u = (h * inverse(s, q)) % q
v = (r * inverse(s, q)) % q
w = (pow(g, u, p) * pow(polyEphemeralPublic, v, p)) % p
print(w == r)

a = pow(g, h * H * inverse(s, q) * inverse(S, q), p)
b = pow(ctuluEphemeralPublic, h * R * inverse(s, q) * inverse(S, q), p)
c = pow(polyEphemeralPublic,  H * r * inverse(s, q) * inverse(S, q), p)
d = pow(GAB, r * R * inverse(s, q) * inverse(S, q), p)

K = (a * b * c * d) % p

polyFlag = bytes([x ^ y for x,y in zip(bytes.fromhex(polyHandshake5['c']), K.to_bytes(128, 'big'))])
print(polyFlag)


R, S = polyHandshake5['r'], polyHandshake5['s']
r, s = polyHandshake6['r'], polyHandshake6['s']
h, H = [int.from_bytes(hashlib.sha256(str(i).encode()).digest(), 'big') for i in [r, R]]

u = (H * inverse(S, q)) % q
v = (R * inverse(S, q)) % q
w = (pow(g, u, p) * pow(ctuluEphemeralPublic, v, p)) % p
print(w == R)

u = (h * inverse(s, q)) % q
v = (r * inverse(s, q)) % q
w = (pow(g, u, p) * pow(polyEphemeralPublic, v, p)) % p
print(w == r)

a = pow(g, h * H * inverse(s, q) * inverse(S, q), p)
b = pow(ctuluEphemeralPublic, h * R * inverse(s, q) * inverse(S, q), p)
c = pow(polyEphemeralPublic,  H * r * inverse(s, q) * inverse(S, q), p)
d = pow(GAB, r * R * inverse(s, q) * inverse(S, q), p)

K = (a * b * c * d) % p

polyFlag = bytes([x ^ y for x,y in zip(bytes.fromhex(polyHandshake7['c']), K.to_bytes(128, 'big'))])
print(polyFlag)