#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Hard] Crypto - PolyCert
#


# Native imports
import base64, hashlib, json, time
from secrets import randbelow


# Non-native imports
from Crypto.Util.number import getPrime, inverse, GCD     # pip install pycryptodome


# Set-up parameters
BITSEC = 2048
KEYNUM = 1


# Functions
def B64Enc(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

def B64Dec(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + '===')

def SquareAndMultiply(x: int, k: int, n: int) -> (int, int):
    r, s, t = x, 1, 0
    for _ in range(n.bit_length()):
        if k & 1:
            s *= r
            t += 1
        r *= r
        t += 1
        k >>= 1
        if s >= n:
            s %= n
            t += 1
        if r >= n:
            r %= n
            t += 1
    return s, t


# RSA key class
class RSAKey:

    @staticmethod
    def generate(bitSec: int) -> object:
        p, q = [getPrime(bitSec // 2) for _ in '01']
        key = RSAKey()
        key.public = {
            'n' : p * q,
            'e' : 0x10001,
        }
        key.private = {
            'p' : p,
            'q' : q,
            'f' : (p - 1) * (q - 1),
            'd' : inverse(key.public['e'], (p - 1) * (q - 1))
        }
        return key

    def __repr__(self) -> str:
        pkbyte = self.public['n'].to_bytes(-(-self.public['n'].bit_length() // 8), 'big')
        return B64Enc(hashlib.sha256(pkbyte).digest())

    def blindedCopy(self) -> (int, object):
        while True:
            k = randbelow(self.private['f'])
            d = self.private['d'] ^ k
            if (d < self.private['f']) and (GCD(d, self.private['f']) == 1):
                break
        key = RSAKey()
        key.public = self.public.copy()
        key.public['e'] = inverse(d, self.private['f'])
        key.private = self.private.copy()
        key.private['d'] = d
        return k, key


# Certificate authority class
class CertAuth:

    def __init__(self, bitSec: int, keyNum: int) -> None:
        self.users = {}
        self.keys = [RSAKey.generate(bitSec) for _ in range(keyNum)]
        self.allowed = {
            'PKTYPE' : ['RSA-1024', 'RSA-2048'],
            'CTYPE'  : ['RSA-2048'],
            'HTYPE'  : {
                'SHA2-256' : hashlib.sha256,
                'SHA2-512' : hashlib.sha512,
                'SHA3-256' : hashlib.sha3_256,
                'SHA3-512' : hashlib.sha3_512
            }
        }

    def registerUser(self, username: str, blocked: bool = False) -> (int, str):
        if username in self.users:
            return 1, 'ERROR :: Username already exists.'
        self.users[username] = {
            'Count'   : 0,
            'Credits' : 20_000_000,
            'Blocked' : blocked
        }
        return 0, 'Registration successful.'
    
    def signCertificate(self, certificate: str) -> (int, str, int):
        try:
            certificate = json.loads(certificate)
        except:
            return 1, 'ERROR :: Invalid certificate.', 0
        reqs = ['OWNER', 'TIME', 'PKTYPE', 'PK']
        if any(i not in set(certificate) for i in reqs):
            return 1, 'ERROR :: Incomplete certificate.', 0
        if certificate['OWNER'] not in self.users:
            return 1, 'ERROR :: Unregistered owner.', 0
        if self.users[certificate['OWNER']]['Blocked']:
            return 1, 'ERROR :: User service unavailable.', 0
        if certificate['PKTYPE'] not in self.allowed['PKTYPE']:
            return 1, 'ERROR :: Invalid public key type.', 0
        certhash  = hashlib.sha256(json.dumps(certificate).encode()).hexdigest()
        intrandom = randbelow(len(self.keys))
        salt, key = self.keys[intrandom].blindedCopy()
        sig, cost = SquareAndMultiply(int(certhash, 16), key.private['d'], key.public['n'])
        if self.users[certificate['OWNER']]['Credits'] < cost:
            return 1, 'ERROR :: Insufficient credits.', 0
        self.users[certificate['OWNER']]['Credits'] -= cost
        self.users[certificate['OWNER']]['Count'] += 1
        signedCertificate = json.dumps({
            'CA'    : 'PolyCert',
            'CTYPE' : 'RSA-2048',
            'CKNUM' : intrandom,
            'CKID'  : B64Enc(salt.to_bytes(256, 'big')),
            'CK'    : B64Enc(key.public['e'].to_bytes(256, 'big')),
            'HTYPE' : 'SHA2-256',
            'TIME'  : int(time.time()),
            'VALID' : int(time.time()) + 31556736,
            'CERT'  : B64Enc(json.dumps(certificate).encode()),
            'SIG'   : B64Enc(sig.to_bytes(256, 'big'))
        })
        return 0, signedCertificate, cost

    def verifyCertificate(self, certificate: str) -> (int, str):
        try:
            certificate = json.loads(certificate)
        except:
            return 1, 'ERROR :: Invalid certificate.'
        reqs = ['CA', 'CTYPE', 'CKNUM', 'CKID', 'CK', 'HTYPE', 'TIME', 'VALID', 'CERT', 'SIG']
        if any(i not in set(certificate) for i in reqs):
            return 1, 'ERROR :: Incomplete certificate.'
        if certificate['CA'] != 'PolyCert':
            return 1, 'ERROR :: Not a PolyCert certificate.'
        if certificate['CTYPE'] not in self.allowed['CTYPE']:
            return 1, 'ERROR :: Invalid certificate type.'
        if certificate['HTYPE'] not in self.allowed['HTYPE']:
            return 1, 'ERROR :: Invalid hash type.'
        if certificate['VALID'] <= int(time.time()):
            return 1, 'ERROR :: Certificate has expired.'
        try:
            hshFun = self.allowed['HTYPE'][certificate['HTYPE']]
            keyObj = self.keys[certificate['CKNUM']]
            keyExp = int.from_bytes(B64Dec(certificate['CK']), 'big')
            assert 1 < int.from_bytes(B64Dec(certificate['SIG']), 'big') < keyObj.public['n']
            assert keyExp == inverse(int.from_bytes(B64Dec(certificate['CKID']), 'big') ^ keyObj.private['d'], keyObj.private['f'])
            decSig, _ = SquareAndMultiply(int.from_bytes(B64Dec(certificate['SIG']), 'big'), keyExp, keyObj.public['n'])
            crtHsh = int(hshFun(B64Dec(certificate['CERT'])).hexdigest(), 16)
        except:
            return 1, 'ERROR :: Corrupted certificate.'
        if decSig != crtHsh:
            return 1, 'ERROR :: Certificate could not be verified.'
        return 0, 'Certificate successfully verified.'