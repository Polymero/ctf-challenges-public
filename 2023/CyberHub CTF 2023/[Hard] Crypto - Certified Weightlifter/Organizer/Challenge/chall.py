#!/usr/local/bin/python
#
# by Polymero
#
# for CyberHub CTF 2023
#

# Native imports
import hashlib, secrets
import time, json, base64

# Non-native imports
from Crypto.Util.number import getPrime, inverse, GCD   # pip install pycryptodome

# Local imports
with open('flag.txt', 'rb') as f:
    FLAG = f.read()
    f.close()


# Functions
def B64enc(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

def B64dec(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + '===')

def SquareAndMultiply(x: int, k: int, n: int) -> tuple:
    r, s, t = x, 1, 0
    for _ in range(n.bit_length()):
        if k & 1:
            s *= r
            s %= n
            t += 1
        r *= r
        r %= n
        t += 1
        k >>= 1
    return s, t


# RSA key class object
class RSAKey:

    @staticmethod
    def generate(bits: int) -> object:
        p, q = [getPrime(bits//2) for _ in '01']
        key = RSAKey()
        key.public = {
            'e': 0x10001,
            'n': p * q
        }
        key.private = {
            'p': p,
            'q': q,
            'f': (p - 1) * (q - 1),
            'd': inverse(0x10001, (p - 1) * (q - 1))
        }
        return key
    
    def __repr__(self) -> str:
        return B64enc(self.public['n'].to_bytes(-(-self.public['n'].bit_length()//8), 'big'))
    
    def blindCopy(self) -> tuple:
        while True:
            k = secrets.randbelow(self.private['f'])
            d = k ^ self.private['d']
            if (d < self.private['f']) and (GCD(d, self.private['f']) == 1):
                break
        key = RSAKey()
        key.public = self.public.copy()
        key.public['e'] = inverse(d, self.private['f'])
        key.private = self.private.copy()
        key.private['d'] = d
        return k, key
    

# Server class object
class SERVER:
    def __init__(self, bits: int, n: int) -> object:
        self.users = {}
        self.keys = [RSAKey.generate(bits) for _ in range(n)]
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
        self.promoCodes = {
            'FREE20M23' : 20_000_000,
            ''          : 0         
        }
        
    def registerUser(self, username: str, promo='') -> (int, str):
        if username in self.users:
            return 1, 'ERROR :: Username already registered.'
        if promo not in self.promoCodes:
            return 1, 'ERROR :: Invalid promotional code.'
        self.users[username] = {
            'Count'   : 0,
            'Credits' : self.promoCodes[promo]
        }
        return 0, 'Registration succesful ~ !'
        
    def signCertificate(self, certificate: str) -> (int, str):
        try:
            certificate = json.loads(certificate)
        except:
            return 1, 'ERROR :: Invalid certificate.'
        reqs = ['OWNER', 'TIME', 'PKTYPE', 'PK']
        if any(i not in set(certificate) for i in reqs):
            return 1, 'ERROR :: Incomplete certificate.'
        if certificate['OWNER'] not in self.users:
            return 1, 'ERROR :: Unregistered owner.'
        if certificate['PKTYPE'] not in self.allowed['PKTYPE']:
            return 1, 'ERROR :: Invalid public key type.'
        certhash  = hashlib.sha256(json.dumps(certificate).encode()).hexdigest()
        intrandom = secrets.randbelow(len(self.keys))
        salt, key = self.keys[intrandom].blindCopy()
        sig, cost = SquareAndMultiply(int(certhash, 16), key.private['d'], key.public['n'])
        if self.users[certificate['OWNER']]['Credits'] < cost:
            return 1, 'ERROR :: Insufficient credits.'
        self.users[certificate['OWNER']]['Credits'] -= cost
        self.users[certificate['OWNER']]['Count'] += 1
        signedCertificate = json.dumps({
            'CA'    : 'PolyCert',
            'CTYPE' : 'RSA-2048',
            'CKNUM' : intrandom,
            'CKID'  : B64enc(salt.to_bytes(256, 'big')),
            'CK'    : B64enc(key.public['e'].to_bytes(256, 'big')),
            'HTYPE' : 'SHA2-256',
            'TIME'  : int(time.time()),
            'VALID' : int(time.time()) + 31556736,
            'CERT'  : B64enc(json.dumps(certificate).encode()),
            'SIG'   : B64enc(sig.to_bytes(256, 'big'))
        })
        return 0, signedCertificate

    def verifyCertificate(self, certificate: str) -> (int, str):
        try:
            certificate = json.loads(certificate)
        except:
            return 1, 'ERROR :: Invalid certificate.'
        reqs = ['CA', 'CTYPE', 'CKNUM', 'CKID', 'CK', 'HTYPE',
                'TIME', 'VALID', 'CERT', 'SIG']
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
            keyMod = self.keys[certificate['CKNUM']].public['n']
            keyExp = int.from_bytes(B64dec(certificate['CK']), 'big')
            decSig, _ = SquareAndMultiply(int.from_bytes(B64dec(certificate['SIG']), 'big'), keyExp, keyMod)
            crtHsh = int(hshFun(B64dec(certificate['CERT'])).hexdigest(), 16)
        except:
            return 1, 'ERROR :: Corrupted certificate.'
        if decSig != crtHsh:
            return 1, 'ERROR :: Certificate could not be verified.'
        return 0, 'Certificate verified ~ !'
    

if __name__ == "__main__":

    # Challenge set-up
    server = SERVER(2048, 1)
    server.registerUser('Polymero')

    print('|\n|\n|  [~] Welcome to the PolyCert terminal ~ !')
    print('|\n|  [~] Our current public key rotation:\n{}'.format(server.keys))

    RUN = True
    while True:
        try:

            print('|\n|\n|  [~] Please register a new user:')
            user = input('|  [>] ')

            print('|\n|  [?] Do you have a promotional code?')
            promo = input('|  [>] (Y/N) ').lower()

            if promo == 'y':
                print('|\n|  [~] Please enter your promotional code:')
                promo = input('|  [>] ')
            else:
                promo = ''

            err, ret = server.registerUser(user, promo)
            if err:
                print('|\n|  [!] {}'.format(ret))
            else:
                print('|\n|  [_] {}'.format(ret))
                break

        except KeyboardInterrupt:
            print('|\n|\n|  [~] Goodbye.\n|')
            RUN = False
            break

        except:
            print('|\n|  [!] Something went wrong...\n|')


    # Main server loop
    while RUN:
        try:

            print('|\n|\n|  [~] Menu:\n|  [A] Account Info\n|  [S] Sign Certificate\n|  [V] Verify Certificate\n|  [Q] Quit\n|')
            choice = input('|  [>] ').lower()

            if choice == 'a':
                print('|\n|  [~] {} Account Info:\n{}'.format(user, json.dumps(server.users[user])))

            elif choice == 's':
                cert = input('|  [>] (JSON) ')
                err, ret = server.signCertificate(cert)
                if err:
                    print('|\n|  [!] {}'.format(ret))
                else:
                    print('|\n|  [_] Certificate succesfully signed:\n{}'.format(ret))

            elif choice == 'v':
                cert = input('|  [>] (JSON) ')
                err, ret = server.verifyCertificate(cert)
                if err:
                    print('|\n|  [!] {}'.format(ret))
                else:
                    print('|\n|  [_] {}'.format(ret))

                if not err:
                    cert = json.loads(B64dec(json.loads(cert)['CERT']))
                    if cert['OWNER'] == 'Polymero':
                        flag, _ = SquareAndMultiply(int(FLAG.hex(), 16), 0x10001, int.from_bytes(B64dec(cert['PK']), 'big'))
                        flag    = B64enc(flag.to_bytes(256, 'big'))
                        print('|\n|\n|  [~] Here is a little something on the house:\n{}'.format(flag))
                        break

            elif choice == 'q':
                print('|\n|\n|  [~] Goodbye.\n|')
                break

            else:
                print('|\n|\n|  [!] Uknown option.\n|')

        except KeyboardInterrupt:
            print('|\n|\n|  [~] Goodbye.\n|')
            break

        except:
            print('|\n|  [!] Something went wrong...\n|')