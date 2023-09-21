#!/usr/bin/env python3
#
# by Polymero
#
# for CyberHub CTF 2023
#

# Native imports
import time, json, base64, hashlib

# Non-native imports
from Crypto.Util.number import getPrime, inverse, isPrime   # pip install pycryptodome
from pwn import context, connect, process                   # pip install pwntools
from sage.all import Matrix, GF                             # sage --python solve.py


# Functions
def B64enc(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

def B64dec(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + '===')


# Oracle class object
class ORACLE:
    def __init__(self, s):
        self.s = s

    @staticmethod
    def process(file: str, py='python3') -> object:
        return ORACLE(process([py, file]))
    
    @staticmethod
    def netcat(host: str, port: int) -> object:
        return ORACLE(connect(host, port))
    
    @staticmethod
    def snicat(host: str, port=443) -> object:
        return ORACLE(connect(host, port, ssl=True, sni=host))
    
    def close(self) -> None:
        self.s.close()

    # Interaction fucntions

    def getPublicKey(self) -> int:
        self.s.recvuntil(b':\n[')
        return int.from_bytes(B64dec(self.s.recvuntil(b']\n', drop=True).decode()), 'big')

    def register(self, username: str) -> None:
        self.s.recv()
        self.s.sendline(username.encode())
        self.s.recv()
        self.s.sendline(b'Y')
        self.s.recv()
        self.s.sendline(b'FREE20M23')

    def signCertificate(self, certificate: str) -> str:
        self.s.recv()
        self.s.sendline(b's')
        self.s.recv()
        self.s.sendline(certificate.encode())
        self.s.recvuntil(b':\n')
        return self.s.recvuntil(b'\n', drop=True).decode()
        
    def checkBalance(self) -> int:
        self.s.recv()
        self.s.sendline(b'a')
        self.s.recvuntil(b':\n')
        return json.loads(self.s.recvuntil(b'\n', drop=True).decode())['Credits']
    
    def verifyCertificate(self, certificate: str) -> None:
        self.s.recv()
        self.s.sendline(b'v')
        self.s.recv()
        self.s.sendline(certificate.encode())
        self.s.recvuntil(b'house:\n')
        return int.from_bytes(B64dec(self.s.recvuntil(b'\n', drop=True).decode()), 'big')




# Start
RUNTIME = int(time.time())
print("|\n|  ~ SOLVE SCRIPT for '...'")


# Stage 1
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Collecting signed certificates...'.format(deltaTime // 60, deltaTime % 60))

oracle = ORACLE.process('./[Hard] Crypto - Certified Weightlifter/Organizer/Challenge/chall.py')
# oracle = ORACLE.netcat('0.0.0.0', 5000)

serverPublicKey = oracle.getPublicKey()
oracle.register('Polywoly')

rsaPrivate = {
    'p' : getPrime(1024),
    'q' : getPrime(1024)
}
rsaPrivate['f'] = (rsaPrivate['p'] - 1) * (rsaPrivate['q'] - 1)
rsaPrivate['d'] = inverse(0x10001, rsaPrivate['f'])

rsaPublic = {
    'e' : 0x10001,
    'n' : rsaPrivate['p'] * rsaPrivate['q']
}

userCertificate = json.dumps({
    'OWNER'  : 'Polywoly',
    'PKTYPE' : 'RSA-2048',
    'TIME'   : int(time.time()),
    'PK'     : B64enc(rsaPublic['n'].to_bytes(256, 'big'))
})

print(userCertificate)

signedCerts   = []
balanceChecks = [20_000_000]
for _ in range(2048 + 64):

    print(_, end='\r', flush=True)

    signedCerts   += [oracle.signCertificate(userCertificate)]
    balanceChecks += [oracle.checkBalance()]

hammingVectors = [int.from_bytes(B64dec(json.loads(i)['CKID']), 'big') for i in signedCerts]
hammingVectors = [[int(i) for i in '{:02048b}'.format(j)] for j in hammingVectors]

mathOperations = [balanceChecks[i] - balanceChecks[i+1] for i in range(len(balanceChecks)-1)]
hammingWeights = [i - serverPublicKey.bit_length() for i in mathOperations]

print(hammingWeights[:20])


# Stage 2
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Recovering server private key...'.format(deltaTime // 60, deltaTime % 60))

for keyHammingWeight in range(1024 - 64, 1024 + 64):

    l = 0
    while not isPrime(keyHammingWeight + l):
        l += 1

    hammingMatrix = Matrix(GF(keyHammingWeight + l), hammingVectors)
    weightsVector = Matrix(GF(keyHammingWeight + l), [i + l for i in hammingWeights]).T

    augmentedMatrix = hammingMatrix.augment(weightsVector)
    augmentedRank   = augmentedMatrix.rank()
    echelonForm     = augmentedMatrix.echelon_form()

    recoveredPrivateKey = [int(i > 1) for i in echelonForm.column(-1)[:augmentedRank]]
    print(keyHammingWeight, l, recoveredPrivateKey[:20])
    
    if any(recoveredPrivateKey[:20]):
        serverPrivateKey = int(''.join(str(i) for i in recoveredPrivateKey) + '1', 2)
        print('Found d =', serverPrivateKey)
        break


# Stage 3
deltaTime = int(time.time() - RUNTIME)
print('|\n|  ({}m {}s) Forging a PolyCert Certificate belonging to Polymero...'.format(deltaTime // 60, deltaTime % 60))

forgedCertificate = json.loads(userCertificate).copy()
forgedCertificate['OWNER'] = 'Polymero'

forgedSignedCertificate = json.dumps({
    'CA'    : 'PolyCert',
    'CTYPE' : 'RSA-2048',
    'CKNUM' : 0,
    'CKID'  : B64enc(b'\x00'),
    'CK'    : B64enc(b'\x01\x00\x01'),
    'HTYPE' : 'SHA2-256',
    'TIME'  : int(time.time()),
    'VALID' : int(time.time()) + 31556736,
    'CERT'  : B64enc(json.dumps(forgedCertificate).encode()),
    'SIG'   : B64enc(pow(int(hashlib.sha256(json.dumps(forgedCertificate).encode()).hexdigest(), 16), serverPrivateKey, serverPublicKey).to_bytes(256, 'big'))
})

print(forgedSignedCertificate)

encryptedFlag = oracle.verifyCertificate(forgedSignedCertificate)

flag = pow(encryptedFlag, rsaPrivate['d'], rsaPublic['n'])
flag = flag.to_bytes(-(-flag.bit_length()//8), 'big')
print(flag)
