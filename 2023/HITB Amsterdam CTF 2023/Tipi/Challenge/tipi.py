#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os, time, hashlib, base64

# Non-native imports
from Crypto.Cipher import AES   # pip install pycryptodome

# Local imports
from DATABASE import SECRET_KEY, ADMIN_PWD
FLAG = os.environ.get('FLAG', 'CTFae{d3bug_fl4g}')
if type(FLAG) == str:
    FLAG = FLAG.encode()


# Update static secrets to be different for every team (and to prevent progress loss upon connection drop)
otp = b''
while len(otp) < len(SECRET_KEY):
    otp += hashlib.sha256(b'OTP::' + FLAG + b'::SECRET_KEY::' + len(otp).to_bytes(2, 'big')).digest()
SECRET_KEY = bytes([i ^ j for i,j in zip(SECRET_KEY, otp)])

otp = b''
while len(otp) < len(ADMIN_PWD):
    otp += hashlib.sha256(b'OTP::' + FLAG + b'::ADMIN_PWD::' + len(otp).to_bytes(2, 'big')).digest()
ADMIN_PWD = base64.urlsafe_b64encode(bytes([i ^ j for i,j in zip(ADMIN_PWD, otp)])).rstrip(b'=')


# Static domain parameters
P = 0xe27773f2a561ed14ba9b1b64042378bc6d221cf5e65af2a43bcfe4e42f938f201575bbbb1a99dfe5468e3ae6a961eb7f97771caca495ea9e00b927fbf2d2b81a78edb9f109a62fbc101b4393de05f7f2d7d3bf947e7ef4b32ee5ab30f30a35fefb72433e0de7e1ffa4f5040acd6d75ecf8061f471fe938d8961300a6c73f4dd9
G = 0x579d87f6cd3b0cdbdd1fd1fb27cb4fd631da81252c1aaf1d7ce903b07bae6a8ebb148754259c7750257f382f67a498486e8b7fe41f8214696584460680fa8247f38e1709c69f97704c2af367bf5f4bbad88b7f41cd8416918220681a9b53566d7dd923c7bc78895c84a73c05b97498ae9552005283fc51e93566a253e79e366a


# RNG class
class RNG:
    def __init__(self, seed: int):
        self.MK = hashlib.sha256(b'RNG::' + str(seed).encode() + b'::init()').digest()
        self.i  = 0

    def get(self, lbyt: int):
        buf = b''
        while len(buf) < lbyt:
            inp = b'RNG::' + self.MK + '::get({})'.format(lbyt).encode()
            buf += hashlib.sha256(inp + self.i.to_bytes(8, 'big')).digest()
            self.i += 1
        return buf[:lbyt]
    

# Padding functions
def Pad(x):
    x = (int(time.time()*1000) % 2**40).to_bytes(5, 'big') + x
    x += (16 - len(x) % 16) * bytes([16 - len(x) % 16])
    return x

def UnPad(x):
    assert x[-x[-1]:] == x[-1] * bytes([x[-1]])
    assert int.from_bytes(x[:5], 'big') <= int(time.time()*1000) % 2**40
    return x[5:-x[-1]]


# Password hashing function
def PasswordHash(pwd, n=100_000):
    i = hashlib.sha256(b'i::' + pwd[:len(pwd) // 2]).digest()
    j = hashlib.sha256(b'j::' + pwd[len(pwd) // 2:]).digest()
    for _ in range(n):
        j = hashlib.sha256(i + b'::j::' + j).digest()
        i = hashlib.sha256(j + b'::i::' + i).digest()
    return hashlib.sha256(b'PasswordHash::' + i + j + b'::' + str(n).encode()).digest()

USER_DATABASE = {
    'admin' : PasswordHash(ADMIN_PWD).hex()
}



# Generate leaked admin login
adminSecret = int.from_bytes(os.urandom(32), 'big')
adminPublic = pow(G, adminSecret, P)

serverSecret = int(hashlib.sha256(str(1681563399).encode()).hexdigest(), 16)
serverPublic = pow(G, serverSecret * int.from_bytes(SECRET_KEY, 'big'), P)

keyMaterial = pow(serverPublic, adminSecret, P)
encryptionKey = hashlib.sha256(str(keyMaterial).encode()).digest()[:32]

serverRNG = RNG(keyMaterial + serverSecret)
randomIV = serverRNG.get(16)
maskedIV = (keyMaterial * int.from_bytes(randomIV, 'big')) % P

username = b'admin'
password = ADMIN_PWD
token  = len(username).to_bytes(2, 'big') + username
token += len(password).to_bytes(2, 'big') + password
token  = AES.new(encryptionKey, AES.MODE_CBC, randomIV).encrypt(Pad(token))

response = len(FLAG).to_bytes(2, 'big') + FLAG
response = AES.new(encryptionKey, AES.MODE_CBC, randomIV).encrypt(Pad(response))

print('Leaked admin login interaction ::')
print([
    adminPublic.to_bytes(128, 'big').hex(),
    serverPublic.to_bytes(128, 'big').hex(),
    maskedIV.to_bytes(128, 'big').hex(),
    token.hex(),
    response.hex()
])



# YOUR TURN!
print('\nYour turn ::')
# Key exchange
while True:
    try:

        userPublic = int(input(), 16)

        tempSecret = int(hashlib.sha256(str(int(time.time())).encode()).hexdigest(), 16)
        tempPublic = pow(G, tempSecret * int.from_bytes(SECRET_KEY, 'big'), P)

        keyMaterial = pow(userPublic, tempSecret * int.from_bytes(SECRET_KEY, 'big'), P)
        encryptionKey = hashlib.sha256(str(keyMaterial).encode()).digest()[:32]

        serverRNG = RNG(keyMaterial + tempSecret)

        print(tempPublic.to_bytes(128, 'big').hex())

        break

    except KeyboardInterrupt:
        exit()

    except:
        print(b'\x00'.hex())


# Login
while True:
    try: 

        randomIV = serverRNG.get(16)
        maskedIV = (keyMaterial * int.from_bytes(randomIV, 'big')) % P
        print(maskedIV.to_bytes(128, 'big').hex())

        userPacket = bytes.fromhex(input())
        parse = UnPad(AES.new(encryptionKey, AES.MODE_CBC, randomIV).decrypt(userPacket))
        
        usrLength = int.from_bytes(parse[:2], 'big')
        usrData, parse = parse[2:2 + usrLength], parse[2 + usrLength:]

        pwdLength = int.from_bytes(parse[:2], 'big')
        pwdData, parse = parse[2:2 + pwdLength], parse[2 + pwdLength:]

        pwdhash = PasswordHash(pwdData).hex()

        assert USER_DATABASE[usrData.decode()] == pwdhash

        serverPacket = len(FLAG).to_bytes(2, 'big') + FLAG
        print(AES.new(encryptionKey, AES.MODE_CBC, randomIV).encrypt(Pad(serverPacket)).hex())

        break

    except KeyboardInterrupt:
        exit()

    except:
        print(b'\x00'.hex())
