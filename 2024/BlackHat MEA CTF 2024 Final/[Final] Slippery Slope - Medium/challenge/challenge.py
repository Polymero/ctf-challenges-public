#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Medium] Crypto - Slippery Slope
#
# by Polymero
#

# Native imports
import os, json, hashlib
from secrets import randbelow
from typing import List, Tuple, Dict

# Non-native imports
from Crypto.Util.number import getPrime, isPrime     # pip install pycryptodome
from Crypto.Cipher import AES

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Global parameters
HASH = hashlib.sha256
KEY_FAMILY = os.urandom(16)
UNIT_DB = {}


# Helper functions
def Ceil(x: int, y: int) -> int:
    """ Returns ceiling division of 'x' by 'y'. """
    return -(-x // y)

def GenSafePrime(pbit: int, qbit: int) -> Tuple[int, int]:
    """ Generates a random prime p ('pbit' bits) with subgroup of size prime q ('qbit' bits). """
    while True:
        q = getPrime(qbit)
        for _ in range(256):
            r = getPrime(pbit - qbit - 1)
            p = (2 * q * r) + 1
            if len(bin(p)[2:]) != pbit:
                continue
            if isPrime(p):
                return p, q
            
def GenGenerator(p: int, q: int) -> int:
    """ Deterministically generates a multiplicative generator of order 'q' for group of size prime 'p'. """
    while True:
        g = pow(2, (p - 1) // q, p)
        if pow(g, q, p) == 1:
            return g
        
def GenChecksumParams(X: int, Y: int, Z: int) -> Tuple[int]:
    """ Generates random parameter list to create checksums of size 'Y' for inputs of size 'X' with density 'Z'. """
    # CX
    u = []
    for _ in range(Y):
        x = 0
        for _ in range(Ceil(X, Y) * Z):
            while True:
                k = 2**randbelow(X)
                if not (x & k):
                    x ^= k
                    break
        u.append(x)
    # CY
    v = Y * [0]
    for i in range(X):
        for _ in range(Ceil(Y, X) * Z):
            while True:
                k = randbelow(Y)
                if not (v[k] & 2**i):
                    v[k] ^= 2**i
                    break
    # CZ
    w = [i ^ j for i,j in zip(u, v)]
    return tuple(w)
        

# Challenge functions
def DoesBigBrotherForbid(packet: Dict[str, str], forbidden: bytes) -> bool:
    """ Checks to see if a forbidden byte-string is present in a packet's plaintext. """
    # Collect
    assert set(packet) == {'iv', 'ct', 'leaf'}
    iv, ct, leaf = [bytes.fromhex(packet[i]) for i in ['iv', 'ct', 'leaf']]
    # Decrypt
    leafDecrypted = AES.new(KEY_FAMILY, AES.MODE_CTR, nonce=iv).decrypt(leaf)
    uid, keyEncrypted = leafDecrypted[:4], leafDecrypted[4:-Y//8]
    keySession = AES.new(UNIT_DB[uid.hex()], AES.MODE_CTR, nonce=iv).decrypt(keyEncrypted)
    # Read
    pt = AES.new(keySession, AES.MODE_CTR, nonce=iv).decrypt(ct)
    return forbidden in pt


# Challenge class
class Shajara:

    __keyFamily = KEY_FAMILY

    def __init__(self, cksmParams: Tuple[int]) -> None:
        """ Initialises class object. """
        # Checksum parameters
        self.csp = cksmParams
        # Encryption parameters
        self.uid = os.urandom(4)
        self.key = os.urandom(16)
        # Session database
        self.sdb = {}
    
    def __Checksum(self, data: bytes) -> bytes:
        """ Returns checksum (Y bits) of given input data (X bits). """
        x = int.from_bytes(data, 'big')
        y = [bin(x & i).count('1') & 1 for i in self.csp]
        z = sum([j * 2**i for i,j in enumerate(y[::-1])])
        return z.to_bytes(Y//8, 'big')
    
    def __Ratchet(self, idUnit: str) -> bytes:
        """ Returns current session key and updates stored key to a new ratcheted key. """
        keyCur = self.sdb[idUnit]
        keyNxt = HASH(b'Shajara.__Ratchet::' + keyCur + b'::KeyRatchet').digest()[:16]
        self.sdb[idUnit] = keyNxt
        return keyCur
    
    def GenIV(self, keySession: bytes) -> Tuple[bytes, bytes]:
        """ Generates random pair of IV and LEAF for Shajara chip-to-chip communication. """
        iv = os.urandom(12)
        ek = self.uid + AES.new(self.key, AES.MODE_CTR, nonce=iv).encrypt(keySession)
        cs = self.__Checksum(iv + keySession + ek)
        return iv, AES.new(self.__keyFamily, AES.MODE_CTR, nonce=iv).encrypt(ek + cs)

    def LoadIV(self, iv: bytes, encryptedLeaf: bytes, keySession: bytes) -> bool:
        """ Checks validity of given IV and LEAF pair. """
        leaf = AES.new(self.__keyFamily, AES.MODE_CTR, nonce=iv).decrypt(encryptedLeaf)
        return self.__Checksum(iv + keySession + leaf[:-4]) == leaf[-4:]

    def InitHandshake(self) -> Tuple[int, int]:
        """ Generates random handshake parameters. """
        x = randbelow(Q)
        y = pow(G, x, P)
        return x, y

    def ParseHandshake(self, secret: int, handshake: int) -> bytes:
        """ Parses generated and received handshake parameters into a shared secret. """
        assert 1 < handshake < P
        assert pow(handshake, Q, P) == 1
        return pow(handshake, secret, P).to_bytes(-(-P.bit_length()//8), 'big')
    
    def InitSession(self, idOther: str, keyMaterial: bytes) -> None:
        """ Initialises session with another Shajara chip given shared key material. """
        keyInit = HASH(b'Shajara.InitSession::' + keyMaterial + b'::KeyMaterial').digest()[:16]
        self.sdb[idOther] = keyInit
        _ = self.__Ratchet(idOther)

    def InitMessage(self, idOther: str, msg: str) -> Dict[str, str]:
        """ Encrypts and packs an input message into a Shajara packet. """
        assert idOther in self.sdb
        keySession = self.__Ratchet(idOther)
        while True:
            iv, leaf = self.GenIV(keySession)
            if self.LoadIV(iv, leaf, keySession):
                break
        ct = AES.new(keySession, AES.MODE_CTR, nonce=iv).encrypt(msg.encode())
        return {
            'iv'   : iv.hex(),
            'ct'   : ct.hex(),
            'leaf' : leaf.hex()
        }

    def ParseMessage(self, idOther: str, packet: Dict[str, str]) -> bytes:
        """ Unpacks and decrypts (if valid) a received Shajara packet. """
        assert idOther in self.sdb
        assert set(packet) == {'iv', 'ct', 'leaf'}
        try:
            iv, ct, leaf = [bytes.fromhex(packet[i]) for i in ['iv', 'ct', 'leaf']]
            keySession = self.__Ratchet(idOther)
            assert self.LoadIV(iv, leaf, keySession)
            pt = AES.new(keySession, AES.MODE_CTR, nonce=iv).decrypt(ct)
            return pt
        except:
            return b''


# Challenge Parameters
X, Y, Z = 8*48, 8*4, 6
CKSM_PARAMS = GenChecksumParams(X, Y, Z)

# Challenge set-up
HDR = r"""|
|                                                                                                                      
|      @@@@@.   @@@       @@@@@ @@@@@@@@.   @@@@@@@@.   @@@@@@@@@ @@@@@@@.  `@@@.     ,@'
|     @@@' `@@. @@@        @@@  @@@    `@@. @@@    `@@. @@@       @@@  `@@.  `@@@.   ,@'
|     `@@@.  `@ @@@        @@@  @@@     ,@@ @@@     ,@@ @@@       @@@   ,@@   `@@@.,@'
|      `@@@.    @@@        @@@  @@@.   ,@@' @@@.   ,@@' @@@@@@@@@ @@@. ,@@'    `@@@@'
|       `@@@.   @@@        @@@  @@@@@@@@@'  @@@@@@@@@'  @@@       @@@@@@@'      `@@@
|   @.   `@@@.  @@@        @@@  @@@         @@@         @@@       @@@`@@        `@@@
|   `@@.  `@@@. @@@        @@@  @@@         @@@         @@@       @@@ `@@.       @@@
|    `@@@@@@@@' @@@@@@@@@ @@@@@ @@@         @@@         @@@@@@@@@ @@@   `@@.     @@@
|  
|     .@@@@@@@.   @ @@@@         ..,,;;;;;;,,,,             @ @@@@@@@@@.   @ @@@@@@@@@@@@
|   .`@@@@@' `@@. @ @@@@   .,;'';;,..,;;;,,,,,.''';;,..     @ @@@@    `@@. @ @@@@
|   @.`@@@@.   @@ @ @@@@,,''                    '';;;;,;''  @ @@@@     `@@ @ @@@@
|   `@.`@@@@.     @ @@@@'    ,;@@;'  ,@@;, @@, ';;;@@;,;';  @ @@@@     ,@@ @ @@@@
|    `@.`@@@@.    @ @@@@  ,;@@@@@'  ;@@@@; ''    ;;@@@@@;;; @ @@@@     ,@@ @ @@@@
|     `@.`@@@@.   @ @@@@ ;;@@@@@;    '''     .,,;;;@@@@@@@;;@ @@@@.   ,@@' @ @@@@@@@@@@@@
|      `@.`@@@@.  @ @@@@;;@@@@@@;           , ';;;@@@@@@@@;;@ @@@@@@@@@@'  @ @@@@
|       `@.`@@@@. @ @@@@ '';@@@@@,.  ,   .   ',;;;@@@@@@;;;;@ @@@@         @ @@@@
|  @@    ;@.`@@@@ @ @@@@    .   '';;;;;;;;;,;;;;@@@@@;;' ,.;@ @@@@         @ @@@@
|  `@@.  ;@.`@@@@ @ @@@@      ''..,,     ''''    '  .,;'    @ @@@@         @ @@@@
|   `@@@@@@@@@@@' @ @@@@@@@@@@@@   '''''';;''''''''         @ @@@@         @ @@@@@@@@@@@@
|"""
print(HDR)

# Generate handshake domain
print('|\n|  [!] Generating handshake domain, please wait...')
P, Q = GenSafePrime(2048, 2032)
G    = GenGenerator(P, Q)

# Init classes
player = Shajara(CKSM_PARAMS)
server = Shajara(CKSM_PARAMS)

# Simulate handshake
privPlayer, pubPlayer = player.InitHandshake()
privServer, pubServer = server.InitHandshake()

# Init shared session
player.InitSession(server.uid.hex(), player.ParseHandshake(privPlayer, pubServer))
server.InitSession(player.uid.hex(), server.ParseHandshake(privServer, pubPlayer))

# Register units
UNIT_DB[player.uid.hex()] = player.key
UNIT_DB[server.uid.hex()] = server.key

# Just a check
assert player.sdb[server.uid.hex()] == server.sdb[player.uid.hex()]
print("|\n|  [~] Chips successfully set up:\n|    PlayerChipID = '{}'\n|    ServerChipID = '{}'".format(player.uid.hex().upper(), server.uid.hex().upper()))


# Server loop
TUI = "|\n|  Menu:\n|    [G]enIV()\n|    [L]oadIV()\n|    [I]nitMessage()\n|    [S]end Packet\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input('|  > ').lower()

        # [Q]uit
        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break


        # [G]enIV()
        elif choice == 'g':
            iv, leaf = player.GenIV(player.sdb[server.uid.hex()])
            print('|\n|    RESP = {}'.format(json.dumps({
                'iv'   : iv.hex(),
                'leaf' : leaf.hex()
            })))


        # [L]oadIV()
        elif choice == 'l':
            while True:
                try:
                    uin = json.loads(input('|\n|  > (JSON) '))
                    assert set(uin) == {'iv', 'leaf'}
                    iv, leaf = [bytes.fromhex(uin[i]) for i in ['iv', 'leaf']]
                    resp = player.LoadIV(iv, leaf, player.sdb[server.uid.hex()])
                    print('|\n|    RESP = {}'.format(resp))
                except:
                    break


        # [I]nitMessage()
        elif choice == 'i':
            uin = input('|\n|  > (str) ')
            resp = player.InitMessage(server.uid.hex(), uin)
            print('|\n|    RESP = {}'.format(json.dumps(resp)))


        # [S]end Packet
        elif choice == 's':
            uin = json.loads(input('|\n|  > (JSON) '))
            assert set(uin) == {'iv', 'ct', 'leaf'}

            # Some snooping...
            if DoesBigBrotherForbid(uin, b'flag'):
                uin['ct'] = b''

            pt = server.ParseMessage(player.uid.hex(), uin)
            if b'flag' in pt:
                print('|\n|  [~] You slipped right past Big Brother ~ !\n|    FLAG = {}'.format(FLAG.decode()))
            else:
                print('|\n|  [~] Server chip succesfully received your message ~ !')


        else:
            print('|\n|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
