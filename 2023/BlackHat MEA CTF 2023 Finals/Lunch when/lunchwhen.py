#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Elite] Crypto - Lunch when?
#

# Native imports
from secrets import randbelow
from hashlib import sha256
import os

# Non-native imports
...

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{{{}}}'.format(os.urandom(16).hex()))
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions
def GenerateBox(size, seed=None):
    if seed is None:
        seed = randbelow(2**32)
    box = []
    while len(box) < size:
        seed = int(sha256(str(seed).encode()).hexdigest(), 16)
        x = seed
        while x > size:
            i = x % size
            if i not in box:
                box.append(i)
            x //= size
    return box

def Sbox(state):
    boxes = []
    while state:
        boxes += [state % 2**(ELEM_SIZE)]
        state //= 2**(ELEM_SIZE)
    boxes = [SBOX[i] for i in boxes]
    return sum(j * (2**(ELEM_SIZE))**(len(boxes) - 1 - i) for i,j in enumerate(boxes))

def Pbox(state):
    array = '{:0{n}b}'.format(state, n=ELEM_SIZE*BLOCKSIZE)
    return int(''.join(array[i] for i in PBOX), 2)

def Kmix(state, key):
    return state ^ key

def RandomRoundString():
    return ''.join(''.join(str(i) for i in GenerateBox(5)) for _ in range(NUMROUNDS))

def Encrypt(key, roundString, plaintext):
    if isinstance(plaintext, bytes):
        plaintext = int.from_bytes(plaintext, 'big')
    if isinstance(key, bytes):
        key = int.from_bytes(key, 'big')
    assert 0 <= key < 2**(ELEM_SIZE * BLOCKSIZE)
    blocks = []
    while plaintext:
        blocks += [plaintext % 2**(ELEM_SIZE * BLOCKSIZE)]
        plaintext //= 2**(ELEM_SIZE * BLOCKSIZE)
    ciphertext = []
    for state in blocks[::-1]:
        for r in roundString:
            state = [Sbox(state), Pbox(state), Kmix(state, key), state, state][int(r)]
            key   = [key, key, key, Sbox(key), Pbox(key)][int(r)]
        ciphertext += [state]
    cipherint = sum(j * (2**(ELEM_SIZE * BLOCKSIZE))**(len(ciphertext) - 1 - i)  for i,j in enumerate(ciphertext))
    return int(cipherint).to_bytes(-(-cipherint.bit_length()//8), 'big')


# Header
HDR = r"""
               ████████████████████        
             ██░░░░░░░░░░░░░░░░░░░░██      
           ██░░░░  ██░░░░░░░░  ██░░░░██    
         ██░░░░░░████░░░░░░░░████░░░░░░██  
         ██░░░░▒▒▒▒░░░░████░░░░▒▒▒▒░░░░██  
         ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██  
       ████████████████████████████████████
       ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██
         ████████████████████████████████  
       ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
         ████▒▒▒▒▒▒██▒▒▒▒▒▒▒▒██▒▒▒▒▒▒████  
         ██░░██████░░████████░░██████░░██  
         ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██  
 ___       ████████████████████████████    
(   )                                      .-.
 | |.-.    ___  ___   ___ .-.      .--.   ( __)  ___ .-.
 | /   \  (   )(   ) (   )   \    /    \  (''") (   )   \   
 |  .-. |  | |  | |   | ' .-. ;  ;  ,-. '  | |   | ' .-. ;  
 | |  | |  | |  | |   |  / (___) | |  | |  | |   |  / (___) 
 | |  | |  | |  | |   | |        | |  | |  | |   | |
 | |  | |  | |  | |   | |        | |  | |  | |   | |
 | '  | |  | |  ; '   | |        | '  | |  | |   | |
 ' `-' ;   ' `-'  /   | |        '  `-' |  | |   | |
  `.__.     '.__.'   (___)        `.__. | (___) (___)
                                  ( `-' ;
                                   `.__.
"""
print(HDR)


# Challenge set-up
ELEM_SIZE = 8
BLOCKSIZE = 8
NUMROUNDS = 9
SBOX = GenerateBox(2**ELEM_SIZE)
PBOX = GenerateBox(ELEM_SIZE * BLOCKSIZE)
KEY  = os.urandom((ELEM_SIZE * BLOCKSIZE) // 8)

flagLength = 64
FLAG  = os.urandom(randbelow(flagLength - len(FLAG))) + FLAG
FLAG += os.urandom(flagLength - len(FLAG))

encryptedFlag = Encrypt(KEY, '01234'*NUMROUNDS, FLAG)
print('Here, have some day old McDocolds ~\n{}'.format(encryptedFlag.hex() + bytes(SBOX).hex() + bytes(PBOX).hex()))


# Server loop
while True:
    try:

        plaintext = bytes.fromhex(input('> (hex) ').lower())
        print(Encrypt(KEY, RandomRoundString(), plaintext).hex())

    except KeyboardInterrupt:
        break

    except:
        print('00')
        continue

