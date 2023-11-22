#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Quals
#
# [Easy] Crypto - Octopodal
#


# Native imports
import os
from sympy.ntheory import legendre_symbol

# Non-native imports
from Crypto.Util.number import getPrime     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('FLAG', 'FLAG{TH1S_1S_JUST_S0M3_D3BUG_FL4G}').encode()


# Challenge set-up
primeNumber = 8
primeBits   = 24
primeList   = [getPrime(primeBits) for _ in range(primeNumber)]

modulus = 1
for prime in primeList:
    modulus *= prime
    
base = 2


# Server loop
HDR = """|
|     _______ _______ _______ _______ _______ _______ ______   _______ ___     
|    |   _   |   _   |       |   _   |   _   |   _   |   _  \ |   _   |   |    
|    |.  |   |.  1___|.|   | |.  |   |.  1   |.  |   |.  |   \|.  1   |.  |    
|    |.  |   |.  |___`-|.  |-|.  |   |.  ____|.  |   |.  |    |.  _   |.  |___ 
|    |:  1   |:  1   | |:  | |:  1   |:  |   |:  1   |:  1    |:  |   |:  1   |
|    |::.. . |::.. . | |::.| |::.. . |::.|   |::.. . |::.. . /|::.|:. |::.. . |
|    `-------`-------' `---' `-------`---'   `-------`------' `--- ---`-------'
|"""
print(HDR)

k = modulus.bit_length() // (8 + 1)
flagPieces = [int.from_bytes(FLAG[i:i+k], 'big') for i in range(0, len(FLAG), k)]

encryptedPieces = [pow(base, i, modulus) for i in flagPieces]
print('|\n|  ~ Flag pieces:')
for i,j in enumerate(encryptedPieces):
    print('|    {}: 0x{:0{n}x}'.format(i, j, n=-(-modulus.bit_length()//4)))
    
def LegSum(x, primes):
    return sum(legendre_symbol(x, p) for p in primes)

while True:
    try:
        
        x = int(input('|\n|  > (int) '))
        print('|    L = {}'.format(LegSum(x, primeList)))
        
    except KeyboardInterrupt:
        print('\n|\n|  ~ Sum you later ~ !\n|')
        break
        
    except:
        print('|\n|  ~ Ehm are you alright ~ ?')
        
