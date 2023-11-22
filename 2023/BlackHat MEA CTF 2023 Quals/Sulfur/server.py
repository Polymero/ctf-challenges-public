#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Quals
#
# [Hard] Crypto - Sulfur
#


# Native imports
import os

# Local imports
from sulfur import *

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'FLAG{TH1S_1S_JUST_S0M3_D3BUG_FL4G}').encode()


# Challenge set-up
slfr = Sulfur(os.urandom(64), 32)


# Server loop
HDR = """|
|    +---------------------+ 
|    | 16            32.06 |
|    |        _______      |
|    |       /  ___  |     |
|    |      |  (__ \_|     |
|    |       '.___`-.      |
|    |      |`\____) |     |
|    |      |_______.'     |
|    |                     |
|    |        Sulfur       |
|    |                     |
|    | [Ne]3s2.3p4 (2,8,6) |
|    +---------------------+"""

print(HDR)

print('|\n|  ~ Public key ::')
print('|    S = "{}"'.format(B64Encode(b''.join(i.encode() for i in slfr.public['S']))))
print('|    T[0] = "{}"'.format(B64Encode(slfr.public['T'][0].to_bytes(-(-P.bit_length()//8),'big'))))

print('|\n|  ~ Encrypted flag ::')
print('|    F = "{}"'.format(B64Encode(slfr.encryptMessage(FLAG))))

print('|\n|  ~ Good luck ~ !\n|\n|')
