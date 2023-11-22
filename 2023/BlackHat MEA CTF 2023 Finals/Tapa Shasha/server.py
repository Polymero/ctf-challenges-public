#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Hard] Crypto - Tapa Shasha
#


# Native imports
import os

# Local imports
from tapashasha import *

# Flag import
FLAG = os.environ.get('FLAG', 'BHFlagY{{{}}}'.format(os.urandom(16).hex()))


# Flag parsing
SECRET = []
flag = int.from_bytes(FLAG.encode(), 'big')
while flag:
    SECRET += [flag % 2**(BITSEC - 1)]
    flag //= 2**(BITSEC - 1)
SECRET = SECRET[::-1]

# Challenge set-up
tapashasha  = TapaShasha(BITSEC, NMAX)
randomTaper = [randbelow(tapashasha.q) for _ in range(len(SECRET))]


# Header
HDR = r"""|
|                  ______              ____
|                 /_  __/             / __ \
|                  / /               / /_/ /
|                 / /               / ____/
|      _____ __  / /__   _____ __  / /__ 
|     / ___// / / /   | / ___// / / /   |
|     \__ \/ /_/ / /| | \__ \/ /_/ / /| |
|    ___/ / __  / ___ |___/ / __  / ___ |
|   /____/_/ /_/_/  |______/_/ /_/_/  |_|
|"""

print(HDR)


# Server loop
print('|\n|  ~ Sharing parameters ::\n|    Size = {}\n|    Kpos = {}\n|    Spos = {}'.format(tapashasha.q, tapashasha.kpos, tapashasha.spos))

while True:
    try:

        n, t = [int(i) for i in input('|\n|  > (n, t) ').strip('()[]').replace(',', ' ').split()]

        if (0 < n <= NMAX - len(SECRET)) and (len(SECRET) <= t <= NMAX):
            print('|\n|  ~ Tapered sharing ::\n|    S = {}'.format(tapashasha.taper(tapashasha.generate(SECRET, n, t), randomTaper)))

        else:
            print('|\n|  ~ You can only tapa the shasha with proper parameters...')

    except KeyboardInterrupt:
        print('\n|\n|  ~ *shashas away* ~ \n|')
        break

    except:
        print('|\n|  ~ Err...')
    