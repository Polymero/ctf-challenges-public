#!/usr/bin/env python3
#
# Polymero
#
# Solve script for [Psychophobia] from [idekctf 2022*]
#

# Imports
from pwn import *
from time import time
from Crypto.Util.number import inverse, GCD


# Globals
O = 57896044618658097711785492504343953926856930875039260848015607506283634007912

# Functions
def mu(x):
    return (x * inverse(x, O)) % O

while True:

    # Server connection
    # s = connect('psychophobia.chal.idek.team', 1337)
    S = process(['python3', 'psychophobia.py'])

    # 1. Send username such that hash value has multiplicity of eight
    S.recv()
    S.sendline(b'Polymeme')

    t0 = time()
    for k in range(500):
        t1 = (time() - t0) / (k + 1) * (500 - k - 1)
        print('|  ~ {}/500 (ETA {}m {}s)   '.format(k+1, int(t1)//60, int(t1)%60), end='\r', flush=True)

        # 2. Receive broken signature (r, s)
        S.recvuntil(b':: (')
        r, s = [int(i) for i in S.recvuntil(b')\n', drop=True).decode().split(', ')]
        S.recv()

        # 3. Find best guess for multiplicity of nonce 'k'
        mr, ms = [mu(i) for i in [r, s]]

        if mr == 8:
            mk = 4
        elif mr == ms:
            mk = 4
        else:
            mk = 8

        # 4. Fix the broken signature using mu(k) and add O//8 if necessary
        s_fix = (inverse(mk, O//8) * s) % (O//8)
        if not s_fix & 1:
            s_fix += O//8

        # 5. Send fixed signature
        S.sendline(', '.join([str(r), str(s_fix)]).encode())

    # 6. Filter for the flag
    result = S.recv()
    print(result)
    
    if b'idek' in result:
        break