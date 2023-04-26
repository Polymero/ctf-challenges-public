#!/usr/bin/env python3
#
# Polymero
#

#-------------------------------------------------------------
# SOLVE SCRIPT FOR "URSA MINOR"
#-------------------------------------------------------------

# Imports
from pwn import *
from Crypto.Util.number import isPrime, inverse, getPrime, GCD
from sympy import nextprime

# Connection
HOST = '0.0.0.0'
PORT = '5000'

context.log_level = "debug"


def new_connect(host, port):
    s = connect(host, port)
    s.recv()
    s.sendline(b"")
    s.recvuntil(b"id = ")
    Nid = s.recvuntil(b"\n", drop=True).decode()
    s.recvuntil(b"e  =")
    s.recvuntil(b"|    ")
    encflag = int(s.recvuntil(b"\n", drop=True).decode())
    s.recvuntil(b"e  = ")
    exp = int(s.recvuntil(b"\n", drop=True).decode())
    return s, Nid, encflag, exp

def encrypt_decrypt(s, m):
    s.recv()
    s.sendline(b"e")
    s.recv()
    s.sendline(b"2")
    s.recvuntil(b"::")
    s.recvuntil(b"|    ")
    enc = int(s.recvuntil(b"\n", drop=True).decode())
    s.recv()
    s.sendline(b"d")
    s.recv()
    s.sendline(str(enc).encode())
    s.recvuntil(b"::")
    s.recvuntil(b"|    ")
    dec = int(s.recvuntil(b"\n", drop=True).decode())
    s.recvuntil(b"e  = ")
    exp = int(s.recvuntil(b"\n", drop=True).decode())
    return dec, exp


pbit = 256
lbit = 12

PSET = set()
k = 3
while k < 2**lbit:
    PSET.add(k)
    k = nextprime(k)


FOCUS = [p for p in PSET if p > (512 + 4) and p < (512 + 32)]
print(FOCUS)

calls = 0
total_calls = 0
connects = 0
max_calls = 500

while True:
    total_calls += calls
    calls = 0
    focus = FOCUS.copy()
    connects += 1

    s, Nid, encflag, e = new_connect(HOST, PORT)
    print(connects, total_calls, Nid, e)

    while focus and calls < max_calls:
        calls += 1

        hit = [i for i in focus if not e % i]
        if hit:
            m = 2
            c, e = encrypt_decrypt(s, m)
            if '1' in bin(c)[3:]:
                break
            else:
                focus.remove(hit[0])

        else:
            s.recv()
            s.sendline(b"u")
            s.recvuntil(b"e  = ")
            e = int(s.recvuntil(b"\n", drop=True).decode())

    if focus and calls < max_calls:

        rem = (2**hit[0] - c)

        for i in range(2, 2**16):
            while not rem % i:
                rem //= i

        print(hashlib.sha256(str(rem).encode()).hexdigest())
        if hashlib.sha256(str(rem).encode()).hexdigest() == Nid:
            break

    s.close()

print()
print(connects, total_calls, calls, hit, FOCUS)
print(rem)

N = rem


k = 2
while True:

    w = k

    for i in PSET:
        w = pow(w, i**2, N)

    p = GCD(w - 1,N)

    if p not in [1, N]:
        q = N // p
        break

    k += 1

print('|\n|  ~ Found the following primes ::')
for i in [p, q]:
    print('|    {}'.format(i))

F = (p - 1) * (q - 1)
d = inverse(0x10001, F)

flag = pow(encflag, d, N).to_bytes(128, 'big').lstrip(b"\x00")
print('|\n|  ~ Recovered the flag ::')
print('|    {}'.format(flag.decode()))