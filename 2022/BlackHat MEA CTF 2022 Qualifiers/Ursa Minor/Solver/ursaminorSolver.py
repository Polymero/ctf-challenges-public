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
from math import log

# Connection
host = '0.0.0.0'
port = '5000'
s = connect(host, port)

# context.log_level = 'debug'

# Pass an enter
print('|\n|  ~ Waiting for prime generation...')
s.recv()
s.sendline(b"")

# Get public modulus (id)
s.recvuntil(b"id = ")
Nid = s.recvuntil(b"\n", drop=True).decode()
print('|\n|  ~ Collecting challenge parameters ::')
print(f"|    id = {Nid}")

# Get encrypted flag
s.recvuntil(b"e  =")
s.recvuntil(b"|    ")
encflag = int(s.recvuntil(b"\n", drop=True).decode())
print(f"|    f  = {encflag}")
s.recv()

print('|    Connection succesfully established ~ !')

# Generate set of all 12-bit primes
print('|\n|  ~ Finding all 12-bit primes...')
primeset = set()
for _ in range(5_000):
	primeset.add(getPrime(12))
print('|    Found {}'.format(len(primeset)))

# Loop to recover public modulus bits
print('|\n|  ~ Starting loop ::')
N = 0
for k in range(512):

	pt = N ^ 2**(512 - k - 1)

	s.sendline(b"e")
	s.recv()

	s.sendline(str(pt).encode())
	s.recvuntil(b"::\n")

	resp = s.recvuntil(b"~ ")
	s.recv()

	if sum([1 for i in resp if i == ord('\n')]) <= 2:

		N = pt

	print('|    N = {:0512b}'.format(N), end='\r', flush=True)

N ^= 1
print('|\n|  ~ Recovered the public modulus ::')
print('|    {}'.format(N))

print('|\n|  ~ Running p-1 factorisation...')

gcdlst = set()
for k in range(2, 200):
    w = k
    for i in primeset:
        w = pow(w, i**int(log(2**12)/log(i) + 10), N)

    gcd = GCD(w-1,N)
    if gcd not in [1, N]:
        gcdlst.add(gcd)

print('|\n|  ~ Found the following primes ::')
for i in gcdlst:
	print('|    {}'.format(i))

if len(gcdlst) == 1:
	gcdlst.add(N // list(gcdlst)[0])

F = 1
for i in list(gcdlst):
	F *= i - 1

d = inverse(0x10001, F)

flag = pow(encflag, d, N).to_bytes(128, 'big').lstrip(b"\x00")
print('|\n|  ~ Recovered the flag ::')
print('|    {}'.format(flag.decode()))

print('|\n|')