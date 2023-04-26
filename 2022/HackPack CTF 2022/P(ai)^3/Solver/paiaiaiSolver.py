#!/usr/bin/env python3
#
# Polymero
#

# Imports
from pwn import *
import random
from Crypto.Util.number import GCD, isPrime
from sympy.ntheory.modular import crt

ALP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_ '

# Connection
host = "0.0.0.0"
port = 00000
s = remote(host, port)


def get_flag() -> int:

	s.recv()
	s.sendline(b"e")
	s.recv()
	s.sendline(b"f")
	s.recvuntil(b"FLAG: ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def get_encrypt(x: bytes) -> int:

	s.recv()
	s.sendline(b"e")
	s.recv()
	s.sendline(b"m")
	s.recv()
	s.sendline(x.encode())
	s.recvuntil(b"CIP: ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def get_decrypt(x: int) -> int:

	s.recv()
	s.sendline(b"d")
	s.recv()
	s.sendline(str(x).encode())
	s.recvuntil(b"MSG: ")

	return int(s.recvuntil(b"\n", drop=True).decode())


# Get both possible erroneously decrypted flag values
flag_r = []
while len(flag_r) != 2:

	k = get_decrypt(get_flag())

	if k not in flag_r:
		flag_r += [k]

flag_p, flag_q = flag_r


# Try to recover prime factorisation of unknown public modulus using random erroneous decryptions
while True:

	rstr = [''.join(random.sample(ALP, 9)) for _ in range(8)]
	rdec = [get_decrypt(get_encrypt(i)) for i in rstr]

	p = max([GCD(flag_p, i) for i in rdec])
	q = max([GCD(flag_q, i) for i in rdec])

	for k in range(2, 1_000_000):
		while not p % k:
			p //= k
		while not q % k:
			q //= k

	if isPrime(p) and isPrime(q):
		break


# Recover flag
n = p * q
flag_modp = flag_q % flag_p
flag_modq = flag_p % flag_q

flag, pub = crt([p, q], [flag_modp, flag_modq])

FLAG = int(flag).to_bytes(128,'big').lstrip(b"\x00")
print(FLAG)

s.close()
