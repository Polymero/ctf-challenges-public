#!/usr/bin/env python3
#
# Polymero
#

# Imports
from pwn import *
from Crypto.Util.number import inverse

# Connection
host = "cha.hackpack.club"
port = 10996
s = remote(host, port)

context.log_level = 'debug'


def s_encrypt(x: int) -> int:

	s.recv()
	s.sendline(b"e")
	s.recv()
	s.sendline(str(x).encode())
	s.recvuntil(b"CIP -> ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def s_decrypt(x: int) -> int:

	s.recv()
	s.sendline(b"d")
	s.recv()
	s.sendline(str(x).encode())
	s.recvuntil(b"MSG -> ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def s_submit(x: int) -> int:

	s.recv()
	s.sendline(b"s")
	s.recv()
	s.sendline(str(x).encode())


def s_params() -> tuple:

	s.recvuntil(b"N: ")
	N = int(s.recvuntil(b"\n", drop=True).decode())
	s.recvuntil(b"G: ")
	G = int(s.recvuntil(b"\n", drop=True).decode())
	s.recvuntil(b"(Password): ")
	P = int(s.recvuntil(b"\n", drop=True).decode())

	return (N, G, P)


# Stage 1
N1, G1, P1 = s_params()
s_submit( (s_decrypt( pow(P1, pow(2, 0x10001, N1), N1*N1) ) * inverse(2, N1)) % N1 )

# Stage 2
N2, G2, P2 = s_params()
s_submit( (s_decrypt( (P2 * pow(pow(G2, 2, N2*N2), 0x10001, N2*N2)) % (N2*N2) ) - 2) % N2 )


# Get flag
s.recvuntil(b"flag: ")
FLAG = s.recvuntil(b"\n", drop=True)
print(FLAG)