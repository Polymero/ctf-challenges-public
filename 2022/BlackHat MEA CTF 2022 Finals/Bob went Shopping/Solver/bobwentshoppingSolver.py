#!/usr/bin/env python3
#
# Polymero
#

# Imports
from pwn import *
from hashlib import sha256
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
from Crypto.Cipher import AES
from time import time
import os


host = '0.0.0.0'
port = 5000

s = connect(host, port)

s.recvuntil(b"p = ")
p = int(s.recvuntil(b"\n", drop=True).decode())

s.recv()
s.sendline(b"2")

s.recvuntil(b"Party People")
s.recvuntil(b"key_id = ")
group_id = s.recvuntil(b"\n", drop=True).decode()
s.recvuntil(b"key_pk = ")
group_pk = int(s.recvuntil(b"\n", drop=True).decode())
group_sk = pow(2, group_pk, p)

s.recvuntil(b"Bob")
s.recvuntil(b"key_id = ")
bob_id = s.recvuntil(b"\n", drop=True).decode()

msg = "sure".encode()
while len(msg) % 16 != 0:
	msg += b" "

salt  = os.urandom(8)
Ke    = sha256('{:02x}:{}:{}'.format(group_sk, salt.hex(), 'Key').encode()).digest()
IVpre = sha256('{:02x}:{}:{}'.format(group_sk, salt.hex(), 'IV').encode()).digest()
IVe   = long_to_bytes(bytes_to_long(IVpre[:16]) ^ bytes_to_long(IVpre[16:]))

C = AES.new(Ke, AES.MODE_CBC, IVe).encrypt(msg)

V    = sha256(C).digest()
Tpre = long_to_bytes(bytes_to_long(V[:16]) ^ bytes_to_long(V[16:]))
T    = AES.new(Ke, AES.MODE_ECB).encrypt(Tpre)

packet = '{}:{}:{}:{}:{}:{}:{}'.format('DiffieChat Ver 3.14', int(time()), salt.hex(), C.hex(), T.hex(), bob_id, group_id)

s.recv()
s.sendline(b"4")

s.recv()
s.sendline(packet.encode())

s.recv()
s.sendline(b"3")
s.recv()
s.sendline(b"1")

print(s.recv().decode())

