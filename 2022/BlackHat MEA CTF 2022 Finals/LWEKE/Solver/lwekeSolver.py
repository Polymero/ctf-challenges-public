#!/usr/bin/env python3
#
# Polymero
#

# imports
from pwn import *
from Crypto.Cipher import AES
from sympy import prevprime
import os, base64, hashlib
import time, traceback


# Encoding functions
def enc_mat(A):
    byt = b"".join(bytes.fromhex(''.join('{:07x}'.format(j) for j in i)) for i in A)
    return base64.urlsafe_b64encode(byt).decode()

def dec_mat(A):
    hx = base64.urlsafe_b64decode(A).hex()
    rs = [hx[i:i + 7*N] for i in range(0, len(hx), 7*N)]
    return [[int(i[j:j + 7], 16) for j in range(0, len(i), 7)] for i in rs]

def enc_sig(s):
    return int(''.join(str(i) for i in s),2).to_bytes(N//8, 'big').hex()

def dec_sig(s):
	return [int(i) for i in '{:0{n}b}'.format(s, n=N)]


# Global parameters
N = 64
Q = prevprime(N**4)
step = Q // N // 2

# Connection
host = '0.0.0.0'
port = 5000

# Challenge debug
DEBUG = False


print('|\n|  ~ LWEKE Challenge Solve Script by Polymero')


print('|\n|  ~ Connecting to {}:{} (change in py code if necessary) ::'.format(host, port))
try:

	s = connect(host, port)
	print('|    Connection established!')

except:
	print('|    ERROR -- Connection could not be established ::\n|')
	traceback.print_exc()
	exit()


print('|\n|  ~ Receiving challenge parameters ::')
try:

	s.recvuntil(b'M = ')
	M = dec_mat(s.recvuntil(b'\n', drop=True).decode())

	assert len(M) == N and len(M[0]) == N
	print('|    Parsed valid M')

	s.recvuntil(b'F = ')
	F = bytes.fromhex(s.recvuntil(b'\n', drop=True).decode())
	print('|    Parsed valid encrypted flag')

	s.recv()

except:
	print('|    ERROR -- Could not parse challenge parameters ::\n|')
	traceback.print_exc()
	exit()


print('|\n|  ~ Collecting handshakes ::')
try:

	s_rec = []
	t0 = time.time()
	for ji in range(N):

		full_sig = []
		for i in range(2):

			pA = list(zip(*[[0]*ji + [k*step + i*N*step] + (N - 1 - ji)*[0] for k in range(N)]))

			s.sendline(enc_mat(pA).encode())

			s.recvuntil(b'pB = ')
			pB = dec_mat(s.recvuntil(b'\n', drop=True).decode())

			assert len(pB) == N and len(pB[0]) == N

			s.recvuntil(b'sig = ')
			sig = dec_sig(int(s.recvuntil(b'\n', drop=True).decode(), 16))

			full_sig += sig

			s.recv()

		assert len(full_sig) == 2*N

		scnt, swap = 0, 0
		for i in full_sig:
			if i != swap:
				if i:
					scnt += 1
				swap = i

		s_rec += [scnt]

		if DEBUG:
			print(s_rec)

		t1 		= time.time()
		del_t   = t1 - t0
		del_ke  = del_t / (ji + 1)
		del_eta = (2*(N-1) - ji) * del_ke
		print('|    {}/{n} ({:.0f}m {:.0f}s, {:.1f} s/ke) ETA: {:.0f}m {:.0f}s   '.format(ji+1, del_t//60, del_t%60, del_ke, del_eta//60, del_eta%60, n=N-1), end='\r', flush=True)

	print('|    {}/{n} ({:.0f}m {:.0f}s, {:.1f} s/ke) ETA: {:.0f}m {:.0f}s   '.format(ji+1, del_t//60, del_t%60, del_ke, del_eta//60, del_eta%60, n=N-1))

except:
	print('|    ERROR -- Something went wrong ::\n|')
	traceback.print_exc()
	exit()


print('|\n|  ~ Absolute-valued key recovered ::')
print('|    {}'.format(s_rec))


print('|\n|  ~ Collecting handshakes ::')
try:

	for jj in range(1, N):

		full_sig = []
		for i in range(2):

			pA = list(zip(*[[k*step + i*N*step] + [0]*(jj - 1) + [k*step + i*N*step] + (N - 1 - jj)*[0] for k in range(N)]))

			s.sendline(enc_mat(pA).encode())

			s.recvuntil(b'pB = ')
			pB = dec_mat(s.recvuntil(b'\n', drop=True).decode())

			s.recvuntil(b'sig = ')
			sig = dec_sig(int(s.recvuntil(b'\n', drop=True).decode(), 16))

			s.recv()

			full_sig += sig

		scnt, swap = 0, 0
		for i in full_sig:
			if i != swap:
				if i:
					scnt += 1
				swap = i

		if s_rec[0] + s_rec[jj] != scnt:
			s_rec[jj] *= -1

		if DEBUG:
			print(s_rec)

		t2      = time.time()
		del_t   = t2 - t1
		del_ke  = del_t / jj
		del_eta = (2*(N-1) - ji - jj) * del_ke
		print('{}/{n} ({:.0f}m {:.0f}s, {:.1f} s/ke) ETA: {:.0f}m {:.0f}s   '.format(ji+jj+1, del_t//60, del_t%60, del_ke, del_eta//60, del_eta%60, n=2*N-1), end='\r', flush=True)

	print('{}/{n} ({:.0f}m {:.0f}s, {:.1f} s/ke) ETA: {:.0f}m {:.0f}s   '.format(ji+jj+1, del_t//60, del_t%60, del_ke, del_eta//60, del_eta%60, n=2*N-1))

except:
	print('|   ERROR -- Something went wrong ::\n|')
	traceback.print_exc()
	exit()


print('|\n|  ~ Possible keys recovered ::')
try:

	rec_keys = [s_rec, [-1*i for i in s_rec]]
	print('|    k1 = {}'.format(rec_keys[0]))
	print('|    k2 = {}'.format(rec_keys[1]))

except:
	print('|    ERROR -- Keys could not be recovered ::\n|')
	traceback.print_exc()
	exit()


print('|\n|  ~ Possible flags ::')
try:

	for key in rec_keys:
		riv, cip = F[:16], F[16:]
		ekey = [[i] * N for i in key]
		flag = AES.new(hashlib.sha256(str(ekey).encode()).digest(), AES.MODE_CBC, riv).decrypt(cip)
		print('|    {}'.format(flag))

except:
	print('|    ERROR -- Flags could not be recovered ::\n|')
	traceback.print_exc()
	exit()


print('|\n|  ~ Some statistics ::')
t3 = time.time()
print('|    Total time cost: {:.0f}m {:.0f}s'.format((t3-t0)//60, (t3-t0)%60))
print('|    Average cost KE: {:.0f}ms/ke'.format((t3-t0)/(2*N-1)*1000))

print('|\n|')