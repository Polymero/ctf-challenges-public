#!/usr/bin/env python3
#
# Polymero
#

# Imports
#from sage.all import *
import requests, time, json
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

ti = time.time()



#------------------------------------------------------------------------------------------------
# 0. SERVER CLASS
#------------------------------------------------------------------------------------------------
class Server:
	def __init__(self, addr):
		self.addr = addr

	def register(self, username):
		ret = requests.get(self.addr + '/register/' + username + '/', allow_redirects=False)
		acto = bytes.fromhex(ret.cookies['access_token'])
		return acto

	def gcm_encrypt(self, nonce, msg, token=None):
		jobj = json.dumps({"nonce":nonce.hex(),"msg":msg.hex()})
		addr = self.addr + '/dev/test/gcm_encrypt/' + jobj + '/'
		ret = requests.get(addr, cookies={'access_token':token}, allow_redirects=False)
		return ret

	def access_vault(self, token=None):
		ret = requests.get(self.addr, cookies={'access_token':token})
		return ret

# Create communication class
S = Server("https://blackhat4-d7e408570235e0e165761d68b2da44e4-0.chals.bh.ctf.sa/")



#------------------------------------------------------------------------------------------------
# 1. FORGE DEVELOPER TOKEN FOR GCM ORACLE ACCESS
#------------------------------------------------------------------------------------------------
print("1   - Forging Developer Token")

def forge_dev_token():

	tstr = str(int(time.time()))[-4:]
	acto = S.register("123456")

	raw_b1 = b'{"user": "123456'
	raw_b3 = (tstr + ', "priv": []').encode()
	target = b"priv:gcm_encrypt"
	enc_iv = acto[:16]
	enc_b2 = acto[32:48]

	forged_block = bytes([raw_b3[i] ^ enc_b2[i] ^ target[i] for i in range(16)])
	forged_token = bytes([raw_b1[i] ^ enc_iv[i] for i in range(16)])

	forged_token += acto[16:32] + forged_block + acto[48:]

	return forged_token


while True:

	dev_acto = forge_dev_token().hex()

	ret = S.gcm_encrypt(b'\x00', b'\x00', token=dev_acto)

	if "ERROR" not in ret.text:
		break

DEV_ACTO = dev_acto
print(DEV_ACTO, ret.text)



#------------------------------------------------------------------------------------------------
# 2. RECOVER GCM AUTHENTICATION KEY TO TURN GCM ORACLE INTO ECB ORACLE
#------------------------------------------------------------------------------------------------
print("2.1 - Recovering GCM Authentication Key")

G2 = GF(2)['x']
x = G2.gen()
G = GF(2**128, 'x', modulus = x**128 + x**7 + x**2 + x + 1)

def int_to_galois(x):
    return G([int(i) for i in list('{:0128b}'.format(x))])

def galois_to_int(g):
    return int('{:0128b}'.format(g.integer_representation())[::-1],2)

def btg(x):
    return int_to_galois(bytes_to_long(x))

def gtb(x):
    return long_to_bytes(galois_to_int(x))

retdic1 = json.loads(S.gcm_encrypt(nonce=b'\x00'*12, msg=b'', token=DEV_ACTO).text)

for k in range(256):
	
	retdic2 = json.loads(S.gcm_encrypt(nonce=b'\x00'*12, msg=bytes([k]), token=DEV_ACTO).text)

	if retdic2['cip'] == '00':

		break

AUTH_KEY = (btg(bytes.fromhex(retdic1['tag'])) + btg(bytes.fromhex(retdic2['tag']))) / int_to_galois(8)
AUTH_KEY_INV = AUTH_KEY**(-1)

print("2.2 - Setting up ECB Oracle")

def ecb_oracle(msg):

	assert len(msg) == 16

	payload_nonce = gtb(btg(msg) * AUTH_KEY_INV**2 + int_to_galois(128) * AUTH_KEY_INV)

	retdic = json.loads(S.gcm_encrypt(nonce=payload_nonce, msg=b'', token=DEV_ACTO).text)

	return bytes.fromhex(retdic['tag'])



#------------------------------------------------------------------------------------------------
# 3. USE ECB ORACLE TO COMMENCE BEAST ATTACK TO RECOVER VAULT ACCESS CODE FROM TOKENS
#------------------------------------------------------------------------------------------------
print("3.1 - Farming Access Tokens with Varying Username Lengths")

k = 1
base_len = len(S.register(k * 'A'))

while True:

	k += 1
	if len(S.register(k * 'A')) != base_len:
		break

k += 3

FARMED_TOKENS = []
for i in range(16):
	FARMED_TOKENS += [S.register((k + i) * 'A')] # [:base_len + 16]

print("3.2 - Commencing BEAST Attack (if it hangs, try again)")

RECOVERED_CODE = b'"}'

indx = None
while True:

	if indx == (len(RECOVERED_CODE) - 2) % 16:
		FARMED_TOKENS = [i[:-16] for i in FARMED_TOKENS]

	code = RECOVERED_CODE[:15]
	indx = (len(RECOVERED_CODE) - 2) % 16

	for k in range(256):

		try_code = bytes([k]) + code

		if len(try_code) < 16:
			try_code = pad(try_code, 16)

		prev_block = FARMED_TOKENS[indx][-32:-16]
		xor_code = bytes([try_code[i] ^ prev_block[i] for i in range(16)])

		enc_code = ecb_oracle(xor_code)

		if enc_code == FARMED_TOKENS[indx][-16:]:

			RECOVERED_CODE = bytes([k]) + RECOVERED_CODE
			break

	print(len(RECOVERED_CODE), RECOVERED_CODE, end='\r', flush=True)

	if RECOVERED_CODE[0] == ord(':'):
		break

ACCESS_CODE = (RECOVERED_CODE[3:-2]).decode()

print(">---- ACCESS CODE:", ACCESS_CODE)



#------------------------------------------------------------------------------------------------
# 4. FORGE ADMIN TOKEN
#------------------------------------------------------------------------------------------------
print("4   - Forging Admin Token")

admin_token = pad(json.dumps({
		"user" : "admin",
		"iat"  : 0,
		"priv" : ["REMOTE__Vault.access"],
		"code" : ACCESS_CODE
	}).encode(), 16)

blocks = [admin_token[i:i+16] for i in range(0,len(admin_token),16)]

ADMIN_ACTO = b'\x00'*16

for block in blocks:

	xor_block = bytes([block[i] ^ ADMIN_ACTO[-16:][i] for i in range(16)])

	ADMIN_ACTO += ecb_oracle(xor_block)



#------------------------------------------------------------------------------------------------
# 5. ACCESS VAULT
#------------------------------------------------------------------------------------------------
print("5   - Accessing Vault")

ret = S.access_vault(token=ADMIN_ACTO.hex())

print(ret.text)

tf = time.time()
print("And it only took me: {:.2f} s".format(tf-ti))