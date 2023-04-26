#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import hashlib

SECRET_KEY = bytes.fromhex('9c642885ce5507b20de6ed04131819268118ba0b5654253b71ce23372debbb518f43be47c90d77c0da9d6e38c5a526347c6fb4b9489d5c6fe992c12e6078f4643796f5a43d660a2d574094febebf79862dcdd90e93cfdac809205ced7da16408b0177137e07cdca07f332b22e66d4df66f841f99bddedcdac789b2a824af95be')

ADMIN_PWD = hashlib.sha256(b'just_1m4g1n3_th1s_t0_b3_4_g00d_p4ssw0rd').digest()[:24]