#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import hashlib

ADMIN_USR = hashlib.sha256(b'th1s_1s_my_4dm1n_us3rn4m3').digest()[:6]
ADMIN_PWD = hashlib.sha256(b'TH1S_1S_MY_4DM1N_P4SSW0RD').digest()[:9]
