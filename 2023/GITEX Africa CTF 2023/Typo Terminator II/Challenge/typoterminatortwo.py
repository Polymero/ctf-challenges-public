#!/usr/local/bin python
#
# Polymero
#
# GITEX Africa CTF 2023
#

# Native imports
import os, base64
from secrets import randbelow

# Local imports
FLAG = os.environ.get('FLAG', 'flag{th1s_1s_just_s0m3_d3bug_fl4g}')
if type(FLAG) == str:
    FLAG = FLAG.encode()


# Functions
def ReduceBase58(x: bytes):
    b64 = base64.b64encode(x).decode()
    b64 = b64.replace('0', 'o').replace('O', 'o').replace('I', 'i')
    b64 = b64.replace('l', 'i').replace('/', 'i').replace('+', 'x')
    return b64

def GetOTPKey(keyLength: int) -> str:
    return ReduceBase58(os.urandom(keyLength))

def GetOTPEncrypt(data: bytes) -> (str, str):
    key = GetOTPKey(len(data))
    return key, bytes([x ^ y for x,y in zip(base64.b64decode(key), data)]).hex()


# Server loop
print('|\n|  ~ Feel free to test out our (second try at an) encryption service ::')
while True:
    try:
        
        requests = int(input('|  (int <= 32) '))
        assert 0 <= requests <= 32
        
        for _ in range(requests):
            print('|  ' + GetOTPEncrypt(FLAG)[1])
        
    except KeyboardInterrupt:
        break
        
    except:
        continue