#!/usr/local/bin python
#
# Polymero
#
# GITEX Africa CTF 2023
#

# Native imports
import os
from secrets import randbelow

# Local imports
FLAG = os.environ.get('FLAG', 'flag{th1s_1s_just_s0m3_d3bug_fl4g}')
if type(FLAG) == str:
    FLAG = FLAG.encode()

# Globals
B58ALP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# Functions
def GetOTPKey(keyLength: int) -> str:
    return ''.join(B58ALP[randbelow(len(B58ALP))] for _ in range(keyLength))

def GetOTPEncrypt(data: bytes) -> (str, str):
    key = GetOTPKey(len(data))
    return key, bytes([x ^ y for x,y in zip(key.encode(), data)]).hex()


# Server loop
print('|\n|  ~ Feel free to test out our encryption service ::')
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
