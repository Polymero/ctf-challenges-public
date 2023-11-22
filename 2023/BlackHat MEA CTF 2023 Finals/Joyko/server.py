#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Elite] Crypto - Joyko
#

# Native imports
from secrets import randbelow
import os

# Local imports
from joyko import *

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{{{}}}'.format(os.urandom(16).hex()))
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Challenge set-up
tokenLength = N.bit_length() // 8


# Header
HDR = """|
|    _______ _______ ___ ___ __          
|   |   _   |   _   |   Y   |  |--.-----.
|   |___|   |.  |   |   |   |    <|  _  |
|   |.  |   |.  |   |\_   _/|__|__|_____|
|   |:  |   |:  |   | |:  |              
|   |::.. . |::.. . | |::.|              
|   `-------`-------' `---'              
|"""
print(HDR)


# Server loop
print('|\n|  ~ Welcome to Joyko ~ !\n|    {:0512x}'.format(N))

while True:
    try:

        choice = input('|\n|  ~ Options:\n|    [R]equest\n|    [D]ecrypt\n|\n|  > ').lower()

        if choice == 'r':

            token  = os.urandom(randbelow(tokenLength - len(FLAG)))
            token += FLAG
            token += os.urandom(tokenLength - len(token))
            token  = Joy(int.from_bytes(token, 'big'), E).to_bytes(256, 'big').hex()

            print('|\n|  ~ Here you go, please handle it with care ~ !\n|    {}'.format(token))

        elif choice == 'd':

            token = int(input('|\n|  ~ Ah, please allow me ~ !\n|  > (hex) ').lower(), 16)
            token = Ko(token).to_bytes(256, 'big')

            if FLAG in token:
                print('|\n|  ~ Most wonderful, thank you kindly ~ !')

            else:
                print('|\n|  ~ What have you done ~ ?\n|    You ruined it, look ~ !\n|    {}'.format(token.hex()))

        else:
            raise ValueError()


    except KeyboardInterrupt:
        print('\n|\n|  ~ Thank you ~ !\n|')
        break

    except Exception as e:
        print('|\n|  ~ Our apologies, but we seem unable to assist you ~ !')
        print(e)