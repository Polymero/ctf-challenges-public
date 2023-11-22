#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Easy] Crypto - Cicero
#


# Native imports
import os

# Local imports
from cicero import *

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'FLAG{TH1S_1S_JUST_S0M3_D3BUG_FL4G}')


# Challenge set-up
cicero = Cicero(FILEPATH, DISTPARS)
keyPhrase = cicero.randomParagraph()


# Header
HDR = r"""|
|
|        _______________________________________________________
|       /\                                                      \
|   (O)===)><><><><><><><><><><><><><><><><><><><><><><><><><><><)==(O)
|       \/''''''''''''''''''''''''''''''''''''''''''''''''''''''/
|       (                                                      (
|        )              )   ___                                 )
|       (              (__/_____) ,                            (
|                        /          _   _  __  ___
|        )              /       _(_(___(/_/ (_(_)               )
|       (              (______)                                (
|        )                                                      )
|       /\''''''''''''''''''''''''''''''''''''''''''''''''''''''\    
|   (O)===)><><><><><><><><><><><><><><><><><><><><><><><><><><><)==(O)
|       \/______________________________________________________/
|
|"""

print(HDR)


# Server loop
while True:
    try:

        plainText = cicero.randomParagraph()
        print('|\n|  ~ Here is a ciphertext ::\n|    {}'.format(cicero.encrypt(keyPhrase, plainText)))

        guess = input('|\n|  ~ Guess the plaintext ::\n|  > (str) ')

        if guess == plainText:
            print('|\n|  ~ Here is your reward ::\n|    {}'.format(FLAG))

        else:
            print('|\n|  ~ Not quite.')

    except KeyboardInterrupt:
        print('\n|\n|  ~ Ci(cero) you later ~\n|')
        break

    except:
        print('|\n|  ~ Something went wrong ~ !')