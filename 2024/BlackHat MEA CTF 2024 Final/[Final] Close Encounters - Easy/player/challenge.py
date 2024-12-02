#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Easy] Crypto - Close Encounters of the Gorgon Kind
#
# by Polymero
#

# Native imports
import os, hashlib
from secrets import randbelow
from typing import List

# Non-native imports
from Crypto.Util.number import getPrime, GCD     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Global parameters
HASH = hashlib.sha256
SNAKE_NUM = 8
SNAKE_LEN = 32
ROUND_NUM = 8


# Helper functions
def Pungi(num: int, bit: int) -> int:
    while True:
        snakes = []
        while len(snakes) < num // 2:
            snake = getPrime(bit)
            if GCD(snake - 1, 3) != 1:
                snakes += [snake]
        while len(snakes) < num:
            snake = getPrime(bit + 1)
            if GCD(snake - 1, 3) != 1:
                snakes += [snake]
        basket = 1
        for snake in snakes:
            basket *= snake
        if basket.bit_length() == num * bit:
            return basket

def Birth(x: int) -> int:
    y = randbelow(x)
    while not y:
        y = randbelow(x)
    return y


# Challenge parameters
BASKET = Pungi(SNAKE_NUM, SNAKE_LEN)
SNAKES = [Birth(BASKET) for _ in range(ROUND_NUM)]
MEDUSA = Birth(BASKET)


# Challenge function
def Gaze(x: int, k: int, n: int, r: int, rc: List[int]) -> int:
    x += k
    x  = pow(x, 3, n)
    for i in range(r - 1):
        x += k
        x += rc[i]
        x  = pow(x, 3, n)
    x += k
    return x % n


# Challenge setup
HDR = r"""|
|
|     ⢠⣀        ⣤⡀      ⣠⠤⣄⡀
|     ⠈⢻⣿⡄      ⠹⣿⡆ ⢀⣠⡴⠞⠛⠷⠄ ⢀⣤⣾⡗   
|       ⠹⣧⡀⣰⡞⠛⠳⣦⣀⣸⠇ ⢾⡇    ⢀⣴⠟⠛⠉⣀⡀  
|       ⣠⣬⡛⢻⡷⠶⠾⢻⡏⠁  ⠈⠛⢷⣤⡀⢰⡿⢁⣴⣻⠿⠋⣿⠄ 
|     ⢀⣼⡇⠘⣷⠈⢿⣦⡀ ⠻⢷⣶⣤⡄ ⣠⣿⡷⠘⣿⠛⢉⣥⣤⡶⠟  
|     ⢾⡟⠁ ⢻⡄ ⠻⣿⣿⠶⠆ ⢀⣴⠾⠛⠋⣠⣴⠟ ⢸⡇  ⡀  
|     ⠈⣠⣄⡀⠘⢷⣤⣤⣤⣤⡶⠞⠂⣀⡀⠐⠦⢤⣤⣤⣤⣤⡾⠃ ⢸⣷⠂ 
|     ⢸⡏⠙⢿⣵⡄⠉⠉⢉⣀ ⠺⢿⣿⣿⡷⠖⡄ ⢠⡶⢦⡀  ⣼⠃  
|     ⠈⢿⣄ ⠙⠛⢀⣴⣿⣿ ⣿⣿⣟⣻⣿⣿⠃⢿⣦⡀ ⠻⣦⣴⠏   
|     ⢀⣀⡉⠙⠛⠛⠋⠉⣠⡿⢠⣟⢻⠿⠿⡟⣻⣧ ⣽⠟⢿⡟⠻⣿⡄   
|     ⢸⣏⠛⠷⣤⣤⣤⡾⠟⠁⠘⢿⣦⣠⣄⣴⠿⠃⣠⡉⠛⠛⠁ ⠈⢿⡀  
|      ⢻⣦⣀ ⠉⠁⣀⣀⣰⠇ ⠈⠉⠉⠁⢀⣠⠾⠃⢀⣀⡀  ⢸⣷     
|      ⠈⠻⠷⠁⢰⡟⠋⠉⠁  ⢀⣀ ⠐⢿⣤⡶⠟⠛⠉⣿⠄ ⢸⡯
|          ⠈⠳⠶⠶⠶⠾⠿⠟⠋      ⠔⡾⡿      
|                         ⠛⠉       
|              LVL: {}
|
|         Once your Eyes meet hers...
|   even your Thoughts will harden to Stone 
|
|  [~] As a SNAKE CHARMER, SHE might not be the most unfortunate encounter the DM could have given you...
|    INVENTORY = {{
|      BASKET = {},
|      SNAKES = {}
|    }}
|
|  [~] Oh and some quick ADVICE, never put all your SNAKES in a single BASKET...
|""".format(int(HASH(str(MEDUSA).encode()).hexdigest(), 16) % 2**32, BASKET, SNAKES)
print(HDR)


# Server loop
TUI = "|\n|  Menu:\n|    [L]ook...\n|    [L]eave"

while True:
    try:

        print(TUI)
        choice = input('|\n|  > ').lower()


        # [L]ook...
        if choice == 'l':

            look = int(input('|\n|  > (int) '))
            gaze = Gaze(look, MEDUSA, BASKET, ROUND_NUM, SNAKES)

            print('|\n|  [~] And so your fate was set in stone...\n|    GAZE = {}'.format(gaze))

            print('|\n|  [!] As you feel your body stiffen, your only salvation is to play your Pungi, note by note...\n|\n|    ...carefully, as a SINGLE false note will be your DOOM ~ !\n|')

            TUNE = list(MEDUSA.to_bytes(SNAKE_LEN*SNAKE_NUM//8, 'big'))

            while TUNE:

                note = int(input('|  > (int) '))

                if note != TUNE.pop(0):
                    raise ValueError('oop-')
                
            print('|\n|  [~] While you catch your breath, her snakes, now charmed, respond in harmonious unity:\n|    FLAG = {}\n|\n|'.format(FLAG.decode()))
            break
        

        # [L]eave 
        elif choice == 'l':
            print('|\n|  [~] You managed to flee with all your limbs still flexible... for now.\n|')
            break


        else:
            print('|\n|\n|\n|\n|  You are NOTHING but a PEBBLE to her now...\n|\n|')

    except KeyboardInterrupt:
        print('\n|\n|\n|\n|  You are NOTHING but a PEBBLE to her now...\n|\n|')
        break

    except Exception as e:
        print('|\n|\n|\n|\n|  You are NOTHING but a PEBBLE to her now...\n|\n|')
        break
