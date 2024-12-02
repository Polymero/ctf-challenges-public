#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Hard] Crypto - Distant Avoidances of the Impetus Cruel
#
# by Polymero
#

# Native imports
import os, hashlib
from secrets import randbelow
from typing import List

# Non-native imports
from Crypto.Util.number import getPrime, GCD, inverse     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Global parameters
HASH = hashlib.sha256
SNAKE_NUM = 8  - 4 # RIP snek
SNAKE_LEN = 32 - 1 # wallah...
ROUND_NUM = 8  - 2 # how sweet of me


# Helper functions
def Pungi(num: int, bit: int) -> int:
    snakes = []
    while len(snakes) < num:
        snake = getPrime(bit)
        if GCD(snake - 1, 3) != 1:
            snakes += [snake]
    basket = 1
    for snake in snakes:
        basket *= snake
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
    x  = inverse(pow(x, 3, n), n)
    for i in range(r - 1):
        x += k
        x += rc[i]
        x  = inverse(pow(x, 3, n), n)
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
|  Did you really think it was going to be that easy ~ ? 
|
|  [~] You are still equipped with your TRUSTY basket of snakes and NOTHING more...
|    INVENTORY = {{
|      BASKET = {},
|      SNAKES = {}
|    }}
|
|""".format(int(HASH(str(MEDUSA).encode()).hexdigest(), 16) % 2**32, BASKET, SNAKES)
print(HDR)


# Server loop
TUI = "|\n|  Menu:\n|    [L]ook... again...\n|    [L]eave?"

while True:
    try:

        print(TUI)
        choice = input('|\n|  > ').lower()


        # [L]ook...
        if choice == 'l':

            look = int(input('|\n|  > (int) '))
            gaze = Gaze(look, MEDUSA, BASKET, ROUND_NUM, SNAKES)

            print('|\n|  [~] Whoever told you that only the HAIR on her HEAD would be SNAKES was lying. Those who learned the TRUTH are now stuck in a PERMANENT state of DISGUST...\n|    GAZE = {}'.format(gaze))

            print('|\n|  [!] As a FAMILIAR, yet DISTURBING, sensation sets in you clear your head of PERTURBED thoughts...\n|\n|    ...to remember your ONE and only GOAL: play their favourite TUNE ~ !\n|')

            TUNE = list(MEDUSA.to_bytes(-(-SNAKE_LEN*SNAKE_NUM//8), 'big'))

            while TUNE:

                note = int(input('|  > (int) '))

                if note != TUNE.pop(0):
                    raise ValueError('oop-')
                
            print('|\n|  [~] While you catch your BREATH, her snakes, now CHARMED, respond in harmonious UNITY:\n|    FLAG = {}\n|\n|'.format(FLAG.decode()))
            break
        

        # [L]eave 
        elif choice == 'l':
            print('|\n|  [~] You managed to FLEE with all your LIMBS still flexible... for now.\n|')
            break


        else:
            print('|\n|\n|\n|\n|  You are NOTHING but a PEBBLE to her now...\n|\n|')

    except KeyboardInterrupt:
        print('\n|\n|\n|\n|  You are NOTHING but a PEBBLE to her now...\n|\n|')
        break

    except Exception as e:
        print('|\n|\n|\n|\n|  You are NOTHING but a PEBBLE to her now...\n|\n|')
        break
