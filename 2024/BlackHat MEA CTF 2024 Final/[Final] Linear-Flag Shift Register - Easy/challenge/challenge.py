#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Easy] Crypto - Linear-Flag Shift Register
#
# by Polymero
#

# Native imports
import os
from typing import Tuple, List, Dict, Union
from secrets import randbelow

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Challenge classes
class LFSR:
    def __init__(self, seed: bytes, taps: List[int]) -> None:
        self.state = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(seed, 'big'), n=8*len(seed))]
        self.taps = taps
        
    def Run(self, k: int = 1) -> List[int]:
        out = []
        for _ in range(k):
            new = 0
            for tap in self.taps:
                new ^= self.state[tap]
            out += [self.state[-1]]
            self.state = [new] + self.state[:-1]
        return out
    
class DuoLFSR:
    def __init__(self, lfsrs: List[LFSR]) -> None:
        self.lfsrs = lfsrs
        
    def Run(self, k: int = 1) -> List[int]:
        outs = []
        for _ in range(k):
            out = 0
            for lfsr in self.lfsrs:
                out ^= lfsr.Run(1)[0]
            outs += [out]
        return outs
    

# Challenge parameters
TAPS = [-1]
while len(TAPS) < 32:
    k = randbelow(8*len(FLAG) - 1)
    if k not in TAPS:
        TAPS += [k]


# Challenge set-up
HDR = r"""|
|   ___________________________________________________________
|   ___  /___(_)_________________ _________________  ____/__  /_____ _______ _
|   __  / __  /__  __ \  _ \  __ `/_  ___/________  /_   __  /_  __ `/_  __ `/
|   _  /___  / _  / / /  __/ /_/ /_  /   _/_____/  __/   _  / / /_/ /_  /_/ /
|   /_____/_/  /_/ /_/\___/\__,_/ /_/           /_/      /_/  \__,_/ _\__, /
|   _____________ ______________________________ _________________ __/____/___
|   __  ___/__  /____(_)__  __/_  /________  __ \___________ ___(_)________  /_____________
|   _____ \__  __ \_  /__  /_ _  __/______  /_/ /  _ \_  __ `/_  /__  ___/  __/  _ \_  ___/
|   ____/ /_  / / /  / _  __/ / /________  _, _//  __/  /_/ /_  / _(__  )/ /_ /  __/  /
|   /____/ /_/ /_//_/  /_/    \__/      /_/ |_| \___/_\__, / /_/  /____/ \__/ \___//_/
|                                                    /____/
|"""
print(HDR)


# Server loop
while True:
    try:

        lfsrFlag = LFSR(FLAG, TAPS)

        print('|\n|  [?] So what is your {} char guess ~ ?'.format(len(FLAG)))
        guess = input('|  > (str) ').encode()

        if len(guess) != len(FLAG):
            raise ValueError('Your guess is {} characters...'.format(len(guess)))
        
        lfsrGuess = LFSR(guess, TAPS)

        lfsrDuo = DuoLFSR([lfsrFlag, lfsrGuess])
        _ = lfsrDuo.Run(1337)

        resp = lfsrDuo.Run(2**(8 - 1) + 2**(8 + 1))
        resp = sum([j * 2**i for i,j in enumerate(resp)])

        print('|\n|  [~] If your guess was right then the response should be 0 ~ !')
        print('|    RETURN = {}\n|\n|'.format(resp))

        break

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
