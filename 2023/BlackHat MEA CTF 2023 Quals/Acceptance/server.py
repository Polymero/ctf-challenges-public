#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Quals
#
# [Medium] Crypto - Acceptance
#


# Native imports
import os, json

# Local imports
from acceptance import *

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'FLAG{TH1S_1S_JUST_S0M3_D3BUG_FL4G}')


# Challenge set-up
council = [Member() for _ in range(8)]

councilPublic = 1
for i,j in enumerate(council):
    councilPublic *= j.public
    councilPublic %= P


# Server loop
HDR = """|
|       /\                                     _   (_)           
|      /  \   ____  ____  ____ ____ ____  ____| |_  _  ___  ____
|     / /\ \ / _  |/ _  |/ ___) _  ) _  |/ _  |  _)| |/ _ \|  _ \ 
|    | |__| ( ( | ( ( | | |  ( (/ ( ( | ( ( | | |__| | |_| | | | |
|    |______|\_|| |\_|| |_|___\____)_|| |\_||_|\___)_|\___/| | |_|
|           (_____(_____| / ____________|                (_) |                                                
|                        | /       ___  _   _ ____   ____ _| |
|          Part I        | |      / _ \| | | |  _ \ / ___) | |
|        Acceptance      | \_____| |_| | |_| | | | ( (___| | |
|                         \_______)___/ \____|_| |_|\____)_|_|
"""

print(HDR)

print('|\n|  ~ Challenge domain:\n|    P = 0x{:0256x}\n|    G = 0x{:0256x}'.format(P, G))

print('|\n|  ~ Council public keys:')
for i,j in enumerate(council):
    print('|    {}: 0x{:0256x}'.format(i, j.public))

while True:
    try:

        print('|\n|  ~ Menu:\n|    [J]oin\n|    [S]ign message\n|    [V]erify signature\n|    [Q]uit')
        choice = input('|\n|  > ').lower()


        if choice == 'j':

            userPublic = int(input('|\n|  ~ Enter your public key:\n|  > (hex) '), 16)

            user = Member(userPublic)

            print('|\n|  ~ You succesfully joined the Council ~ !')


        elif choice == 's':

            userMessage = input('|\n|  ~ Enter message to sign:\n|  > (str) ')
            assert 'flag' not in userMessage.lower()
            
            userCommit = input('|\n|  ~ Enter your SHA-256 commitment:\n|  > (hex) ').lower()
            R, t = [list(j) for j in list(zip(*[i.generateCommitment() for i in council]))]

            print('|\n|  ~ Council commitments:')
            for i,j in enumerate(council):
                print('|    {}: {}'.format(i, t[i]))

            userR = int(input('|\n|  ~ Enter your public R value:\n|  > (hex) '), 16)

            assert all(i.verifyCommitments(R + [userR], t + [userCommit]) for i in council)

            print('|\n|  ~ Council public R values:')
            for i,j in enumerate(council):
                print('|    {}: 0x{:0256x}'.format(i, R[i]))

            userS = int(input('|\n|  ~ Enter your public S value:\n|  > (hex) '), 16)

            S = [i.generateSignature(council + [user], R + [userR], userMessage) for i in council]

            # print('|\n|  ~ Council public S values:')
            # for i,j in enumerate(council):
            #     print('|    {}: 0x{:0256x}'.format(i, S[i]))

            aggL = user.public
            for i,j in enumerate(council):
                aggL *= j.public
                aggL %= P

            aggR = userR
            for r in R :
                aggR *= r
                aggR %= P

            aggS = (sum(S) + userS) % (P - 1)

            signature = {
                'L' : '0x{:0256x}'.format(aggL),
                'R' : '0x{:0256x}'.format(aggR),
                'S' : '0x{:0256x}'.format(aggS),
                'm' : userMessage
            }

            assert all(i.verifySignature(signature) for i in council)

            print('|\n|  ~ Here is the aggregated signature:\n|    SIG = {}'.format(json.dumps(signature)))


        elif choice == 'v':
            
            userSignature = json.loads(input('|\n|  ~ Enter signature to verify:\n|  > (json) '))

            assert all(i.verifySignature(userSignature) for i in council)

            print('|\n|  ~ Signature successfully verified ~ !')

            if int(userSignature['L'], 16) == (councilPublic * user.public) % P:

                if userSignature['m'] == 'Can I hab flag plz?':

                    print('|\n|  ~ Yes you can! Here you go:\n|    F = {}'.format(FLAG))


        elif choice == 'q':
            print('|\n|  ~ The Council bids you farewell ~\n|')
            break

        else:
            raise ValueError()

    except KeyboardInterrupt:
        print('\n|\n|  ~ The Council bids you farewell ~\n|')
        break

    except:
        print('|\n|  ~ It might be smarter not to aggrevate the Aggregation Council ~ !')