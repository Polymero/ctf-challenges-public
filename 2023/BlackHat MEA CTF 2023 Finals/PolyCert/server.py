#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Hard] Crypto - PolyCert
#


# Native imports
import os

# Local imports
from certauth import *

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'FLAG{TH1S_1S_JUST_S0M3_D3BUG_FL4G}')


# Challenge set-up
certauth = CertAuth(BITSEC, KEYNUM)
certauth.registerUser('PolyCert Admin', blocked=True)


# Header
HDR = r"""|
|      ___      _         ___          _   
|     / _ \___ | |_   _  / __\___ _ __| |_ 
|    / /_)/ _ \| | | | |/ /  / _ \ '__| __|
|   / ___/ (_) | | |_| / /__|  __/ |  | |_ 
|   \/    \___/|_|\__, \____/\___|_|   \__|
|                 |___/                    
|                                          
|         the  Certified   Authority       
|         in  Certificate Authorities      
|"""

print(HDR)


# Server loop
print('|\n|\n|  [~] Welcome to the PolyCert CA terminal ~ !')
print('|\n|  [~] Our current public key rotation ::')
for i,j in enumerate(certauth.keys):
    print('|      {} : {}'.format(i, str(j)))

RUN = True
while RUN:
    try:

        user  = input('|\n|\n|  [~] Please register a new user:\n|  [>] ')
        
        err, ret = certauth.registerUser(user)
        if err:
            print('|\n|  [!] {}'.format(ret))
        else:
            print('|\n|  [_] {}'.format(ret))
            break

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye.\n|')
        RUN = False
        break

    except:
        print('|\n|  [!] Something went wrong!')

while RUN:
    try:

        choice = input('|\n|\n|  [~] Menu:\n|  [A] Account Info\n|  [S] Sign Certificate\n|  [V] Verify Certificate\n|  [Q] Quit\n|\n|  [>] ')

        if choice == 'a':
            print('|\n|  [~] {} Account Info ::\n|      {}'.format(user, json.dumps(certauth.users[user])))

        elif choice == 's':
            cert = input('|  [>] (JSON) ')
            err, ret, cst = certauth.signCertificate(cert)
            if err:
                print('|\n|  [!] {}'.format(ret))
            else:
                print('|\n|  [_] Certificate succesfully signed ::\n|      CERT = {}\n|      COST = {}'.format(ret, cst))

        elif choice == 'v':
            cert = input('|  [>] (JSON) ')
            err, ret = certauth.verifyCertificate(cert)
            if err:
                print('|\n|  [!] {}'.format(ret))
            else:
                print('|\n|  [_] {}'.format(ret))

            if not err:
                cert = json.loads(B64Dec(json.loads(cert)['CERT']))
                if cert['OWNER'] == 'PolyCert Admin':
                    flag, _ = SquareAndMultiply(int(FLAG.encode().hex(), 16), 0x10001, int.from_bytes(B64Dec(cert['PK']), 'big'))
                    flag    = B64Enc(flag.to_bytes(256, 'big'))
                    print('|\n|\n|  [~] Here is a little something on the house ::\n|      FLAG = {}'.format(flag))   

        elif choice == 'q':
            print('|\n|\n|  [~] Goodbye.\n|')
            break

        else:
            print('|\n|\n|  [!] Unknown option.\n|')


    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye.\n|')
        break

    except:
        print('|\n|  [!] Something went wrong!')