#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Hard] Crypto - Ping Pong
#

# Native imports
import os, json

# Local imports
from pingpong import *

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{{{}}}'.format(os.urandom(16).hex()))
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Challenge set-up
opponent = PingPong.new(1024, 256)

# Header
HDR = r"""|
|
|   ヽ(^o^)ρ ┳┻┳ °σ(^o^)/
|"""

print(HDR)


# Server loop
print('|\n|  ~ My opponent is ::')
print('|    ' + json.dumps({
    'p': opponent.longDomain['p'],
    'q': opponent.longDomain['q'],
    'g': opponent.longDomain['g'],
    'y': opponent.longPublic
}))


# My match
print('|\n|\n|  ! FIRST MATCH ! ME vs OPPONENT !')
me = PingPong.load(opponent.longDomain)
meSecret,  meSignature  = me.initiate()

print('|\n|  ~ Me -> Opponent ::')
print('|    ' + json.dumps({
    'y': me.longPublic,
    'r': meSignature[0],
    's': meSignature[1]
}))

opponentSecret, opponentSignature = opponent.initiate()
opponent.receive(opponentSecret, me.longPublic, meSignature)

print('|\n|  ~ Opponent -> Me ::')
print('|    ' + json.dumps({
    'r': opponentSignature[0],
    's': opponentSignature[1]
}))

me.receive(meSecret, opponent.longPublic, opponentSignature)
assert opponent.shortDomain == me.shortDomain

opponentSecret, opponentSignature = opponent.initiate()

print('|\n|  ~ Opponent -> Me ::')
print('|    ' + json.dumps({
    'y': opponent.shortPublic,
    'r': opponentSignature[0],
    's': opponentSignature[1]
}))

meSecret, meSignature = me.initiate()
meOTPKey = me.receive(meSecret, opponent.shortPublic, opponentSignature)

print('|\n|  ~ Me -> Opponent ::')
print('|    ' + json.dumps({
    'y': me.shortPublic,
    'r': meSignature[0],
    's': meSignature[1]
}))

opponentOTPKey = opponent.receive(opponentSecret, me.shortPublic, meSignature)


# My serve
meMessage  = b'Serve: ' + FLAG
opponentMessage = b''

for i in range(0, len(meMessage), 128 - 1):

    meBlock = meMessage[ i : i + (128 - 1) ]
    meBlock = len(meBlock).to_bytes(1, 'big') + meBlock
    meBlock += os.urandom(128 - len(meBlock))
    meCipher = bytes([x ^ y for x,y in zip(meBlock, meOTPKey.to_bytes(128, 'big'))])

    meSecret, meSignature = me.initiate()

    print('|\n|  ~ Me -> Opponent ::')
    print('|    ' + json.dumps({
        'c': meCipher.hex(),
        'r': meSignature[0],
        's': meSignature[1]
    }))

    opponentPacket = bytes([x ^ y for x,y in zip(meCipher, opponentOTPKey.to_bytes(128, 'big'))])
    opponentMessage += opponentPacket[ 1 : opponentPacket[0] + 1 ]

    opponentSecret, opponentSignature = opponent.initiate()
    opponentOTPKey = opponent.receive(opponentSecret, me.shortPublic, meSignature)

    print('|\n|  ~ Opponent -> Me ::')
    print('|    ' + json.dumps({
        'r': opponentSignature[0],
        's': opponentSignature[1]
    }))

    meOTPKey = me.receive(meSecret, opponent.shortPublic, opponentSignature)

assert meMessage == opponentMessage


# Opponent's action
opponentMessage = b' S M A S H '
while len(opponentMessage) < 128:
    opponentMessage = b'~' + opponentMessage + b'~'

opponentCipher = bytes([x ^ y for x,y in zip(opponentMessage[:128], opponentOTPKey.to_bytes(128, 'big'))])

print('|\n|  ~ Opponent -> Me ::')
print('|    ' + json.dumps({
    'c': opponentCipher.hex()
}))


print('|\n|  I lost... QnQ')


# Your match
print('|\n|\n|  ! SECOND MATCH ! YOU vs OPPONENT !')
opponent.shortDomain = None
opponent.shortPublic = None
opponent.shortSecret = None
opponentOTPKey = None

while True:

    try:

        print('|\n|  ~ You -> Opponent ::')
        yourInput = json.loads(input('|    > (JSON) '))


        if set(yourInput) == {'y', 'r', 's'}:
            
            yourStaticPublic = yourInput['y']
            yourSignature = (yourInput['r'], yourInput['s'])

            opponent.shortDomain = None
            opponent.shortPublic = None
            opponent.shortSecret = None
            opponentSecret, opponentSignature = opponent.initiate()

            print('|\n|  ~ Opponent -> You ::')
            print('|    ' + json.dumps({
                'r': opponentSignature[0],
                's': opponentSignature[1]
            }))

            opponent.receive(opponentSecret, yourStaticPublic, yourSignature)
            opponentSecret, opponentSignature = opponent.initiate()

            print('|\n|  ~ Opponent -> You ::')
            print('|    ' + json.dumps({
                'y': opponent.shortPublic,
                'r': opponentSignature[0],
                's': opponentSignature[1]
            }))

            print('|\n|  ~ You -> Opponent ::')
            yourInput = json.loads(input('|    > (JSON) '))

            assert set(yourInput) == {'y', 'r', 's'}

            yourEphemeralPublic = yourInput['y']
            yourSignature = (yourInput['r'], yourInput['s'])

            opponentOTPKey = opponent.receive(opponentSecret, yourEphemeralPublic, yourSignature)


        if set(yourInput) == {'c', 'r', 's'}:
            
            yourCipher = bytes.fromhex(yourInput['c'])
            yourSignature = (yourInput['r'], yourInput['s'])

            yourMessage = bytes([x ^ y for x,y in zip(yourCipher, opponentOTPKey.to_bytes(128, 'big'))])
            yourMessage = yourMessage[ 1 : yourMessage[0] + 1 ]

            opponentSecret, opponentSignature = opponent.initiate()
            opponentOTPKey = opponent.receive(opponentSecret, yourEphemeralPublic, yourSignature)

            print('|\n|  ~ Opponent -> You ::')
            print('|    ' + json.dumps({
                'r': opponentSignature[0], 
                's': opponentSignature[1]
                }))
            
            if b'flag' in yourMessage:

                opponentMessage = ' That is beyond your light cone, young Adeen '
                while len(opponentMessage) < 128:
                    opponentMessage = b'~' + opponentMessage + b'~'

                opponentCipher = bytes([x ^ y for x,y in zip(opponentMessage[:128], opponentOTPKey.to_bytes(128, 'big'))])
                opponentSecret, opponentSignature = opponent.initiate()

                print('|\n|  ~ Opponent -> You ::')
                print('|    ' + json.dumps({
                    'c': opponentCipher.hex(),
                    'r': opponentSignature[0],
                    's': opponentSignature[1]
                }))

                print('|\n|  ~ You -> Opponent ::')
                yourInput = json.loads(input('|    > (JSON) '))

                assert set(yourInput) == {'r', 's'}

                yourSignature = (yourInput['r'], yourInput['s'])

                opponentOTPKey = opponent.receive(opponentSecret, yourEphemeralPublic, yourSignature)


    except KeyboardInterrupt:
        break

    except:
        continue
