#!/usr/bin/env python3
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import requests, base64, time

# Non-native imports


# Functions
def b64enc(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

def b64dec(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + '===')

def HuffmanDecompress(compressedBytestring, huffmanTree):
    inverseTree = { huffmanTree[i] : i for i in huffmanTree }
    compressedBitstring = list(bin(int.from_bytes(compressedBytestring, 'big'))[3:])
    decompressedBitstring = ''
    temporaryBitstring = ''
    while compressedBitstring:
        temporaryBitstring += compressedBitstring.pop(0)
        if temporaryBitstring in inverseTree:
            decompressedBitstring += inverseTree[temporaryBitstring]
            temporaryBitstring = ''
    return decompressedBitstring, temporaryBitstring


# Oracle class
class ORACLE:

    ALP = '{":, }ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    def __init__(self, webAddress):
        self.webAddress = webAddress
        response = requests.get(self.webAddress, allow_redirects=False)
        tokenData, tokenTag = [b64dec(i) for i in response.cookies['token'].split('.')]
        huffmanTree = HuffmanDecompress(tokenTag, {'0': '11', '1': '0', '.': '10'})[0].split('.')
        huffmanTree = { self.ALP[i] : huffmanTree[i] for i in range(len(self.ALP)) if huffmanTree[i] }
        self.adminData = tokenData
        self.adminTree = huffmanTree
        self.tag = response.cookies['token'].split('.')[1]

    def login(self, data):
        return requests.get(self.webAddress, cookies={'token': b64enc(data) + '.' + self.tag}, allow_redirects=True)


# Header
RUNTIME = int(time.time())
print('|\n|  ~ SOLVE SCRIPT for HUFFin')


oracle = ORACLE('https://hitb-30eae76201b5f166b1f302e8874ac885-0.chal.game.ctf.ae/')
print(oracle.adminTree)


# tokenAlphabet = '0123456789abcdef'
tokenAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'

tokenDigraphs = []
for i in tokenAlphabet:
    for j in tokenAlphabet:
        if (i in oracle.adminTree) and (j in oracle.adminTree):
            tokenDigraphs += [i + j]

digraphLengths = set([len(''.join([oracle.adminTree[i] for i in j])) for j in tokenDigraphs])
print(max(digraphLengths), 2 ** max(digraphLengths))

recovered = '"}'

CALLS = 0
for _ in range(24):

    pointDictionary = { i : 0 for i in tokenDigraphs }

    for k in range(1, 2 ** max(digraphLengths)):

        print(k, end='\r', flush=True)

        xorBitstring = bin(k)[2:] + '0' * sum(len(oracle.adminTree[i]) for i in recovered)

        forgedToken = bytes([i ^ j for i,j in zip(oracle.adminData, int(xorBitstring, 2).to_bytes(len(oracle.adminData), 'big'))])

        CALLS += 1
        response = oracle.login(forgedToken)

        for target in tokenDigraphs:

            if k >= 2 ** len(''.join(oracle.adminTree[i] for i in target)):
                continue

            bitstring = ''.join(oracle.adminTree[i] for i in target + recovered)

            forgedBitstring = '{:0{n}b}'.format(int(xorBitstring, 2) ^ int(bitstring, 2), n=len(bitstring))
            decompressedBitstring, restBitstring = HuffmanDecompress(int('1' + forgedBitstring, 2).to_bytes(32, 'big'), oracle.adminTree)

            validLogin = False
            if not restBitstring:
                if decompressedBitstring.replace(' ', '')[-2:] == '"}':
                    if all(i not in decompressedBitstring.replace(' ', '')[:-2] for i in '{"}'):
                        validLogin = True

            pointDictionary[target] += validLogin == ('Invalid username or password' in response.text)

    for k in pointDictionary:
        pointDictionary[k] = int(pointDictionary[k] / (2 ** len(''.join(oracle.adminTree[i] for i in k)) - 1) * 100)

    bestScore = max(pointDictionary[i] for i in pointDictionary)
    possibleDigraphs = [i for i in pointDictionary if pointDictionary[i] == bestScore]
    if len(possibleDigraphs) != 1:
        print('OOP-')
        print(possibleDigraphs)
        break

    recovered = possibleDigraphs[0] + recovered

    points = [pointDictionary[i] for i in pointDictionary]
    points.sort()
    points = points[::-1]

    print('|  ({}m {}s) {} {} {}'.format(int(time.time() - RUNTIME) // 60, int(time.time() - RUNTIME) % 60, CALLS, points[:3], recovered))