#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Easy] Crypto - Cicero
#


# Native imports
import random


# Set-up parameters
FILEPATH = './loremipsum-wordlist.txt'
DISTPARS = (0, 1)


# Cicero class
class Cicero:

    def __init__(self, filePath: str, distPars: tuple) -> None:
        with open(filePath, 'r') as f:
            self.words = list(f.read().split())
            f.close()
        a, b = distPars
        prob = [1 / (a + len(i)**b) for i in self.words]
        self.prob = [(sum(prob[:i]) + j) / sum(prob) for i,j in enumerate(prob)]
        self.alp  = ''
        for i in ''.join(self.words):
            if i not in self.alp:
                self.alp += i
        self.alp += ' ,.'

    def randomWord(self) -> str:
        r = random.random()
        return self.words[[r < i for i in self.prob].index(True)]
    
    def randomSentence(self) -> str:
        while True:
            r = round(random.gauss(7.3, 3.1))
            s = [self.randomWord() for _ in range(r)]
            if len(s) > 1:
                break
        t = ''
        for i in range(len(s) - 1):
            t += s[i]
            if random.random() < 0.19:
                t += ','
            t += ' '
        return t[0].upper() + t[1:] + s[-1] + '.'
    
    def randomParagraph(self) -> str:
        while True:
            r = round(random.gauss(16.7, 5.2))
            p = ' '.join(self.randomSentence() for _ in range(r))
            if p:
                break
        return p
    
    def encrypt(self, keyPhrase: str, plainText: str) -> str:
        keyList = keyPhrase.lower().split()
        cipherText = plainText
        for key in keyList:
            cipherText = ''.join([self.alp[(self.alp.index(j.lower()) + self.alp.index(key[i % len(key)])) % len(self.alp)] for i,j in enumerate(cipherText)])
        return cipherText
