#!/usr/local/bin/python
#
# by Polymero
#
# for CyberHub CTF 2023
#

# Native imports
from secrets import randbelow

# Non-native imports
from Crypto.Util.number import getPrime, GCD   # pip install pycryptodome

# Local imports
with open('flag.txt', 'rb') as f:
    FLAG = f.read()
    f.close()


# Server class object
class RSA:
    def __init__(self, bits):
        p, q = [getPrime(bits // 2) for _ in '01']
        self.public  = p * q
        self.private = (p - 1) * (q - 1)
        self.used = set()

    def getExponent(self):
        while True:
            e = randbelow(self.private)
            if all(GCD(e, i) != 1 for i in self.used):
                self.used.add(e)
                return e
            
    def getEncryption(self, x):
        if type(x) == str:
            x = x.encode()
        if type(x) == bytes:
            x = int.from_bytes(x, 'big')
        e = self.getExponent()
        return e, pow(x, e, self.public)


# Challenge set-up
rsa = RSA(1024)
bit = int.from_bytes(FLAG, 'big').bit_length()
print("|\n|  ~ Let's see if you are a real RSA trickster ~ !\n|    n = {}\n|    b = {}\n|".format(rsa.public, bit))


# Main server loop
while True:
    try:

        print('|\n|  ~ Menu:\n|    [E]ncrypt flag\n|    [Q]uit\n|')
        choice = input('|  > ').lower()

        if choice == 'e':
            e, c = rsa.getEncryption(FLAG)
            print('|\n|  ~ Here you go:\n|    e = {}\n|    c = {}\n|'.format(e, c))

        elif choice == 'q':
            print('|\n|\n|  ~ Bye ~ !\n|')
            break

        else:
            print('|\n|\n|  ~ Try again!\n|')

    except KeyboardInterrupt:
        print('|\n|\n|  ~ Bye ~ !\n|')
        break

    except:
        print('|\n|  ~ Something went wrong...\n|')