#!/usr/bin/env python3
#
# BlackHat MEA 2023 CTF Finals
#
# [Elite] Crypto - Joyko
#

# Native imports
from secrets import randbelow

# Non-native imports
from Crypto.Util.number import inverse

# Local imports
from private import PRIMES, TRACES

# FYI :: PRIMES was generated using
# PRIMES = []
# while len(PRIMES) < PNUM:
#     p = getPrime(512)
#     if p % 3 == 2:
#         PRIMES += [p]


# Elliptic curve parameters
N = 1
for prime in PRIMES:
    N *= prime
A = 13
B = 37
E = (A << (A//2)) + B


# Functions
def Joy(x, k, steps=2048):
    assert k & 1
    k   = ((k - 1) * inverse(2, N)) % N
    r   = randbelow(N - 1)
    x  *= r
    rr  = pow(r, 2, N)
    yp  = 4*((x*x + A*rr)*x + B*r*rr)
    x3  = 3*x
    m   = (x*x3 + A*rr) % N
    x3 *= yp
    yp  = pow(yp, 2, N)
    xrp = pow(m, 2, N) - x3
    yr  = 2*m*xrp + yp
    xrq, yq = xrp, yp
    prev = 0
    skip = 0
    for t in range(steps):
        curr = bool(k & (1 << t))
        prev ^= curr
        if prev:
            xrp, xrq = xrq, xrp
        if skip: 
            skipnext = not prev
        else:
            skipnext = xrq == 0
        skipcurr = skip or skipnext
        if prev ^ skipcurr:
            yp, yq = yq, yp
        prev = curr ^ skipcurr ^ skip
        xrq = xrp - xrq
        if skipcurr:
            xrp, xrq = xrq, xrp
        xrq = xrp - xrq
        if skipcurr:
            xrp, xrq = xrq, xrp
            yp, yr = yr, yp
        yp  *= xrq
        yp  %= N
        xrq  = pow(xrq, 2, N)
        xrp *= xrq
        xrp %= N
        yp  *= xrq
        yp  *= yr
        yp  %= N
        yq  *= yr
        yq  %= N
        h    = pow(yr, 2, N)
        m    = h + yq - 2*xrp
        xrp  = pow(xrp, 2, N) - yp
        yp  *= h
        yp  %= N
        yq  *= h
        yq  %= N
        if skip:
            xrp, yq = yq, xrp
        skip = skipnext
        xrq  = xrp - yq
        yq   = m*yq + yp
        yr   = m*xrp + yp
    if skip and not prev:
        return 'Inf'
    if prev:
        xrp, xrq = xrq, xrp
        yp, yq = yq, yp
    xpq = xrq - xrp
    if skip:
        xpq, xrq = xrq, xpq
    xpq *= 4
    xrq *= 4
    yq  *= 4
    xq  = pow(m, 2, N) - xpq - xrq
    xp  = 3*xpq + xq
    xr  = 3*xrq + xq
    c   = 3*yq - m*xq
    num = B*(xp*(xq + xr) + xq*xr + 6*c*m)
    den = A*(3*c*c - xp*(xq*xr))
    if pow(num, 3, N) != (pow(den, 2, N) * A * B) % N:
        return None
    return (xp * num * inverse(den, N)) % N

def Ko(x):
    order = 1
    for i,p in enumerate(PRIMES):
        order *= p + 1 + (-1)**(pow(A*x + B, (p - 1) // 2, p)) * TRACES[i]
    return Joy(x, inverse(E, order))