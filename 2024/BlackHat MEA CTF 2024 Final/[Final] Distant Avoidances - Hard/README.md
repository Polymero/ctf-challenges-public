### Distant Avoidances of the Impetus Cruel

> _"A challenge so NICE I just had to make it TWICE :^) :^)"_

```py
Difficulty = {
    'Label'          : 'Hard',
    'Solves'         : -1,
    'Identification' : 2 / 5,
    'Exploitation'   : 2 / 5
}

Topics = {
    'Tags'       : ['Reduced Round', 'Polynomials'],
    'Primitives' : ['MiMC', 'Jarvis'],
    'CWEs'       : {
        326  : 'Inadequate Encryption Strength',
        1240 : 'Use of a Cryptographic Primitive with a Risky Implementation'
    }
}

Dockers = {
    'Challenge' : {
        'python3' : ['pycryptodome']
    },
    'Solver'    : {
        'python3' : ['pwntools', 'pycryptodome'],
        'sage'    : ['crt', 'factor', 'GF', 'ideal', 'PolynomialRing', 'Zmod', 'ZZ']
    }
}

Justification = {
    'Educational' : 'On the surface, polynomials with inverses might more secure than their non-inverse counterparts. Mostly because the polynomial degree seems much larger and a lot of computation on rational polynomial rings is harder. The challenge for the player is to realise that small inverses still only create low-degree numerators which can be solved accordingly.',
    'Inspiration' : 'https://www.zellic.io/blog/algebraic-attacks-on-zk-hash-functions/'
}

Writeups = {
    ...
}
```
