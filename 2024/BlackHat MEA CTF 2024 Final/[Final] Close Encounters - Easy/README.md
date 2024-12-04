### Close Encounters of the Gorgon Kind

> _"At least strike a t-pose before you die so you can meme forever :^)"_

```py
Difficulty = {
    'Label'          : 'Easy',
    'Solves'         : -1,
    'Identification' : 2 / 5,
    'Exploitation'   : 1 / 5
}

Topics = {
    'Tags'       : ['Reduced Round', 'Polynomials'],
    'Primitives' : ['MiMC']
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
    'Educational' : 'We are often taught that non-linear systems are hard to break, but that only holds for systems which introduce sufficient non-linearity. In this challenge players are faced with a reduced round version of MiMC which does not even come close to introducing enough non-linearity to be considered secure.',
    'Inspiration' : 'https://eprint.iacr.org/2016/492.pdf'
}

Writeups = {
    ...
}
```