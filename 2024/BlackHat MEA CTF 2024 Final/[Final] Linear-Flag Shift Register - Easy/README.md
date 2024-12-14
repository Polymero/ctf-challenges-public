### Linear-Flag Shift Register

> _"If the air conditioning is on too strong again, hopefully this challenge will help warm you up... :)"_

```py
Difficulty = {
    'Label'          : 'Easy',
    'Solves'         : -1,
    'Identification' : 1 / 5,
    'Exploitation'   : 2 / 5
}

Topics = {
    'Tags'       : ['Unknown Feedback Polynomial'],
    'Primitives' : ['Linear-Feedback Shift Register'],
    'CWEs'       : {
        335  : 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)',
        337  : 'Predictable Seed in Pseudo-Random Number Generator (PRNG)',
        338  : 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)'
    }
}

Dockers = {
    'Challenge' : {
        'python3' : [] 
    },
    'Solver'    : { 
        'python3' : ['pwntools', 'pycryptodome'],
        'sage'    : ['GF', 'Matrix', 'berlekamp_massey']
    }
}

Justification = {
    'Educational' : 'Testing a player's basic knowledge on LFSRs, with an emphesis on seed reconstruction and unknown taps / feedback polynomial recovery.',
    'Inspiration' : '"What if I just put the flag inside an LFSR?"'
}

Writeups = {
    ...
}
```
