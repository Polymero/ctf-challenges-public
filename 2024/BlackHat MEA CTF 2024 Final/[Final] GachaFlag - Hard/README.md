### GachaFlag

> _"Try your luck here, why don't you..."_

```py
Difficulty = {
    'Label'          : 'Hard',
    'Solves'         : -1,
    'Identification' : 1 / 5,
    'Exploitation'   : 4 / 5
}

Topics = {
    'Tags'       : ['Python Random Module', 'Rejection Sampling'],
    'Primitives' : ['Mersenne Twister']
}

Dockers = {
    'Challenge' : {
        'python3' : []
    },
    'Solver'    : {
        'python3' : ['pwntools', 'pycryptodome', 'z3-solver']
    }
}

Justification = {
    'Educational' : 'Since the Mersenne Twister is fully linear, it is a perfect target for gaining experience with a SAT solver like z3-solver. There are plenty of examples of z3-solver being used to crack Mersenne Twisters. In order to provide the player with a new and unique challenge, rejection sampling was used to add an extra layer of complexity to the exploitation phase of the challenge.',
    'Inspiration' : 'Gachas are fun, Mersenne Twisters are fun, you do the math ~ :)'
}

Writeups = {
    ...
}
```
