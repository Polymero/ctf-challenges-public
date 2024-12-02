### Hypsophobia

> _"I'm really not great with heights... :("_

Difficulty = {
    'Label'          : 'Elite',
    'Solves'         : -1,
    'Identification' : 4 / 5,
    'Exploitation'   : 3 / 5
}

Topics = {
    'Tags'       : ['ECC', 'Ladder', 'Quadratic Twists'],
    'Primitives' : ['Demytko']
}

Dockers = {
    'Challenge' : {
        'python3' : ['pycryptodome']
    },
    'Solver'    : {
        'python3' : ['pwntools', 'pycryptodome'],
        'sage'    : ['crt', 'ECM', 'EllipticCurve', 'GF', 'jacobi_symbol', 'prime_factors']
    }
}

Justification = {
    'Educational' : 'In this challenge the players are faced with a Demytko-based ECC ladder with minimal references to ECC. It is up to the player to recognise the presence of elliptic curves and work their way through dealing with 1) elliptic curves over composite rings and 2) quadratic twists.',
    'Inspiration' : 'https://dgalindo.es/IEEE2003-final.pdf'
}

Writeups = {
    ...
}