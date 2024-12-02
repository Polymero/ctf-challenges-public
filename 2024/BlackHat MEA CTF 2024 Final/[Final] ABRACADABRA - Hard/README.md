### ABRACADABRA

> _"Wanna see a magic trick?"_

Difficulty = {
    'Label'          : 'Hard',
    'Solves'         : -1,
    'Identification' : 4 / 5,
    'Exploitation'   : 1 / 5
}

Topics = {
    'Tags'       : ['Kleptography', 'Malicious Implementation'],
    'Primitives' : ['ElGamel Signatures', 'SETUP']
}

Dockers = {
    'Challenge' : {
        'python3' : ['MAGIC_POWERS.py', 'pycryptodome']
    },
    'Solver'    : {
        'python3' : ['pwntools', 'pycryptodome'],
        'sage'    : ['Primes', 'prod']
    }
}

Justification = {
    'Educational' : 'Any deviation from well-defined standards can lead to unexpected behaviour and/or vulnerabilities. However, even worse, some of these deviations can be maliciously implemented to be abused by the adversarial developer later on. This challenge provide the players with a signature oracle containing a Secretely Embedded Trapdoor with Universal Protection (SETUP) that allows the developer to recover secret information from generated signatures only, thus breaching security. The players are tasked with identifying the SETUP and supplying calculated parameters such that the present SETUP is minimally effective.',
    'Inspiration' : 'https://pure.tue.nl/ws/portalfiles/portal/46913835/801620-1.pdf'
}

Writeups = {
    ...
}