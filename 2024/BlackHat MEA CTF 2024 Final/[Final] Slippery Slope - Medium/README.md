### Slippery Slope

> _"I knew LEAFs are a slip hazard this time of year, but I wasn't aware they're also a crypto hazard..."_

```py
Difficulty = {
    'Label'          : 'Medium',
    'Solves'         : -1,
    'Identification' : 2 / 5,
    'Exploitation'   : 2 / 5
}

Topics = {
    'Tags'       : ['Key Escrow', 'Law Enforcement Accessability Field', 'Linear Algebra'],
    'Primitives' : ['AES-CTR', 'DHKE'],
    'CWEs'       : {
        328 : 'Use of Weak Hash',
        512 : 'Spyware'
    }
}

Dockers = {
    'Challenge' : {
        'python3' : ['pycryptodome']
    },
    'Solver'    : {
        'python3' : ['pwntools']
    }
}

Justification = {
    'Educational' : 'Key escrowing is one of the many historically proposed ways of govermental bodies to undermine the privacy (and security) of their citizens. In 1993, under the Clinton administration, the Clipper chip was such a proposed solution. This construction added a LEAF to encrypted communication, allowing them to decrypt the communication at a later stage. In this challenge the players are faced with a big brother character using a key escrow construction to perform content checks on their communication. The goal is to slip forbidden content through this check without raising suspicion.',
    'Inspiration' : 'https://www.mattblaze.org/papers/eesproto.pdf'
}

Writeups = {
    ...
}
```
