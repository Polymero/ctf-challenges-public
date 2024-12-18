### Trouble in Pairs

> _"Real trouble never comes alone..."_

```py
Difficulty = {
    'Label'          : 'Elite',
    'Solves'         : -1,
    'Identification' : 4 / 5,
    'Exploitation'   : 2 / 5
}

Topics = {
    'Tags'       : ['Zero-Knowledge Proof', 'Malleable Encryption', 'Fiat-Shamir Transformation'],
    'Primitives' : ['ElGamel Encryption', 'Schnorr Signatures'],
    'CWEs'       : {
        327 : 'Use of a Broken or Risky Cryptographic Algorithm',
        358 : 'Improperly Implemented Security Check for Standard',
        407 : 'Inefficient Algorithmic Complexity'
    }
}

Dockers = {
    'Challenge' : {
        'python3' : ['pycryptodome']
    },
    'Solver'    : {
        'python3' : ['pwntools', 'pycryptodome']
    }
}

Justification = {
    'Educational' : 'Zero-Knowledge is an exciting field of modern cryptography that sees a lot of attention. The Fiat-Shamir transformation is a very common technique to turn interactive schemes into non-interactive schemes, allowing for much more flexibility. However, this transformation needs to be implemented properly as so-called weak Fiat-Shamir transformation can lead to relatively trivial forgery attacks. In this challenge the players are faced with a malleable encryption algorithm containing non-interactive Schnorr-based proofs. The algorithm contains a weak Fiat-Shamir transformation which can be exploited by the players to generate valid encryptions of arbitrary messages.',
    'Inspiration' : 'https://eprint.iacr.org/2023/691.pdf'
}

Writeups = {
    ...
}
```
