import base64
from importlib.resources import open_binary

import cryptopals.ecb


def test():
    lines = open_binary("test.sets.data", "1_08.txt").readlines()
    ciphertexts = [base64.b64decode(line) for line in lines]

    detected = [
        index
        for (index, ciphertext) in enumerate(ciphertexts)
        if cryptopals.ecb.detect(ciphertext, block_length=16)
    ]

    assert detected == [132]
