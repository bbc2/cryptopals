import base64
from importlib.resources import files

import cryptopals.ecb


def test():
    lines = files("test.sets.data").joinpath("1_08.txt").open("rb").readlines()
    ciphertexts = [base64.b64decode(line) for line in lines]

    detected = [
        index
        for (index, ciphertext) in enumerate(ciphertexts)
        if cryptopals.ecb.detect(ciphertext, block_length=16)
    ]

    assert detected == [132]
