import base64

import pkg_resources

import cryptopals.ecb


def test():
    lines = pkg_resources.resource_stream("test.sets", "data/1/08.txt").readlines()
    ciphertexts = [base64.b64decode(line) for line in lines]

    detected = [
        index
        for (index, ciphertext) in enumerate(ciphertexts)
        if cryptopals.ecb.detect(ciphertext, block_length=16)
    ]

    assert detected == [132]
