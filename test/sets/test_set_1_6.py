import base64

import pkg_resources

import cryptopals.multi_byte_xor
import cryptopals.xor


def test_hamming_distance():
    result = cryptopals.multi_byte_xor.hamming_distance(
        b"this is a test", b"wokka wokka!!!",
    )

    assert result == 37


def test_crack():
    ciphertext = base64.b64decode(
        pkg_resources.resource_stream("test.sets", "data/1/6.txt").read()
    )

    result = cryptopals.multi_byte_xor.crack(ciphertext, key_lengths=range(2, 40))

    assert result == b"Terminator X: Bring the noise"
