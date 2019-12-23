import base64

import pkg_resources

import cryptopals.aes
import cryptopals.pkcs7


def test():
    ciphertext = base64.b64decode(
        pkg_resources.resource_stream("test.sets", "data/2/10.txt").read()
    )

    result = cryptopals.aes.decrypt_cbc(
        key=b"YELLOW SUBMARINE",
        ciphertext=cryptopals.pkcs7.pad(ciphertext, block_length=16),
        iv=b"\x00" * 16,
    )

    assert result.startswith(b"I'm back and I'm ringin' the bell \n")
