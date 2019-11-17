import base64

import pkg_resources

import cryptopals.aes


def test():
    data = pkg_resources.resource_stream("test.sets", "data/1/7.txt").read()
    ciphertext = base64.b64decode(data)

    result = cryptopals.aes.decrypt_ecb(key=b"YELLOW SUBMARINE", ciphertext=ciphertext)

    assert result.startswith(b"I'm back and I'm ringin' the bell")
