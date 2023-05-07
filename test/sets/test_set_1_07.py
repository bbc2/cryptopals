import base64
from importlib.resources import files

import cryptopals.aes


def test():
    data = files("test.sets.data").joinpath("1_07.txt").read_bytes()
    ciphertext = base64.b64decode(data)

    result = cryptopals.aes.decrypt_ecb(key=b"YELLOW SUBMARINE", ciphertext=ciphertext)

    assert result.startswith(b"I'm back and I'm ringin' the bell")
