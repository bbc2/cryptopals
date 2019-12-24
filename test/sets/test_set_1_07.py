import base64
from importlib.resources import read_binary

import cryptopals.aes


def test():
    data = read_binary("test.sets.data", "1_07.txt")
    ciphertext = base64.b64decode(data)

    result = cryptopals.aes.decrypt_ecb(key=b"YELLOW SUBMARINE", ciphertext=ciphertext)

    assert result.startswith(b"I'm back and I'm ringin' the bell")
