import base64
from importlib.resources import files

import cryptopals.aes
import cryptopals.pkcs7


def test() -> None:
    data = files("test.sets.data").joinpath("2_10.txt").read_bytes()
    ciphertext = base64.b64decode(data)

    result = cryptopals.aes.decrypt_cbc(
        key=b"YELLOW SUBMARINE",
        ciphertext=cryptopals.pkcs7.pad(ciphertext, block_length=16),
        iv=b"\x00" * 16,
    )

    assert result.startswith(b"I'm back and I'm ringin' the bell \n")
