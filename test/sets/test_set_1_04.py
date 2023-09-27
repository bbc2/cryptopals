from importlib.resources import files

import cryptopals.format
import cryptopals.single_byte_xor


def test() -> None:
    ciphertexts = [
        cryptopals.format.hex_to_bytes(line.strip())
        for line in files("test.sets.data").joinpath("1_04.txt").open().readlines()
    ]

    result = cryptopals.single_byte_xor.find(ciphertexts)

    assert result == b"Now that the party is jumping\n"
