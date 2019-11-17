import pkg_resources

import cryptopals.format
import cryptopals.single_byte_xor


def test():
    ciphertexts = [
        cryptopals.format.hex_to_bytes(line.strip())
        for line in pkg_resources.resource_stream(
            "test.sets", "data/1/04.txt"
        ).readlines()
    ]

    result = cryptopals.single_byte_xor.find(ciphertexts)

    assert result == b"Now that the party is jumping\n"
