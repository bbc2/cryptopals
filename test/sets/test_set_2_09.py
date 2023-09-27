import cryptopals.pkcs7


def test() -> None:
    result = cryptopals.pkcs7.pad(b"YELLOW SUBMARINE", block_length=20)

    assert result == b"YELLOW SUBMARINE\x04\x04\x04\x04"
