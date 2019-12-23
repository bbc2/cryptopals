import pytest

import cryptopals.pkcs7


@pytest.mark.parametrize(
    "bytes_,block_length,expected",
    [
        (b"", 1, b"\x01"),
        (b"1", 1, b"1\x01"),
        (b"1", 2, b"1\x01"),
        (b"1", 3, b"1\x02\x02"),
    ],
)
def test_pad_mod(bytes_, block_length, expected):
    result = cryptopals.pkcs7.pad(bytes_=bytes_, block_length=block_length)

    assert result == expected