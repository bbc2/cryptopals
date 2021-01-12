import pytest

import cryptopals.pkcs7


@pytest.mark.parametrize(
    "padded,expected",
    [
        (b"ICE ICE BABY\x04\x04\x04\x04", b"ICE ICE BABY"),
        (b"ICE ICE BABY\x05\x05\x05\x05", None),
        (b"ICE ICE BABY\x01\x02\x03\x04", None),
    ],
)
def test_unpad(padded, expected):
    result = cryptopals.pkcs7.unpad(padded)

    assert result == expected
