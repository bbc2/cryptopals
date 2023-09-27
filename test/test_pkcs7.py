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
def test_pad_mod(bytes_: bytes, block_length: int, expected: bytes) -> None:
    result = cryptopals.pkcs7.pad(bytes_=bytes_, block_length=block_length)

    assert result == expected


@pytest.mark.parametrize(
    "padded,expected",
    [
        (b"\x01", b""),
        (b"1\x01", b"1"),
        (b"1\x02\x02", b"1"),
        (b"", None),
        (b"\x02", None),
        (b"1\x03\x02", None),
        (b"1\x02\x03", None),
    ],
)
def test_unpad(padded: bytes, expected: bytes | None) -> None:
    result = cryptopals.pkcs7.unpad(padded)

    assert result == expected
