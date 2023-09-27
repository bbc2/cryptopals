from typing import Sequence

import pytest

import cryptopals.util


@pytest.mark.parametrize(
    "input_,chunk_length,expected",
    [("", 1, []), ("a", 1, ["a"]), ("a", 2, []), ("ab", 1, ["a", "b"])],
)
def test_chunk_bytes(
    input_: bytes, chunk_length: int, expected: Sequence[bytes]
) -> None:
    result = cryptopals.util.chunk_bytes(input_, chunk_length=chunk_length)

    assert list(result) == expected


@pytest.mark.parametrize(
    "text,number,count,expected",
    [
        (b"0a1b2c3d", 0, 1, b"0a"),
        (b"0a1b2c3d", 1, 1, b"1b"),
        (b"0a1b2c3d", 1, 2, b"1b2c"),
        (b"0a1b2c3d", 3, 2, b"3d"),
        (b"0a1b2c3d", 1, None, b"1b2c3d"),
    ],
)
def test_nth_block(
    text: bytes, number: int, count: int | None, expected: bytes
) -> None:
    result = cryptopals.util.nth_block(text, block_length=2, number=number, count=count)

    assert result == expected
