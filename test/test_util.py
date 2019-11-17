from typing import Sequence

import pytest

import cryptopals.util


@pytest.mark.parametrize(
    "input_,chunk_length,expected",
    [("", 1, []), ("a", 1, ["a"]), ("a", 2, []), ("ab", 1, ["a", "b"])],
)
def test_chunk_bytes(input_: bytes, chunk_length: int, expected: Sequence[bytes]):
    result = cryptopals.util.chunk_bytes(input_, chunk_length=chunk_length)

    assert list(result) == expected
