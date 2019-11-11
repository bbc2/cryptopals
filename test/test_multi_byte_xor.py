from typing import Sequence

import pytest

import cryptopals.multi_byte_xor


@pytest.mark.parametrize(
    "input_,expected",
    [
        (0, [False, False, False, False, False, False, False, False]),
        (1, [True, False, False, False, False, False, False, False]),
        (0xFF, [True, True, True, True, True, True, True, True]),
    ],
)
def test_bits(input_: int, expected: Sequence[bool]):
    result = cryptopals.multi_byte_xor.bits(input_)

    assert result == expected


def test_guess_key_length():
    ciphertext = b"abc" * 3

    result = cryptopals.multi_byte_xor.guess_key_length(
        ciphertext=ciphertext, lengths=range(1, 5),
    )

    assert result[0] == 3


@pytest.mark.parametrize(
    "input_,expected",
    [
        ([], []),
        ([b"a"], [b"a"]),
        ([b"ab", b"c"], [b"ac"]),
        ([b"ab", b"cd"], [b"ac", b"bd"]),
    ],
)
def test_transpose(input_: Sequence[bytes], expected: Sequence[bytes]):
    result = cryptopals.multi_byte_xor.transpose(input_)

    assert list(result) == expected


@pytest.mark.parametrize(
    "input_,chunk_length,expected",
    [("", 1, []), ("a", 1, ["a"]), ("a", 2, []), ("ab", 1, ["a", "b"])],
)
def test_chunk_bytes(input_: bytes, chunk_length: int, expected: Sequence[bytes]):
    result = cryptopals.multi_byte_xor.chunk_bytes(input_, chunk_length=chunk_length)

    assert list(result) == expected
