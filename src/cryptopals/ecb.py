import itertools
from collections import Counter
from dataclasses import dataclass
from typing import Callable

import cryptopals.util


def detect(ciphertext: bytes, block_length: int) -> bool:
    """Detect if a ciphertext was obtained with ECB mode."""
    blocks = cryptopals.util.chunk_bytes(ciphertext, chunk_length=block_length)
    counts = Counter(blocks)
    return any(count > 1 for (block, count) in counts.items())


@dataclass(frozen=True)
class Lengths:
    block: int
    extra_byte_count: int


def find_lengths(oracle: Callable[[bytes], bytes]) -> Lengths:
    """
    Find the block and fixed number of added bytes of an encryption oracle.

    Requirements:

    - The oracle uses a block cipher (e.g. AES CBC).
    - The number of bytes added is always the same. It doesn't matter if the bytes are
      different.
    """

    # For a 5-byte fixed string:
    #
    # ________ -> 01234PPP
    # A_______ -> A01234PP
    # AA______ -> AA01234P
    # AAA_____ -> AAA01234 PPPPPPPP
    #
    # * Block length: 16 - 8.
    # * String length: 8 - 3.
    #
    # For an 8-byte fixed string:
    #
    # ________ -> 01234567 PPPPPPPP
    # A_______ -> A0123456 7PPPPPPP
    # AA______ -> AA012345 67PPPPPP
    # AAA_____ -> AAA01234 567PPPPP
    # AAAA____ -> AAAA0123 4567PPPP
    # AAAAA___ -> AAAAA012 34567PPP
    # AAAAAA__ -> AAAAAA01 234567PP
    # AAAAAAA_ -> AAAAAAA0 1234567P
    # AAAAAAAA -> AAAAAAAA 01234567 PPPPPPPP
    #
    # * Block length: 24 - 16.
    # * String length: 16 - 8.

    base_length = len(oracle(b""))
    for input_length in itertools.count(start=1):
        ciphertext_length = len(oracle(b"A" * input_length))
        if ciphertext_length != base_length:
            return Lengths(
                block=ciphertext_length - base_length,
                extra_byte_count=base_length - input_length,
            )
    assert False


def find_byte(
    oracle: Callable[[bytes], bytes],
    plaintext: bytes,
    target_block: bytes,
    block_number: int,
    block_length: int,
) -> bytes:
    """
    Brute force the last byte of a block of ciphertext.

    The length of the plaintext must be 1 less than a multiple of the block length, so
    that the added byte will be at the end of a block.
    """

    # For every possible x the following is encrypted with the oracle:
    #
    #     ... PPPPPPPx ... -> ... CCCCCCCC ...
    #
    # The algorithm stops when "CCCCCCCC" is the target block.

    for i in range(256):
        byte = bytes([i])
        ciphertext = oracle(plaintext + byte)
        block = cryptopals.util.nth_block(
            ciphertext,
            block_length=block_length,
            number=block_number,
        )
        if block == target_block:
            return byte

    assert False
