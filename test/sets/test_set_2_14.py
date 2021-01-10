import base64
import os
import random
from typing import Callable

import cryptopals.aes
import cryptopals.ecb
import cryptopals.pkcs7
from cryptopals.util import chunk_bytes


def make_encryption_oracle() -> Callable[[bytes], bytes]:
    key = os.urandom(16)

    # Random but fixed prefix
    system_random = random.SystemRandom()
    prefix_length = system_random.randrange(64)
    prefix = os.urandom(prefix_length)

    def encryption_oracle(input_: bytes) -> bytes:
        unknown_string = base64.b64decode(
            """
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK
            """
        )
        plaintext = prefix + input_ + unknown_string
        padded = cryptopals.pkcs7.pad(plaintext, block_length=16)
        return cryptopals.aes.encrypt_ecb(key=key, plaintext=padded)

    return encryption_oracle


def find_repeated_block(text: bytes, block_length: int):
    previous_chunk = None

    for chunk in chunk_bytes(text, block_length):
        if chunk == previous_chunk:
            return chunk

        previous_chunk = chunk

    assert False


def find_prefix_length(oracle: Callable[[bytes], bytes], block_length: int) -> int:
    # For a 5-byte random prefix:
    #
    # 0 more "Z" bytes -> PPPPPAAA AAAAA___ ... -> ________ ________ ...
    # 1 more "Z" bytes -> PPPPPZAA AAAAAA__ ... -> ________ ________ ...
    # 2 more "Z" bytes -> PPPPPZZA AAAAAAA_ ... -> ________ ________ ...
    # 3 more "Z" bytes -> PPPPPZZZ AAAAAAAA ... -> ________ aaaaaaaa ...
    #
    # Offset of known block: 8
    # Prefix length: 8 - 3
    #
    # For a 8-byte random prefix:
    #
    # 0 more "Z" bytes -> PPPPPPPP AAAAAAAA ... -> ________ aaaaaaaa ...
    #
    # Offset of known block: 8
    # Prefix length: 8 - 0
    #
    # When enough "Z" bytes are provided, a full "AAAAAAAA" block is encrypted, which we
    # can recognize in the output, and which gives us the length of the unknown prefix.
    # We need to also test it with a "BBBBBBBB" block to ensure we're not confused by some
    # "A" bytes present in the unknown string.

    a_block = block_length * b"A"
    b_block = block_length * b"B"
    a_block_ciphertext = find_repeated_block(
        text=oracle(3 * a_block),
        block_length=block_length,
    )
    b_block_ciphertext = find_repeated_block(
        text=oracle(3 * b_block),
        block_length=block_length,
    )

    for count in range(block_length):
        ciphertext_a = oracle(count * b"Z" + a_block)
        ciphertext_b = oracle(count * b"Z" + b_block)

        try:
            offset_a = ciphertext_a.index(a_block_ciphertext)
            offset_b = ciphertext_b.index(b_block_ciphertext)
        except ValueError:
            continue

        if offset_a == offset_b:
            return offset_a - count

    assert False


def test():
    encryption_oracle = make_encryption_oracle()
    lengths = cryptopals.ecb.find_lengths(encryption_oracle)

    assert lengths.block == 16

    prefix_length = find_prefix_length(
        oracle=encryption_oracle,
        block_length=lengths.block,
    )
    unknown_string_length = lengths.extra_byte_count - prefix_length

    assert unknown_string_length == 138
