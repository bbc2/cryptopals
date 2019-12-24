import base64
import itertools
import os
from dataclasses import dataclass
from typing import Callable

import cryptopals.aes
import cryptopals.ecb
import cryptopals.pkcs7
import cryptopals.util


def make_encryption_oracle() -> Callable[[bytes], bytes]:
    key = os.urandom(16)

    def encryption_oracle(input_: bytes) -> bytes:
        unknown_string = base64.b64decode(
            """
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK
            """
        )
        plaintext = input_ + unknown_string
        padded = cryptopals.pkcs7.pad(plaintext, block_length=16)
        return cryptopals.aes.encrypt_ecb(key=key, plaintext=padded)

    return encryption_oracle


@dataclass(frozen=True)
class Lengths:
    block: int
    unknown_string: int


def find_lengths(oracle: Callable[[bytes], bytes]) -> Lengths:
    """
    Find the block and unknown string lengths of the encryption oracle.
    """

    # For a 5-byte unknown string:
    #
    # ________ -> 01234PPP
    # A_______ -> A01234PP
    # AA______ -> AA01234P
    # AAA_____ -> AAA01234 PPPPPPPP
    #
    # * Block length: 16 - 8.
    # * String length: 8 - 3.
    #
    # For an 8-byte unknown string:
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
                unknown_string=base_length - input_length,
            )
    assert False


def nth_block(text: bytes, block_length: int, number: int) -> bytes:
    return text[number * block_length : (number + 1) * block_length]


def find_byte(
    oracle: Callable[[bytes], bytes],
    plaintext: bytes,
    target_block: bytes,
    block_number: int,
    block_length: int,
):
    for i in range(256):
        byte = bytes([i])
        ciphertext = oracle(plaintext + byte)
        block = nth_block(ciphertext, block_length=block_length, number=block_number)
        if block == target_block:
            return byte
    assert False


def find_unknown_string(
    oracle: Callable[[bytes], bytes], block_length: int, unknown_string_length: int,
):
    # Suppose the block length is 8 and the unknown string is `0123456789`.  At each step,
    # a byte from the unknown string is discovered.  Each step is denoted with the
    # following format:
    #
    #     p -> f | u -> b
    #
    # where:
    #
    # * `p`: partial plaintext which will have the unknown string appended to.
    # * `f`: full plaintext, the ciphertext of which provides a reference block.
    # * `u`: bruteforced plaintext (max 256 attempts) with unknown byte `x`.
    # * `b`: the newly discovered value of that byte.
    #
    # Here it goes:
    #
    #     AAAAAAA_ ->          AAAAAAA0 ... |          AAAAAAAx -> 0
    #     AAAAAA__ ->          AAAAAA01 ... |          AAAAAA0x -> 1
    #     AAAAA___ ->          AAAAA012 ... |          AAAAA01x -> 2
    #     AAAA____ ->          AAAA0123 ... |          AAAA012x -> 3
    #     AAA_____ ->          AAA01234 ... |          AAA0123x -> 4
    #     AA______ ->          AA012345 ... |          AA01234x -> 5
    #     A_______ ->          A0123456 ... |          A012345x -> 6
    #     ________ ->          01234567 ... |          0123456x -> 7
    #     AAAAAAA_ -> AAAAAAA0 12345678 ... | AAAAAAA0 1234567x -> 8
    #     AAAAAA__ -> AAAAAA01 23456789     | AAAAAA01 2345678x -> 9

    unknown_string = b""

    for step in range(unknown_string_length):
        block_cut_length = (step % block_length) + 1
        partial_plaintext = b"A" * (block_length - block_cut_length)
        ciphertext = oracle(partial_plaintext)
        block_number = step // block_length
        block = nth_block(ciphertext, block_length=block_length, number=block_number)
        unknown_string += find_byte(
            oracle=oracle,
            plaintext=partial_plaintext + unknown_string,
            target_block=block,
            block_number=block_number,
            block_length=block_length,
        )

    return unknown_string


def test():
    encryption_oracle = make_encryption_oracle()
    lengths = find_lengths(encryption_oracle)

    assert lengths == Lengths(block=16, unknown_string=138)

    block_length = lengths.block
    unknown_string_length = lengths.unknown_string
    ciphertext = encryption_oracle(b"A" * (2 * block_length))

    assert cryptopals.ecb.detect(ciphertext, block_length=block_length)

    unknown_string = find_unknown_string(
        oracle=encryption_oracle,
        block_length=block_length,
        unknown_string_length=unknown_string_length,
    )

    assert unknown_string == (
        b"Rollin' in my 5.0\n"
        b"With my rag-top down so my hair can blow\n"
        b"The girlies on standby waving just to say hi\n"
        b"Did you stop? No, I just drove by\n"
    )
