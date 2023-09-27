import os
import random
from dataclasses import dataclass

import pytest

import cryptopals.aes
import cryptopals.ecb
import cryptopals.pkcs7
import cryptopals.util


@dataclass
class Result:
    ciphertext: bytes
    is_ecb: bool


def encryption_oracle(input_: bytes) -> Result:
    before = os.urandom(random.randint(5, 10))
    after = os.urandom(random.randint(5, 10))
    plaintext = before + input_ + after
    padded = cryptopals.pkcs7.pad(plaintext, block_length=16)
    key = os.urandom(16)
    iv = os.urandom(16)
    is_ecb = random.choice([True, False])

    if is_ecb:
        ciphertext = cryptopals.aes.encrypt_ecb(key=key, plaintext=padded)
    else:
        ciphertext = cryptopals.aes.encrypt_cbc(key=key, plaintext=padded, iv=iv)

    return Result(
        ciphertext=ciphertext,
        is_ecb=is_ecb,
    )


@pytest.mark.repeat(100)
def test() -> None:
    # ECB can be detected because if two input blocks are identical, the two output blocks
    # will also be identical.  Therefore, we need two input blocks to be the same in the
    # input and we'll look for identical blocks in the output.

    # The problem is that the oracle will prepend and append some bytes to the input
    # before encrypting it.  As a result, if we were using e.g. 32 null bytes, they
    # wouldn't result in two identical input blocks (the first block would have some of
    # the random prefix, the second block would be all null bytes, and the last block
    # would have some of the random suffix).  So we need at least 3 blocks worth of null
    # bytes, to ensure that two input blocks will be all null bytes.
    block_length = 16
    input_ = b"\x00" * (3 * block_length)
    result = encryption_oracle(input_)

    assert (
        cryptopals.ecb.detect(ciphertext=result.ciphertext, block_length=block_length)
        == result.is_ecb
    )
