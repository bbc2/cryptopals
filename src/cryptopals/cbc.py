import logging
from dataclasses import dataclass
from typing import Self, Sequence

from typing_extensions import Protocol

from cryptopals.format import bytes_to_hex
from cryptopals.util import nth_block, nth_block_view

logger = logging.getLogger(__name__)


class Oracle(Protocol):
    def check(self, iv: bytes, ciphertext: bytes) -> bool:
        ...


@dataclass(frozen=True)
class Params:
    block_length: int
    iv: bytes
    ciphertext: bytes

    def with_ciphertext(self, ciphertext: bytes) -> "Params":
        return Params(
            block_length=self.block_length,
            iv=self.iv,
            ciphertext=ciphertext,
        )


@dataclass(frozen=True)
class CrackedBlock:
    length: int
    plaintext: Sequence[int]

    @classmethod
    def empty(cls, length: int) -> Self:
        return cls(length=length, plaintext=[])

    def with_one_more_byte(self, byte: int) -> "CrackedBlock":
        return CrackedBlock(length=self.length, plaintext=[byte, *self.plaintext])

    def is_complete(self) -> bool:
        return len(self.plaintext) >= self.length

    def hex(self) -> str:
        return bytes_to_hex(bytes(self.plaintext))


def crack_byte(
    oracle: Oracle,
    params: Params,
    cracked: CrackedBlock,
) -> CrackedBlock:
    """
    Crack one byte of plaintext from a given block.

    The target block is the last block in the ciphertext and the target byte is inferred
    from the amount of plaintext already cracked.
    """

    block_number = len(params.ciphertext) // params.block_length - 1
    logger.debug(
        "Cracking byte (block_number: %s, plaintext (hex): %s)",
        block_number,
        cracked.hex() or "-",
    )

    # Copy the IV or ciphertext to modify.
    iv = bytearray(params.iv)
    ciphertext = bytearray(params.ciphertext)

    # If we target the first block, we must modify the IV.
    if block_number < 1:
        block = memoryview(iv)
    else:
        block = nth_block_view(
            data=ciphertext, block_length=params.block_length, number=-2
        )

    # Byte number of the target plaintext (starting from 0, from the right).
    byte_number = len(cracked.plaintext)
    assert byte_number < params.block_length

    index = -(byte_number + 1)  # Index of the target byte (e.g. last index is `-1`).
    pad = byte_number + 1  # Padding byte eg. at offset 0 we'll pad with 0x01 bytes.

    # Tweak the ciphertext bytes where we know the plaintext to get the desired padding.
    # For example, if we know the last two bytes, we'll want the oracle to get get
    # `0x0303` during decryption, so that we can test the third byte.
    for i, byte in zip(range(index + 1, 0), cracked.plaintext):
        block[i] ^= byte ^ pad

    original_byte = block[index]  # Save the original byte before modifying it.

    # Change the target byte (with our `delta` byte) until the padding is accepted.
    for delta in range(256):
        block[index] = original_byte ^ delta

        if oracle.check(iv=iv, ciphertext=ciphertext):
            if pad == 1:
                # Resolve a potential ambiguity by modifying the byte of the left and
                # checking again with the oracle (e.g. we turned `0x0200` into `0x0202`,
                # which is valid padding but not the one we want; we want `0x0201`).
                block[index - 1] ^= 1

                if not oracle.check(iv=iv, ciphertext=ciphertext):
                    continue

            break

    # We changed the last byte ciphertext and it worked so we assume it turned the padding
    # into a `0x01` (or whatever we wanted based on the offset in the block). The
    # corresponding byte of plaintext can be obtained with a XOR.
    return cracked.with_one_more_byte(pad ^ delta)


def crack_block(oracle: Oracle, params: Params, block_number: int) -> bytes:
    """
    Crack a block and return the corresponding plaintext.
    """

    # Truncate the ciphertext so that the target block is the last block.
    params = params.with_ciphertext(
        nth_block(
            data=params.ciphertext,
            block_length=params.block_length,
            number=0,
            count=block_number + 1,
        )
    )

    # First byte (from the right) -> None:
    #
    # Modify the last byte of the block (identified by `*` on the `xor` line) until
    # padding is accepted. Then we have the delta to infer the last byte of plaintext.
    #
    #     plaintext:  ________________ ________________ _______________p
    #     ciphertext: ________________ _______________c ________________
    #     xor:                                        d
    #     to unpad:   ________________ ???????????????? _______________*
    #
    # Mathematically, we have the following:
    #
    # - From the decryption rules: `p = c ^ D`
    # - From the padding oracle: `1 = c ^ d ^ D`
    #
    # Therefore, `p = d ^ 1`.
    #
    # Second byte (from the right) -> None:
    #
    # Modify the last byte of the block to set it to `2` based on the plaintext discovered
    # in the last step (`d = p ^ 2`). Modify the byte on the left (identified by `*` on
    # the `xor` line) until padding is accepted, then use the new delta `e` to infer the
    # corresponding byte of plaintext (`p = `e ^ 2`).
    #
    #     plaintext:  ________________ ________________ _______________p
    #     ciphertext: ________________ ________________ ________________
    #     xor:                                       ed
    #     to unpad:   ________________ ???????????????? ______________*2
    #
    # And so on until we have a whole block of plaintext.

    cracked = CrackedBlock.empty(length=params.block_length)

    while not cracked.is_complete():
        cracked = crack_byte(
            oracle=oracle,
            params=params,
            cracked=cracked,
        )

    return bytes(cracked.plaintext)


def crack(oracle: Oracle, params: Params) -> bytes:
    """
    Crack CBC using a padding oracle.

    This returns the plaintext corresponding to the ciphertext provided as input in the
    `params` argument.
    """

    block_count = len(params.ciphertext) // params.block_length

    cracked_blocks = [
        crack_block(oracle=oracle, params=params, block_number=block_number)
        for block_number in range(block_count)
    ]

    return b"".join(cracked_blocks)
