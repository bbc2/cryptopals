import string
from typing import Iterable, Iterator, List, Sequence

import cryptopals.single_byte_xor

bit_masks = [1 << offset for offset in range(8)]


def bits(byte: int) -> Sequence[bool]:
    """Return each bit as a boolean, least-significant first."""
    assert byte < 0x100
    return [bool(byte & mask) for mask in bit_masks]


def hamming_distance(bytes_0: bytes, bytes_1: bytes) -> int:
    """Return Hamming distance between strings of the same length."""
    assert len(bytes_0) == len(bytes_1)
    return sum(sum(bits(byte_0 ^ byte_1)) for (byte_0, byte_1) in zip(bytes_0, bytes_1))


def chunk_bytes(bytes_: bytes, chunk_length: int) -> Iterator[bytes]:
    iteration = 0
    while True:
        chunk = bytes_[iteration * chunk_length : (iteration + 1) * chunk_length]
        if len(chunk) < chunk_length:
            break
        yield chunk
        iteration += 1


def evaluate_length(ciphertext: bytes, length: int) -> float:
    chunks = chunk_bytes(ciphertext, chunk_length=length)
    distances: List[float] = []
    try:
        for _ in range(64):
            bytes_0 = next(chunks)
            bytes_1 = next(chunks)
            distances.append(hamming_distance(bytes_0, bytes_1) / length)
    except StopIteration:
        pass
    return sum(distances) / len(distances)


def guess_key_length(ciphertext: bytes, lengths: Iterable[int]) -> Sequence[int]:
    """Return a likely key length assuming XOR encryption."""
    return sorted(
        lengths, key=lambda length: evaluate_length(ciphertext, length=length)
    )


def transpose(rows: Iterable[bytes]) -> Sequence[bytes]:
    return [bytes(column) for column in zip(*rows)]


def validate(plaintext: bytes):
    return all(byte in string.printable.encode() for byte in plaintext)


def crack(ciphertext: bytes, key_lengths: Iterable[int]) -> bytes:
    guessed_key_lengths = guess_key_length(ciphertext, lengths=key_lengths)
    for key_length in guessed_key_lengths:
        chunks = chunk_bytes(ciphertext, chunk_length=key_length)
        single_byte_keys = [
            cryptopals.single_byte_xor.crack(column) for column in transpose(chunks)
        ]
        key = b"".join(single_byte_keys)
        plaintext = cryptopals.xor.decrypt(ciphertext, key=key)
        if validate(plaintext):
            return key
    assert False
