import itertools
from typing import Iterable


def add(bytes_0: Iterable[int], bytes_1: Iterable[int]) -> bytes:
    return bytes(byte_0 ^ byte_1 for (byte_0, byte_1) in zip(bytes_0, bytes_1))


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    return add(plaintext, itertools.cycle(key))


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return encrypt(ciphertext, key=key)
