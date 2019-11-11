import itertools


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    return bytes(
        byte_0 ^ byte_1 for (byte_0, byte_1) in zip(plaintext, itertools.cycle(key))
    )


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return encrypt(ciphertext, key=key)
