import itertools
from typing import Iterator

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import cryptopals.util
import cryptopals.xor


def ecb_cipher(key: bytes) -> Cipher[modes.ECB]:
    backend = default_backend()
    return Cipher(algorithms.AES(key), modes.ECB(), backend=backend)


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    cipher = ecb_cipher(key)
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    cipher = ecb_cipher(key)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    block_size = 16
    assert len(plaintext) % block_size == 0
    assert len(iv) % block_size == 0

    ciphertext_block = iv
    ciphertext = b""
    plaintext_blocks = cryptopals.util.chunk_bytes(plaintext, chunk_length=block_size)

    for plaintext_block in plaintext_blocks:
        ciphertext_block = encrypt_ecb(
            key=key,
            plaintext=cryptopals.xor.add(plaintext_block, ciphertext_block),
        )
        ciphertext += ciphertext_block

    return ciphertext


def decrypt_cbc(key: bytes, ciphertext: bytes | bytearray, iv: bytes | bytearray) -> bytes:
    block_size = 16
    assert len(ciphertext) % block_size == 0
    assert len(iv) % block_size == 0

    previous_block = iv
    plaintext = b""
    ciphertext_blocks = cryptopals.util.chunk_bytes(ciphertext, chunk_length=block_size)

    for ciphertext_block in ciphertext_blocks:
        plaintext += cryptopals.xor.add(
            decrypt_ecb(
                key=key,
                ciphertext=ciphertext_block,
            ),
            previous_block,
        )
        previous_block = ciphertext_block

    return plaintext


def gen_ctr_blocks(key: bytes, nonce: bytes) -> Iterator[bytes]:
    counter = 0
    while True:
        data = nonce + counter.to_bytes(8, "little")
        yield encrypt_ecb(key=key, plaintext=data)
        counter += 1


def encrypt_ctr(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    assert len(key) == 16
    assert len(nonce) == 8

    block_length = 16
    length = len(plaintext)
    count = length // block_length
    remainder = length % block_length
    needed = count + 1 if remainder else count
    ctr_blocks = itertools.islice(gen_ctr_blocks(key=key, nonce=nonce), needed)
    ctr_stream = b"".join(ctr_blocks)
    return cryptopals.xor.encrypt(plaintext=plaintext, key=ctr_stream)


def decrypt_ctr(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    return encrypt_ctr(key=key, plaintext=ciphertext, nonce=nonce)
