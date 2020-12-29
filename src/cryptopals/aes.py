from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import cryptopals.util
import cryptopals.xor


def ecb_cipher(key: bytes) -> Cipher:
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


def decrypt_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
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
