from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
