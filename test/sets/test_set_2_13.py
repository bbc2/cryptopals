import os
from dataclasses import dataclass
from typing import Dict, Optional

import cryptopals.aes
import cryptopals.pkcs7
from cryptopals.params import Params
from cryptopals.util import nth_block

params = Params(bind_char="=", delim_char="&")


def profile_for(email: str) -> str:
    return params.encode({"email": email, "uid": "10", "role": "user"})


@dataclass
class Oracle:
    def __init__(self) -> None:
        self.key = os.urandom(16)

    def encrypt(self, email: bytes) -> bytes:
        plaintext = profile_for(email.decode()).encode()
        padded = cryptopals.pkcs7.pad(plaintext, block_length=16)
        return cryptopals.aes.encrypt_ecb(key=self.key, plaintext=padded)

    def decrypt(self, ciphertext: bytes) -> Optional[Dict[str, str]]:
        padded = cryptopals.aes.decrypt_ecb(key=self.key, ciphertext=ciphertext)
        plaintext = cryptopals.pkcs7.unpad(padded)
        if plaintext is None:
            return None
        return params.decode(plaintext.decode())


def test() -> None:
    # Two emails are used to get two ciphertexts:
    #
    # Ciphertext 0:
    #
    #     email=foooooooooooooooo@example.org&uid=10&role=user____________
    #     0000000000000000111111111111111122222222222222223333333333333333
    #
    # Ciphertext 1:
    #
    #     email=AAAAAAAAAAadmin___________&uid=10&role=user_______________
    #     4444444444444444555555555555555566666666666666667777777777777777
    #
    # The ciphertexts are then combined into an "admin" cookie ciphertext:
    #
    #     0000000000000000111111111111111122222222222222225555555555555555
    #     email=foooooooooooooooo@example.org&uid=10&role=admin___________

    block_length = 16
    oracle = Oracle()
    c_0 = oracle.encrypt(email=b"foooooooooooooooo@example.org")
    padding = bytes([11]) * 11
    c_1 = oracle.encrypt(email=b"AAAAAAAAAAadmin" + padding)
    blocks_0 = nth_block(c_0, block_length=block_length, number=0, count=3)
    blocks_1 = nth_block(c_1, block_length=block_length, number=1)
    cookie = oracle.decrypt(ciphertext=blocks_0 + blocks_1)

    assert cookie == {
        "email": "foooooooooooooooo@example.org",
        "uid": "10",
        "role": "admin",
    }
