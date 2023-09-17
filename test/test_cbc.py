from dataclasses import dataclass

import pytest

import cryptopals.aes
import cryptopals.cbc
import cryptopals.pkcs7


@dataclass(frozen=True)
class Oracle:
    key: bytes

    def check(self, iv: bytes, ciphertext: bytes) -> bool:
        padded = cryptopals.aes.decrypt_cbc(key=self.key, iv=iv, ciphertext=ciphertext)
        plaintext = cryptopals.pkcs7.unpad(padded)
        return plaintext is not None


@pytest.mark.parametrize(
    "plaintext",
    [
        b"abcdefghijklmnop",
        b"abcdefghijklmnopqrstuvwxyzABCDEF",
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
    ],
)
def test_crack(plaintext: bytes) -> None:
    block_length = 16
    key = b"\x00" * block_length
    iv = b"\x01" * block_length
    ciphertext = cryptopals.aes.encrypt_cbc(key=key, plaintext=plaintext, iv=iv)
    oracle = Oracle(key=key)

    result = cryptopals.cbc.crack(
        oracle=oracle,
        params=cryptopals.cbc.Params(
            block_length=block_length,
            iv=iv,
            ciphertext=ciphertext,
        ),
    )

    assert result == plaintext
