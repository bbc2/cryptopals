import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import pytest

import cryptopals.aes
import cryptopals.pkcs7
from cryptopals.util import nth_block


class ParserError(Exception):
    pass


def decode_binding(binding: str) -> Tuple[str, str]:
    try:
        (key, value) = binding.split("=")
    except ValueError:
        raise ParserError()
    else:
        return (key, value)


def decode_cookie(cookie: str) -> Optional[Dict[str, str]]:
    if cookie == "":
        return {}
    try:
        return dict(decode_binding(binding) for binding in cookie.split("&"))
    except ParserError:
        return None


@pytest.mark.parametrize(
    "cookie,expected",
    [
        ("", {}),
        ("a=b", {"a": "b"}),
        ("a=b&c=d", {"a": "b", "c": "d"}),
        ("a=b&a=c", {"a": "c"}),
        ("a", None),
        ("&", None),
        ("a=b&c", None),
    ],
)
def test_decode_cookie(cookie, expected):
    result = decode_cookie(cookie)

    assert result == expected


def encode_binding(key: str, value: str) -> str:
    assert "&" not in key
    assert "=" not in key
    assert "&" not in value
    assert "=" not in value
    return f"{key}={value}"


def encode_cookie(cookie: Dict[str, str]) -> str:
    return "&".join(encode_binding(key, value) for (key, value) in cookie.items())


def profile_for(email: str) -> str:
    return encode_cookie({"email": email, "uid": "10", "role": "user"})


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
        return decode_cookie(plaintext.decode())


def test():
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
