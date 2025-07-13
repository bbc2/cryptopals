import base64
import logging
import os
import secrets
from dataclasses import dataclass

import pytest

import cryptopals.aes
import cryptopals.cbc
import cryptopals.pkcs7
from cryptopals.format import bytes_to_ascii, prettify_blocks

logger = logging.getLogger()


@dataclass(frozen=True)
class Encrypted:
    iv: bytes
    ciphertext: bytes


@dataclass
class Oracle:
    STRINGS = (
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    )

    def __init__(self) -> None:
        self.key = os.urandom(16)

    def encrypt(self) -> Encrypted:
        # The randomness is a bit useless here. It's kind of a waste of CPU resources.
        plaintext = base64.b64decode(secrets.choice(self.STRINGS))
        padded = cryptopals.pkcs7.pad(plaintext, block_length=16)
        iv = os.urandom(16)
        return Encrypted(
            iv=iv,
            ciphertext=cryptopals.aes.encrypt_cbc(key=self.key, plaintext=padded, iv=iv),
        )

    def check(self, iv: bytes | bytearray, ciphertext: bytes | bytearray) -> bool:
        padded = cryptopals.aes.decrypt_cbc(key=self.key, iv=iv, ciphertext=ciphertext)
        plaintext = cryptopals.pkcs7.unpad(padded)
        return plaintext is not None


@pytest.mark.repeat(20)
def test() -> None:
    oracle = Oracle()
    block_length = 16

    encrypted = oracle.encrypt()

    assert oracle.check(iv=encrypted.iv, ciphertext=encrypted.ciphertext) is True

    padded = cryptopals.cbc.crack(
        oracle=oracle,
        params=cryptopals.cbc.Params(
            block_length=block_length,
            iv=encrypted.iv,
            ciphertext=encrypted.ciphertext,
        ),
    )

    plaintext = cryptopals.pkcs7.unpad(padded)

    assert plaintext is not None

    logger.info("Cracked plaintext: %s", prettify_blocks(plaintext, block_length))
    logger.info("Cracked plaintext (ASCII): %s", bytes_to_ascii(plaintext))

    assert plaintext in (
        b"000000Now that the party is jumping",
        b"000001With the bass kicked in and the Vega's are pumpin'",
        b"000002Quick to the point, to the point, no faking",
        b"000003Cooking MC's like a pound of bacon",
        b"000004Burning 'em, if you ain't quick and nimble",
        b"000005I go crazy when I hear a cymbal",
        b"000006And a high hat with a souped up tempo",
        b"000007I'm on a roll, it's time to go solo",
        b"000008ollin' in my five point oh",
        b"000009ith my rag-top down so my hair can blow",
    )
