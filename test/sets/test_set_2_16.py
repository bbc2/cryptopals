import os
import secrets
import string
from dataclasses import dataclass

import cryptopals.aes
import cryptopals.ecb
import cryptopals.pkcs7
from cryptopals.params import Params
from cryptopals.util import nth_block

params = Params(bind_char="=", delim_char=";")


def repr_byte(byte: int) -> str:
    b = chr(byte)
    if len(b) > 1:
        return ". "
    else:
        return f"{b} "


def encode_userdata(userdata: str) -> str:
    return params.encode(
        {
            "comment1": "cooking%20MCs",
            "userdata": userdata,
            "comment2": "%20like%20a%20pound%20of%20bacon",
        }
    )


@dataclass(frozen=True)
class Encoded:
    iv: bytes
    ciphertext: bytes


@dataclass
class Oracle:
    def __init__(self) -> None:
        self.key = os.urandom(16)

    def encode(self, userdata: bytes) -> Encoded:
        plaintext = encode_userdata(userdata.decode()).encode()
        padded = cryptopals.pkcs7.pad(plaintext, block_length=16)
        iv = os.urandom(16)

        return Encoded(
            iv=iv,
            ciphertext=cryptopals.aes.encrypt_cbc(
                key=self.key, plaintext=padded, iv=iv
            ),
        )

    def validate(self, iv: bytes, ciphertext: bytes) -> bool:
        padded = cryptopals.aes.decrypt_cbc(key=self.key, ciphertext=ciphertext, iv=iv)
        plaintext = cryptopals.pkcs7.unpad(padded)

        if plaintext is None:
            return False

        try:
            data = params.decode(plaintext.decode())
        except UnicodeDecodeError:
            return False

        if data is None:
            return False

        return data.get("admin") == "true"


def random_letters(length: int) -> str:
    return "".join(secrets.choice(string.ascii_letters) for _ in range(length))


def test() -> None:
    # Errors in CBC decryption don't propagate because each block of plaintext is obtained
    # from only two blocks of ciphertext: the block at the same position and the one
    # before it.
    #
    # We want to get `"admin": "true"` in the decoded cookie. We can't use the string
    # `";admin=true"` as user data because it would be rejected. We thus need to input
    # something else and manipulate the ciphertext so that it is decrypted into a
    # plaintext containing `;admin=true`.
    #
    #     plaintext:  comment1=foo;use rdata=__________ 9admin9true;comm ent2=bar
    #     ciphertext: xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx
    #     xor:                         2     4
    #     plaintext:  comment1=foo;use ???????????????? ;admin=true;comm ent2=bar
    #
    # The XOR applied to the second block has two effects on the decrypted value:
    #
    # - The block at the same position is scrambled. As far as we're concerned, it's
    #   random.
    # - The block at the next position is XOR-ed with 2 and 4 at the corresponding byte
    #   offsets:
    #   - "9" ^ 2 = ";"
    #   - "9" ^ 4 = "="
    #
    # The `_` characters above represent the padding applied to the userdata so that
    # `9admin9true` lands at the beginning of a block. This is not strictly necessary but
    # it ensures we scramble only one block.
    #
    # The length of that padding is inferred from the challenge (we know the prefix is
    # 32 bytes long). If we didn't know it, we would need to try with several lengths
    # until validation worked. I haven't found anything better for now.

    oracle = Oracle()
    lengths = cryptopals.ecb.find_lengths(lambda c: oracle.encode(c).ciphertext)

    assert lengths == cryptopals.ecb.Lengths(block=16, extra_byte_count=74)

    block_length = lengths.block
    prefix_length = 32  # inferred from the challenge propmt
    length_to_next_block = -prefix_length % block_length
    userdata = (b"_" * length_to_next_block) + b"9admin9true"
    number = (prefix_length - 1) // block_length  # second block in the example

    while True:
        encryption = oracle.encode(userdata)
        cookie = encryption.ciphertext

        block = bytearray(nth_block(cookie, block_length=block_length, number=number))
        block[0] ^= 2  # In the decrypted plaintext: `9` → `;`.
        block[6] ^= 4  # In the decrypted plaintext: `9` → `=`.

        start = nth_block(cookie, block_length=block_length, number=0, count=number)
        end = nth_block(
            cookie, block_length=block_length, number=number + 1, count=None
        )
        new_cookie = start + block + end
        result = oracle.validate(iv=encryption.iv, ciphertext=new_cookie)

        if result:
            break

    assert result is True
