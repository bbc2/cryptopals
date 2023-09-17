import base64
import binascii
import string
from typing import AnyStr

from . import util

GOOD_ASCII = string.ascii_letters + string.digits + string.punctuation + " "
BAD_ASCII = bytes(frozenset(range(256)) - frozenset(ord(s) for s in GOOD_ASCII))


def bytes_to_hex(bytes_: bytes) -> str:
    return binascii.hexlify(bytes_).decode("ascii")


def bytes_to_ascii(bytes_: bytes) -> str:
    """
    Convert bytes to an ASCII string (without newlines or other non-printable characters).
    """

    return bytes_.translate(None, delete=BAD_ASCII).decode("ascii")


def hex_to_bytes(string: AnyStr) -> bytes:
    return binascii.unhexlify(string)


def hex_to_base64(string: str) -> str:
    bytes_ = hex_to_bytes(string)
    return base64.b64encode(bytes_).decode("ascii")


def prettify_blocks(bytes_: bytes, block_length: int) -> str:
    blocks: list[str] = []

    for chunk in util.chunk_bytes(bytes_, chunk_length=block_length):
        blocks.append(bytes_to_hex(chunk))

    return " ".join(blocks)
