import base64
import binascii
from typing import AnyStr


def bytes_to_hex(bytes_: bytes) -> str:
    return binascii.hexlify(bytes_).decode("ascii")


def hex_to_bytes(string: AnyStr) -> bytes:
    return binascii.unhexlify(string)


def hex_to_base64(string: str) -> str:
    bytes_ = hex_to_bytes(string)
    return base64.b64encode(bytes_).decode("ascii")
