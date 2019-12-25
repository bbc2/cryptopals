from typing import Optional


def pad(bytes_: bytes, block_length: int) -> bytes:
    pad_length = block_length - (len(bytes_) % block_length)
    return bytes_ + bytes([pad_length] * pad_length)


def unpad(bytes_) -> Optional[bytes]:
    try:
        pad_length = bytes_[-1]
    except IndexError:
        return None
    if len(bytes_) < pad_length:
        return None
    return bytes_[:-pad_length]
