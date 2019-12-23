def pad(bytes_: bytes, block_length: int) -> bytes:
    pad_length = block_length - (len(bytes_) % block_length)
    return bytes_ + bytes([pad_length] * pad_length)
