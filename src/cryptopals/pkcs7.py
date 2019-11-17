def pad(bytes_: bytes, length: int):
    bytes_length = len(bytes_)
    pad_length = length - bytes_length
    assert 0 <= pad_length < 0x100
    return bytes_ + int.to_bytes(pad_length, length=1, byteorder="big") * pad_length
