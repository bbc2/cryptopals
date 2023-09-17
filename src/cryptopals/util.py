from typing import Iterator


def chunk_bytes(bytes_: bytes, chunk_length: int) -> Iterator[bytes]:
    iteration = 0
    while True:
        chunk = bytes_[iteration * chunk_length : (iteration + 1) * chunk_length]
        if len(chunk) < chunk_length:
            break
        yield chunk
        iteration += 1


def nth_block(
    data: bytes, block_length: int, number: int, count: int | None = 1
) -> bytes:
    """
    Return the nth block in a sequence of bytes.

    If `count` is `None`, this returns all the blocks starting with the one at the
    specified number.
    """
    if count is None:
        return data[number * block_length :]
    else:
        return data[number * block_length : (number + count) * block_length]


def nth_block_view(
    data: bytes | bytearray, block_length: int, number: int, count: int | None = 1
) -> memoryview:
    """
    Return a memory view of the nth block in a sequence of bytes.

    If `count` is `None`, this returns all the blocks starting with the one at the
    specified number.
    """
    if count is None:
        return memoryview(data)[number * block_length :]
    else:
        return memoryview(data)[number * block_length : (number + count) * block_length]
