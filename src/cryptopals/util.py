from typing import Iterator


def chunk_bytes(bytes_: bytes, chunk_length: int) -> Iterator[bytes]:
    iteration = 0
    while True:
        chunk = bytes_[iteration * chunk_length : (iteration + 1) * chunk_length]
        if len(chunk) < chunk_length:
            break
        yield chunk
        iteration += 1


def nth_block(text: bytes, block_length: int, number: int, count: int = 1) -> bytes:
    return text[number * block_length : (number + count) * block_length]
