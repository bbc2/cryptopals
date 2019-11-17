from typing import Iterator


def chunk_bytes(bytes_: bytes, chunk_length: int) -> Iterator[bytes]:
    iteration = 0
    while True:
        chunk = bytes_[iteration * chunk_length : (iteration + 1) * chunk_length]
        if len(chunk) < chunk_length:
            break
        yield chunk
        iteration += 1
