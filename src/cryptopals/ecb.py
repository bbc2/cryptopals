from collections import Counter

import cryptopals.util


def detect(ciphertext: bytes, block_length: int) -> bool:
    """Detect if a ciphertext was obtained with ECB mode."""
    blocks = cryptopals.util.chunk_bytes(ciphertext, chunk_length=block_length)
    counts = Counter(blocks)
    return any(count > 1 for (block, count) in counts.items())
