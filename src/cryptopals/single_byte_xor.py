import itertools
from collections import Counter
from typing import List

import cryptopals.format

english_frequencies = {
    "e": 0.12702,
    "t": 0.9056,
    "a": 0.8167,
    "o": 0.7507,
    "i": 0.6966,
    "n": 0.6749,
    "s": 0.6327,
    "h": 0.6094,
    "r": 0.5987,
    "d": 0.4253,
    "l": 0.4025,
    "c": 0.2782,
    "u": 0.2758,
    "m": 0.2406,
    "w": 0.2360,
    "f": 0.2228,
    "g": 0.2015,
    "y": 0.1974,
    "p": 0.1929,
    "b": 0.1492,
    "v": 0.0978,
    "k": 0.0772,
    "j": 0.0153,
    "x": 0.0150,
    "q": 0.0095,
    "z": 0.0074,
}

reference_frequencies = {
    ord(letter): frequency for (letter, frequency) in english_frequencies.items()
}


def distance(plaintext: bytes) -> float:
    lowered_letters = plaintext.lower()
    counts = Counter(lowered_letters)
    lowercase_and_non_printable = itertools.chain(
        range(0x00, ord(" ")), range(ord("a"), ord("z")), range(0x80, 0x100)
    )
    return sum(
        (counts[code] / len(plaintext) - reference_frequencies.get(code, 0.0)) ** 2
        for code in lowercase_and_non_printable
    )


def key_from_int(integer: int) -> bytes:
    return integer.to_bytes(length=1, byteorder="big")


def crack(ciphertext: bytes) -> bytes:
    possible_plaintexts = (
        cryptopals.xor.encrypt(ciphertext, key=key_from_int(integer))
        for integer in range(0, 255)
    )
    return min(possible_plaintexts, key=distance)


def find(ciphertexts: List[bytes]) -> bytes:
    best_plaintexts = (crack(ciphertext) for ciphertext in ciphertexts)
    return min(best_plaintexts, key=distance)
