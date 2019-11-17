import pytest

import cryptopals.aes
import cryptopals.format


@pytest.mark.parametrize(
    "plaintext,key,expected",
    [
        (
            "f34481ec3cc627bacd5dc3fb08f273e6",
            "00000000000000000000000000000000",
            "0336763e966d92595a567cc9ce537f5e",
        ),
        (
            "f34481ec3cc627bacd5dc3fb08f273e69798c4640bad75c7c3227db910174e72",
            "00000000000000000000000000000000",
            "0336763e966d92595a567cc9ce537f5ea9a1631bf4996954ebc093957b234589",
        ),
        (
            "1b077a6af4b7f98229de786d7516b639",
            "000000000000000000000000000000000000000000000000",
            "275cfc0413d8ccb70513c3859b1d0f72",
        ),
    ],
)
def test_encrypt_ecb(plaintext: str, key: str, expected: str):
    result = cryptopals.aes.encrypt_ecb(
        key=cryptopals.format.hex_to_bytes(key),
        plaintext=cryptopals.format.hex_to_bytes(plaintext),
    )

    assert cryptopals.format.bytes_to_hex(result) == expected


@pytest.mark.parametrize(
    "ciphertext,key,expected",
    [
        (
            "0336763e966d92595a567cc9ce537f5e",
            "00000000000000000000000000000000",
            "f34481ec3cc627bacd5dc3fb08f273e6",
        ),
        (
            "0336763e966d92595a567cc9ce537f5ea9a1631bf4996954ebc093957b234589",
            "00000000000000000000000000000000",
            "f34481ec3cc627bacd5dc3fb08f273e69798c4640bad75c7c3227db910174e72",
        ),
        (
            "275cfc0413d8ccb70513c3859b1d0f72",
            "000000000000000000000000000000000000000000000000",
            "1b077a6af4b7f98229de786d7516b639",
        ),
    ],
)
def test_decrypt_ecb(ciphertext: str, key: str, expected: str):
    result = cryptopals.aes.decrypt_ecb(
        key=cryptopals.format.hex_to_bytes(key),
        ciphertext=cryptopals.format.hex_to_bytes(ciphertext),
    )

    assert cryptopals.format.bytes_to_hex(result) == expected
