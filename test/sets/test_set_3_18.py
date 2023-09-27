import base64

import cryptopals.aes
import cryptopals.format


def test_main() -> None:
    ciphertext_base64 = (
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    ciphertext = base64.b64decode(ciphertext_base64)

    plaintext = cryptopals.aes.decrypt_ctr(
        key=b"YELLOW SUBMARINE",
        ciphertext=ciphertext,
        nonce=b"\x00\x00\x00\x00\x00\x00\x00\x00",
    )

    assert len(plaintext) == len(ciphertext)
    assert plaintext == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


def test_other() -> None:
    key = b"\x01" * 16
    nonce = b"\x02" * 8
    plaintext = b"abcdefghijklmnop"

    ciphertext = cryptopals.aes.encrypt_ctr(key=key, plaintext=plaintext, nonce=nonce)
    result = cryptopals.aes.decrypt_ctr(key=key, ciphertext=ciphertext, nonce=nonce)

    assert len(plaintext) == len(ciphertext) == len(result)
    assert result == plaintext
