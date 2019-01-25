import cryptopals.format
import cryptopals.xor


class TestEncrypt:
    def test_same_lengths(self):
        plaintext = b"\x01"
        key = b"\x11"

        result = cryptopals.xor.encrypt(plaintext, key)

        assert result == b"\x10"

    def test_smaller_key(self):
        plaintext = b"\x01\x10"
        key = b"\x11"

        result = cryptopals.xor.encrypt(plaintext, key)

        assert result == b"\x10\x01"

    def test_bigger_key(self):
        plaintext = b"\x01"
        key = b"\x11\x00"

        result = cryptopals.xor.encrypt(plaintext, key)

        assert result == b"\x10"
