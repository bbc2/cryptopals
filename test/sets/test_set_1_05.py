import cryptopals.format


class TestEncrypt:
    def test_vector(self) -> None:
        plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

        result = cryptopals.xor.encrypt(plaintext, b"ICE")

        assert cryptopals.format.bytes_to_hex(result) == (
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263"
            "24272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028"
            "3165286326302e27282f"
        )
