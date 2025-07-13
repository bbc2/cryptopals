import cryptopals.format
import cryptopals.single_byte_xor


def test() -> None:
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    input_ = cryptopals.format.hex_to_bytes(ciphertext)

    result = cryptopals.single_byte_xor.crack(input_)

    assert result == b"X"
    assert cryptopals.xor.decrypt(input_, key=result) == b"Cooking MC's like a pound of bacon"
