import cryptopals.format


def test() -> None:
    string_0 = "1c0111001f010100061a024b53535009181c"
    string_1 = "686974207468652062756c6c277320657965"
    input_0 = cryptopals.format.hex_to_bytes(string_0)
    input_1 = cryptopals.format.hex_to_bytes(string_1)

    result = cryptopals.xor.encrypt(input_0, input_1)

    assert (
        cryptopals.format.bytes_to_hex(result) == "746865206b696420646f6e277420706c6179"
    )
