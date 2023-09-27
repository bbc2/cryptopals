import cryptopals.format


def test() -> None:
    string = (
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f"
        "69736f6e6f7573206d757368726f6f6d"
    )

    result = cryptopals.format.hex_to_base64(string)

    assert result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
