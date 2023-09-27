import pytest

from cryptopals.params import Params


def test_encode_ok() -> None:
    params = Params(bind_char="=", delim_char="&")

    result = params.encode({"a": "x", "b": "y"})

    assert result == "a=x&b=y"


def test_encode_forbidden_character_in_key() -> None:
    params = Params(bind_char="=", delim_char="&")

    with pytest.raises(AssertionError):
        params.encode({"=": "x"})


def test_encode_forbidden_character_in_value() -> None:
    params = Params(bind_char="=", delim_char="&")

    with pytest.raises(AssertionError):
        params.encode({"a": "="})


@pytest.mark.parametrize(
    "cookie,expected",
    [
        ("", {}),
        ("a=b", {"a": "b"}),
        ("a=b&c=d", {"a": "b", "c": "d"}),
        ("a=b&a=c", {"a": "c"}),
        ("a", None),
        ("&", None),
        ("a=b&c", None),
    ],
)
def test_decode(cookie: str, expected: dict[str, str] | None) -> None:
    params = Params(bind_char="=", delim_char="&")

    result = params.decode(cookie)

    assert result == expected
