from dataclasses import dataclass


class ParserError(Exception):
    pass


@dataclass(frozen=True)
class Params:
    """
    Encoding and decoding of cookies or URL parameters.
    """

    bind_char: str
    delim_char: str

    def _encode_binding(self, key: str, value: str) -> str:
        assert self.bind_char not in key
        assert self.delim_char not in key
        assert self.bind_char not in value
        assert self.delim_char not in value
        return f"{key}={value}"

    def encode(self, cookie: dict[str, str]) -> str:
        return self.delim_char.join(
            self._encode_binding(key, value) for (key, value) in cookie.items()
        )

    def _decode_binding(self, binding: str) -> tuple[str, str]:
        try:
            (key, value) = binding.split(self.bind_char)
        except ValueError:
            raise ParserError()
        else:
            return (key, value)

    def decode(self, cookie: str) -> dict[str, str] | None:
        if cookie == "":
            return {}
        try:
            return dict(self._decode_binding(binding) for binding in cookie.split(self.delim_char))
        except ParserError:
            return None
