"""Read tokens for the tests: a tab's token goes on its `cassette`/`live` socket and on the list."""

from notary_server.read_token import TOKEN_HEADER

TOKEN = "t" * 36
"""A well-formed token (36 characters, like a UUID)."""
OTHER_TOKEN = "o" * 36
HEADERS = {TOKEN_HEADER: TOKEN}
OTHER_HEADERS = {TOKEN_HEADER: OTHER_TOKEN}


def with_token(path: str, token: str = TOKEN) -> str:
    """The path with `token=<token>` added to its query."""
    return f"{path}{'&' if '?' in path else '?'}token={token}"
