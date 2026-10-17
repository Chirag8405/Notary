"""The read token of an endorsement list (#235).

A tab makes a random token and presents it on its `cassette` and `live` sockets and on
`GET /runs/{run_id}/endorsements`. The server keeps only `HMAC-SHA256(server_key, run_id NUL token)`
for the socket and compares it in constant time. The token lets a client READ the cards of the
sockets that hold the same token; it is never an answer or cancel credential (those need the
socket-held owner secret, see `notary_server.endorsement`).
"""

import hashlib
import hmac
import re

MIN_TOKEN_CHARS = 32
MAX_TOKEN_CHARS = 128
TOKEN_QUERY_PARAM = "token"
TOKEN_HEADER = "X-Notary-Token"

_TOKEN = re.compile(rf"[A-Za-z0-9_-]{{{MIN_TOKEN_CHARS},{MAX_TOKEN_CHARS}}}")


def valid_token(token: str | None) -> bool:
    """A token of 32 to 128 characters of `[A-Za-z0-9_-]` (a UUID has 36)."""
    return token is not None and _TOKEN.fullmatch(token) is not None


def read_key(server_key: bytes, run_id: str, token: str) -> bytes:
    """The digest kept in place of the token. The NUL separator keeps `("a", "bc")` and
    `("ab", "c")` apart; a run id is a printable id, never a NUL."""
    message = run_id.encode("utf-8") + b"\0" + token.encode("utf-8")
    return hmac.new(server_key, message, hashlib.sha256).digest()


def same_key(a: bytes | None, b: bytes | None) -> bool:
    """Constant-time equality; a missing key is never equal to anything."""
    return a is not None and b is not None and hmac.compare_digest(a, b)
