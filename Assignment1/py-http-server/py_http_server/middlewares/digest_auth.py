"""Coursework's simplified Digest authentication, not RFC 7616 challenge/response.

The response field contains SHA256(password). It is reusable if intercepted;
this implementation does not provide nonce-based replay protection.
"""

import hmac
from pathlib import Path
import re
from typing import Optional

from .. import log
from ..common import HeaderContainer, NO_CACHE_HEADERS, RequestHandler, RequestHandlerABC
from ..http.request import HTTPRequest
from ..http.response import HTTPResponse, HTTPResponseFactory
from ..networking import ConnectionInfo

__all__ = ["DigestAuthMiddleware"]

LOG = log.getLogger("middlewares.digest_auth")

_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_FIELD = re.compile(
    rf'[ \t]*({_TOKEN})[ \t]*=[ \t]*(?:"((?:[^"\\]|\\.)*)"|({_TOKEN}))[ \t]*'
)
_HASH = re.compile(r"[0-9a-fA-F]{64}")


def _parse_authorization(header: str) -> Optional[dict[str, str]]:
    """Parse the whole header, preserving quoted commas and rejecting ambiguity."""
    # The base server decodes HTTP headers as ASCII. Reject controls as well,
    # rather than allowing malformed input to reach downstream handlers.
    if re.search(r"[^\t\x20-\x7e]", header):
        return None
    parts = header.strip(" \t").split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "digest":
        return None

    data = parts[1]
    fields: dict[str, str] = {}
    position = 0
    while position < len(data):
        match = _FIELD.match(data, position)
        if match is None:
            return None
        name, quoted, token = match.groups()
        name = name.lower()
        # Duplicate names are ambiguous even when their values agree.
        if name in fields:
            return None
        fields[name] = re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else token
        position = match.end()
        if position == len(data):
            return fields
        if data[position] != ",":
            return None
        position += 1
    return None  # Includes an empty field list or a trailing comma.


class DigestAuthMiddleware(RequestHandlerABC):
    """Validate credentials before delegating to the existing request handler."""

    def __init__(self, next: RequestHandler, pwdfile: str):
        self.next = next
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
        self._credentials: dict[str, str] = {}
        try:
            # Read once at startup: requests only consult this read-only mapping.
            with Path(pwdfile).open(encoding="utf-8") as source:
                for number, line in enumerate(source, 1):
                    if not line.strip():
                        continue
                    username, separator, digest = line.rstrip("\r\n").partition(":")
                    digest = digest.strip()
                    if not separator or not username or not _HASH.fullmatch(digest):
                        raise ValueError(f"Invalid password-file entry on line {number}")
                    if username in self._credentials:
                        raise ValueError(f"Duplicate password-file username on line {number}")
                    self._credentials[username] = digest.lower()
        except OSError as exc:
            raise OSError(f"Cannot read password file {pwdfile!s}: {exc.strerror}") from exc
        except UnicodeError as exc:
            raise ValueError("Password file must be UTF-8 text") from exc

    def _authorized(self, header: str) -> bool:
        fields = _parse_authorization(header)
        if fields is None:
            return False
        if fields.get("algorithm", "").lower() not in ("sha-256", "sha256"):
            return False
        response = fields.get("response", "")
        if not _HASH.fullmatch(response):
            return False
        expected = self._credentials.get(fields.get("username", ""))
        return expected is not None and hmac.compare_digest(expected, response.lower())

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest) -> HTTPResponse:
        if self._authorized(request.headers.get("Authorization", "")):
            # The router owns resource status codes, such as 200 and 404.
            return self.next(conn_info, request)
        # INFO keeps the assertNoLogs(level="WARNING") contract and records
        # neither usernames, digests nor header values.
        LOG.info("Digest authentication rejected for %s %s", request.method, request.path)
        return self.http.status(
            401,
            HeaderContainer(
                {"WWW-Authenticate": 'Digest realm="auth", algorithm=SHA-256'}
            ),
        )
