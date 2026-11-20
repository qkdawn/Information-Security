"""Launcher-side hardening for the coursework's simplified Digest server.

This module is intentionally outside the four submission files. It normalises
the client-selected algorithm token, validates the credential file before
startup, and audits authentication failures without changing the distributed
authentication source (and therefore without disturbing its line numbers,
MD5 or character budget).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from py_http_server import log
from py_http_server.common import HeaderContainer, NO_CACHE_HEADERS
from py_http_server.http.response import HTTPResponseFactory

__all__ = [
    "AlgorithmGuard",
    "PasswordFileError",
    "normalize_algorithm",
    "validate_password_file",
]

_TOKEN = re.compile(r"sha-?([0-9]+)", re.IGNORECASE)
# A single field extraction is enough for the launcher-side check. The full
# header parse (and its duplicate-key check) still happens downstream in the
# authentication middleware, so this guard never has to repeat that work.
_ALGORITHM_FIELD = re.compile(
    r'(?:^|[, \t])algorithm\s*=\s*"?([A-Za-z0-9-]+)"?', re.IGNORECASE
)
_DIGEST = re.compile(r"[0-9a-fA-F]{64}")
_MAX_TOKEN_LENGTH = 8
_CHALLENGE = 'Digest realm="auth", algorithm=SHA-256'

LOG = log.getLogger("launcher.hardening")


class PasswordFileError(ValueError):
    """Credential-file problem with an actionable file and line reference."""

    def __init__(self, path: Path, line: int, reason: str):
        self.path = path
        self.line = line
        self.reason = reason
        super().__init__(f"{path}:{line}: {reason}")


def validate_password_file(path: str | Path) -> dict[str, str]:
    """Validate the credential file and return its accounts.

    The distributed middleware loads this file with a one-line dict
    comprehension: a row without a colon raises an opaque ValueError during
    construction, a duplicate account is silently overwritten, and a short
    digest is accepted. Checking here keeps the submission source unchanged
    while making startup deterministic.
    """
    file = Path(path)
    try:
        raw = file.read_bytes()
    except OSError as exc:
        raise PasswordFileError(file, 0, f"cannot read credential file: {exc.strerror}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PasswordFileError(file, 0, "credential file is not valid UTF-8") from exc

    accounts: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if ":" not in line:
            raise PasswordFileError(file, number, "missing ':' separator")
        name, value = line.split(":", 1)
        if not name:
            raise PasswordFileError(file, number, "empty account name")
        if name in accounts:
            raise PasswordFileError(file, number, f"duplicate account {name!r}")
        if not _DIGEST.fullmatch(value):
            raise PasswordFileError(file, number, "digest must be exactly 64 hex characters")
        accounts[name] = value
    if not accounts:
        raise PasswordFileError(file, 0, "credential file contains no accounts")
    return accounts


def normalize_algorithm(header: str) -> str | None:
    """Return the algorithm token when it is a well-formed registered-style name.

    Rejects leading zeros, oversized tokens and malformed headers. These are
    ordinary input-validation rules for a protocol field; the guard has no
    knowledge of whether a token triggers the coursework flaw.
    """
    parts = header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "digest":
        return None
    # Ordinary requests take two C-level string scans instead of a regex. The
    # comma keeps SHA-2560 and similar longer tokens on the strict path.
    if header.count("algorithm=") == 1 and "algorithm=SHA-256," in header:
        return "SHA-256"
    tokens = _ALGORITHM_FIELD.findall(header)
    if len(tokens) != 1:
        return None
    token = tokens[0]
    if len(token) > _MAX_TOKEN_LENGTH:
        return None
    match = _TOKEN.fullmatch(token)
    if match is None:
        return None
    digits = match.group(1)
    if len(digits) > 1 and digits.startswith("0"):
        return None
    if not 1 <= int(digits) <= 256:
        return None
    return token


class AlgorithmGuard:
    """Reject malformed algorithm tokens and audit authentication failures."""

    def __init__(self, next: Callable):
        self.next = next
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

    def __call__(self, conn_info, request):
        header = request.headers.get("Authorization", "")
        if normalize_algorithm(header) is None:
            self._audit(request, "malformed_algorithm")
            return self._challenge()
        response = self.next(conn_info, request)
        if getattr(response, "status_code", None) == 401:
            self._audit(request, "credentials_rejected")
        return response

    def _challenge(self):
        return self.http.status(401, HeaderContainer({"WWW-Authenticate": _CHALLENGE}))

    @staticmethod
    def _audit(request, reason: str) -> None:
        # Never log the Authorization header, usernames or digests.
        target = getattr(request, "target", None) or getattr(request, "path", "/")
        LOG.info("auth failure reason=%s path=%s", reason, target)
