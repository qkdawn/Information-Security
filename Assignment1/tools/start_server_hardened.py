"""Hardened launcher used for local evaluation and black-box testing.

Not one of the four submission files. The teacher-supplied
start_server_subverted.py is byte-locked by SuppliedLauncherTests and keeps its
original behaviour; this launcher adds algorithm normalisation, credential-file
validation, an INFO-level failure audit trail and the restricted docroot.
"""

from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
ASSIGNMENT = TOOLS.parent
PROJECT = ASSIGNMENT / "py-http-server"
DOCROOT = ASSIGNMENT / "docroot"
# Single authoritative credential file. The copy under doc/ belongs to the
# supplied distribution and is not read here.
PASSWORDS = PROJECT / "passwords.txt"

sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(PROJECT))

from hardened_runtime import AlgorithmGuard, PasswordFileError, validate_password_file
from py_http_server import app_main
from py_http_server.middlewares import DefaultMiddleware
from py_http_server.middlewares.digest_auth_subverted import DigestAuthSubvertedMiddleware
from py_http_server.networking import TCPAddress
from py_http_server.routers import FileRouter


def main() -> int:
    try:
        validate_password_file(PASSWORDS)
    except PasswordFileError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    handler_chain = DefaultMiddleware(
        AlgorithmGuard(
            DigestAuthSubvertedMiddleware(
                next=FileRouter(str(DOCROOT)), pwdfile=str(PASSWORDS)
            )
        )
    )
    app_main(
        handler_chain=handler_chain,
        http_listeners=[TCPAddress("127.0.0.1", 8080), TCPAddress("::1", 8080)],
        log_level="INFO",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
